require "securerandom"
require "openssl"
require "domain_guard/errors"
require "domain_guard/crypto"
require "domain_guard/models"
require "domain_guard/ca"
require "domain_guard/issuance_policy"
require "domain_guard/lock"

module DomainGuard
  # Issues, renews and revokes certificates, enforcing IssuancePolicy.
  #
  # The invariant that matters for this feature:
  #
  #   A certificate is never issued from stored state alone. Every issuance
  #   re-runs the full policy (ownership, liveness, fresh DNS proof, CAA,
  #   quotas). A domain that was released, detached, disputed or moved after
  #   its last check cannot obtain a new or renewed certificate.
  class Issuer
    def initialize(config:, ca:, policy:, vault:, audit:, token_resolver:, dns: nil,
                   clock: nil, limiter: nil)
      @config = config
      @ca = ca
      @policy = policy
      @vault = vault
      @audit = audit
      @dns = dns
      @clock = clock || config.clock
      @limiter = limiter
      # Resolves a claim to its plaintext proof token. Supplied by the service
      # so the token's AAD scheme lives in exactly one place.
      @token_resolver = token_resolver
      @policy.token_resolver = token_resolver
    end

    def now
      @clock.call
    end

    # Issues a certificate covering `claims` for `account`.
    #
    # Returns the Certificate row. Idempotency: if an identical live
    # certificate (>30 days valid) already covers exactly these names, it is
    # returned instead of hitting the CA again — important at 300k scale where
    # retries are common.
    def issue(account:, claims:, actor: nil)
      claims = claims.map { |c| CustomDomain.find(c.id) }
      @policy.authorize!(account: account, claims: claims)

      names = normalized_names(claims)

      existing = find_reusable_certificate(account, names)
      return existing if existing

      key = Keys.generate(@config)
      issued = @ca.issue(names: names, key: key, lifetime: @config.cert_lifetime,
                         clock: @clock)

      DB.transaction do
        cert = Certificate.new(
          account_id: account.id,
          names: names,
          serial: issued.serial,
          not_before: issued.not_before,
          not_after: issued.not_after,
          state: "issued",
          key_blob: @vault.encrypt(issued.private_key_pem, aad: "cert:#{issued.serial}"),
          cert_pem: issued.cert_pem,
          chain_pem: issued.chain_pem,
          issued_at: now,
          renewal_due_at: renewal_due_at(issued.not_after),
          created_at: now,
          updated_at: now
        )
        cert.save!

        claims.each do |claim|
          CertificateDomain.create!(certificate_id: cert.id, custom_domain_id: claim.id,
                                    name: claim.host)
        end

        @audit.record!(action: "certificate.issued", actor_type: actor_type(actor),
                       actor_id: actor_id(actor), subject_type: "certificate",
                       subject_id: cert.id, host: names.first,
                       metadata: { names: names, serial: issued.serial })
        cert
      end
    end

    # Renews a certificate. Re-runs the whole policy against the *current*
    # claims, so a domain that lost its proof cannot be renewed.
    def renew(certificate)
      cert = Certificate.find(certificate.id)
      claims = cert.custom_domains.to_a
      if claims.empty?
        raise IssuanceDenied.new(:no_claims, "certificate has no associated domains")
      end

      account = Account.find(cert.account_id)
      begin
        @policy.authorize!(account: account, claims: claims, purpose: :renewal)
      rescue IssuanceDenied => e
        # A dead certificate must not linger forever. If any name can no longer
        # be proven, mark the certificate superseded so it stops being renewed
        # and stop routing it, but never extend it.
        if e.reason == :proof_missing || e.reason == :not_active || e.reason == :not_owner
          mark_unrenewable!(cert, e.reason)
        end
        raise
      end

      names = normalized_names(claims)
      key = Keys.generate(@config)
      issued = @ca.issue(names: names, key: key, lifetime: @config.cert_lifetime, clock: @clock)

      DB.transaction do
        old = Certificate.lock.find(cert.id)
        new_cert = Certificate.new(
          account_id: old.account_id,
          names: names,
          serial: issued.serial,
          not_before: issued.not_before,
          not_after: issued.not_after,
          state: "issued",
          key_blob: @vault.encrypt(issued.private_key_pem, aad: "cert:#{issued.serial}"),
          cert_pem: issued.cert_pem,
          chain_pem: issued.chain_pem,
          issued_at: now,
          renewal_due_at: renewal_due_at(issued.not_after),
          created_at: now,
          updated_at: now
        )
        new_cert.save!

        claims.each do |claim|
          CertificateDomain.create!(certificate_id: new_cert.id,
                                    custom_domain_id: claim.id, name: claim.host)
        end

        old.state = "superseded"
        old.updated_at = now
        old.save!

        @audit.record!(action: "certificate.renewed", subject_type: "certificate",
                       subject_id: new_cert.id, host: names.first,
                       metadata: { previous_certificate_id: old.id, serial: issued.serial })
        new_cert
      end
    end

    def revoke(certificate, reason:, actor: nil)
      DB.transaction do
        cert = Certificate.lock.find(certificate.id)
        return cert unless cert.state == "issued"

        cert.state = "revoked"
        cert.revoked_at = now
        cert.revoke_reason = reason.to_s
        cert.updated_at = now
        cert.save!
        @ca.revoke(cert.serial, reason)

        @audit.record!(action: "certificate.revoked", actor_type: actor_type(actor),
                       actor_id: actor_id(actor), subject_type: "certificate",
                       subject_id: cert.id, host: cert.names.first,
                       metadata: { reason: reason.to_s, serial: cert.serial })
        cert
      end
    end

    # The certificate to serve for a host, if any. Returns nil when the host is
    # not live or its only certificate is expired/revoked.
    def serving_certificate(host)
      cert = Certificate.live
                       .joins(:certificate_domains)
                       .where(certificate_domains: { name: host })
                       .where("not_after > ?", now.utc.iso8601(6))
                       .order(not_after: :desc)
                       .first
      return nil unless cert

      claim = CustomDomain.live.find_by(host: host)
      return nil unless claim && claim.account_id == cert.account_id

      cert
    end

    def private_key(certificate)
      cert = certificate.is_a?(Certificate) ? certificate : Certificate.find(certificate.id)
      @vault.decrypt(cert.key_blob, aad: "cert:#{cert.serial}")
    end

    private

    def find_reusable_certificate(account, names)
      min_valid = now + (30 * 86_400)
      Certificate.live
                 .where(account_id: account.id)
                 .where("not_after > ?", min_valid.utc.iso8601(6))
                 .order(not_after: :desc)
                 .detect { |c| c.names.sort == names.sort }
    end

    def normalized_names(claims)
      claims.map(&:host).uniq.sort
    end

    def renewal_due_at(not_after)
      jitter = (@config.renew_jitter * (rand - 0.5)).to_i
      not_after - @config.renew_lead + jitter
    end

    def mark_unrenewable!(cert, reason)
      DB.transaction do
        row = Certificate.lock.find(cert.id)
        return unless row.state == "issued"

        row.state = "superseded"
        row.updated_at = now
        row.save!
        @audit.record!(action: "certificate.unrenewable", subject_type: "certificate",
                       subject_id: row.id, host: row.names.first,
                       metadata: { reason: reason.to_s })
      end
    end

    def token_for(claim)
      @token_resolver.call(claim)
    end

    def actor_type(actor)
      actor.is_a?(Hash) ? actor[:type] : nil
    end

    def actor_id(actor)
      actor.is_a?(Hash) ? actor[:id] : nil
    end
  end
end
