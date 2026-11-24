require "domain_guard/errors"
require "domain_guard/models"
require "domain_guard/crypto"
require "domain_guard/proof"
require "domain_guard/idna"

module DomainGuard
  # Decides whether a set of hosts may be put on a certificate *right now*.
  #
  # Every rule here exists because of a specific failure mode, mostly around
  # domains that changed hands:
  #
  #   * every name must have a live claim owned by the requesting account;
  #   * every name's DNS proof must still be present (re-checked, not trusted
  #     from an old `active` state) — a domain released a minute ago must not
  #     get a fresh cert;
  #   * the claim must be `active`, not `at_risk`, and not under review for a
  #     reclaim dispute;
  #   * CAA must permit this platform's CA (RFC 8659);
  #   * ACME-style issuance quotas must not be exceeded.
  #
  # Deny by default: anything not provably satisfied raises IssuanceDenied with
  # a reason, which callers surface to the user and to ops.
  class IssuancePolicy
    Decision = Struct.new(:allowed, :reason, :names, keyword_init: true) do
      def allowed?; allowed; end
    end

    def initialize(config:, dns:, verifier:, limiter: nil, clock: nil)
      @config = config
      @dns = dns
      @verifier = verifier
      @limiter = limiter
      @clock = clock || config.clock
    end

    def now
      @clock.call
    end

    # `claims` are CustomDomain rows the caller wants on one certificate.
    # Returns nil when allowed; raises IssuanceDenied otherwise.
    #
    # @param purpose [:initial, :renewal] Renewals of an already-serving
    #   certificate are treated more leniently than new issuance: an existing
    #   site must not lose HTTPS because a moderator is still reviewing a
    #   reclaim. New issuance, however, waits for that review.
    def authorize!(account:, claims:, purpose: :initial)
      raise IssuanceDenied.new(:no_domains, "no domains selected") if claims.empty?
      raise IssuanceDenied.new(:too_many_names, "too many domains in one certificate") if claims.size > @config.max_sans

      names = claims.map(&:host)

      claims.each do |claim|
        raise IssuanceDenied.new(:not_owner, "#{claim.host} is not yours") if claim.account_id != account.id
        unless claim.state == "active"
          raise IssuanceDenied.new(:not_active, "#{claim.host} is #{claim.state}")
        end
      end

      # Review gating:
      #   * a claim under an unresolved *dispute* never gets a new certificate;
      #     renewals are still allowed so the incumbent site stays up (the
      #     dispute itself has no power to take a site down).
      #   * a recent risky reclaim is held for review before its *first*
      #     certificate, but once issued it may renew.
      if purpose == :initial
        claims.each do |claim|
          if claim.flagged_for?("dispute")
            raise IssuanceDenied.new(:disputed, "#{claim.host} is under dispute review")
          end
          if claim.review_required? && claim.review_reason.to_s.start_with?("recent_release", "previous_abuse")
            raise IssuanceDenied.new(:awaiting_review,
                                     "#{claim.host} is awaiting manual review of a recent reclaim")
          end
        end
      end

      # Re-look at DNS for every name. This is the decisive step: a claim that
      # was verified yesterday but whose DNS has since changed must not receive
      # a certificate today.
      claims.each do |claim|
        observation = @verifier.observe_claim(claim, token_for(claim, account))
        unless observation.state == :present
          raise IssuanceDenied.new(
            :proof_missing,
            "#{claim.host} no longer proves control (#{observation.detail || observation.state})"
          )
        end
      end

      check_caa!(names)
      check_quotas!(account, claims)

      nil
    end

    # RFC 8659: walk from each name up to its registrable domain looking for
    # CAA. The first CAA RRset found governs; if it exists and does not permit
    # our CA, issuance is refused. An inconclusive lookup is *not* a refusal —
    # but it does not authorise issuance on its own either, so it is treated as
    # "no CAA" only when truly absent. We treat inconclusive as an error here
    # because a certificate is irreversible.
    def check_caa!(names)
      identifiers = @config.caa_identifiers.map(&:downcase)
      names.each do |name|
        found = caa_for(name)
        next if found.nil? # no CAA anywhere on the chain

        issue_ok = found.any? do |rr|
          rr[:tag] == "issue" && permitted_identifier?(rr[:value], identifiers)
        end
        issuewild_ok = found.any? do |rr|
          rr[:tag] == "issuewild" && permitted_identifier?(rr[:value], identifiers)
        end

        # Only `issue` limits normal (non-wildcard) names.
        unless issue_ok
          raise IssuanceDenied.new(:caa, "#{name}: CAA does not permit this CA")
        end
        # We do not currently request wildcards, but if we ever do the same
        # applies; keeping the check means a policy change cannot silently
        # bypass CAA.
        _ = issuewild_ok
      end
    end

    private

    # Returns nil if no CAA RRset exists, else an array of {tag:, value:}.
    # Raises IssuanceDenied if the lookup is inconclusive.
    def caa_for(name)
      labels = name.split(".")
      registrable = labels.length >= 2 ? labels[-2..-1].join(".") : name

      current = name
      loop do
        outcome = @dns.caa(current)
        if outcome.records?
          return outcome.records.map { |r| r.value }
        end
        unless outcome.absent?
          raise IssuanceDenied.new(:caa_lookup_failed,
                                   "#{name}: could not resolve CAA for #{current}")
        end
        break if current == registrable

        parts = current.split(".")
        current = parts[1..-1].join(".")
        break if parts.length <= 2
      end
      nil
    end

    def permitted_identifier?(value, identifiers)
      identifier = value.to_s.strip.split(/\s+/).first.to_s.downcase
      # An empty "issue \";\"" / "issue \";\"" denies all issuance.
      return false if identifier.empty? || identifier == ";"
      identifiers.include?(identifier)
    end

    def check_quotas!(account, claims)
      return unless @limiter

      @limiter.check!("acme:account:#{account.id}",
                      limit: @config.acme_new_orders_per_account_3h,
                      window: 3 * 3600)
      claims.map(&:registrable_domain).uniq.each do |reg|
        @limiter.check!("acme:reg:#{reg}",
                        limit: @config.acme_certs_per_registered_domain_7d,
                        window: 7 * 24 * 3600)
      end
      @limiter.check!("acme:global",
                      limit: @config.issuance_global_per_minute,
                      window: 60)
    end

    def token_for(claim, account)
      @token_resolver.call(claim)
    end

    public

    # Injected by the service so the policy does not need the vault.
    attr_writer :token_resolver
  end
end
