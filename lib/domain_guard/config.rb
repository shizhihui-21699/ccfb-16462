module DomainGuard
  # All policy knobs live here so that the security posture of the platform is
  # a reviewable configuration rather than scattered constants.
  class Config
    DEFAULTS = {
      # Hostname the platform's edge answers on. Claims on this name (or
      # anything under it) are rejected.
      edge_domain: "edge.kite.example",

      # Where users publish the verification TXT record:
      #   _kite-verify.<host>  TXT  "kite-verify=<token>"
      verify_label: "_kite-verify",

      # Per-claim CNAME target suffix. The full target is
      # "<claim-label>.verify.kite.example" where <claim-label> is derived from
      # the claim's token, never from the hostname.
      cname_suffix: "verify.kite.example",

      # Default proof method for a first-time claim: "auto" prefers CNAME
      # (the record is required to serve anyway) and falls back to TXT for
      # apex names. "txt" or "cname" force one method.
      default_proof: "auto",

      # A pending claim expires after this long.
      pending_ttl: 7 * 24 * 3600,

      # A verified claim stays usable for issuance this long after its last
      # successful proof observation. Serving does not depend on this, so a
      # late check never takes a live site down.
      verification_freshness: 30 * 24 * 3600,

      # Re-check cadence for live claims, with +/- jitter so 300k checks do not
      # land in the same minute.
      health_check_interval: 24 * 3600,
      health_check_jitter: 6 * 3600,
      # After the first *definite* absence, keep retrying and alert before
      # releasing. Availability failures (SERVFAIL/timeout) never start this.
      detach_grace: 14 * 24 * 3600,

      # A different account re-claiming a recently released host must use the
      # strong TXT proof for this long, and the claim is queued for review and
      # the previous owner is notified. The previous owner is exempt.
      reclaim_cooldown: 7 * 24 * 3600,

      # How long a previous owner may contest a new claim on a host they lost.
      dispute_window: 14 * 24 * 3600,

      # Certificate lifetime requested from the CA and the renewal lead time.
      cert_lifetime: 90 * 24 * 3600,
      renew_lead: 30 * 24 * 3600,
      renew_jitter: 12 * 3600,

      # Maximum SANs packed into one certificate.
      max_sans: 100,

      # CAA identifiers under which this platform's CA is allowed to issue.
      # A domain whose CAA records exist but do not list any of these must not
      # be issued by us (RFC 8659).
      caa_identifiers: %w[kite-ca.example letsencrypt.org],

      # DNS resolver settings.
      resolver_nameservers: %w[1.1.1.1 8.8.8.8],
      resolver_timeout: 3,
      resolver_attempts: 2,

      # Certificate key algorithm.
      key_algorithm: "ec", # "ec" (P-256) or "rsa"
      rsa_bits: 2048,

      # Master key for envelope encryption of private keys. In production this
      # comes from KMS. A development fallback exists so nothing is ever stored
      # in the clear, but it is not production-safe.
      master_key: nil,

      # ACME-style quotas mirroring a public CA's published limits.
      acme_new_orders_per_account_3h: 300,
      acme_certs_per_registered_domain_7d: 50,
      issuance_global_per_minute: 600,
      verification_checks_per_minute: 12_000,

      # Scheduler batch sizes.
      scheduler_batch_size: 500,
      lease_ttl: 120
    }.freeze

    attr_accessor(*DEFAULTS.keys)
    attr_accessor :clock, :public_suffix_path

    def initialize(overrides = {})
      DEFAULTS.each { |key, value| public_send("#{key}=", value) }
      @clock = -> { Time.now.utc }
      @public_suffix_path = File.expand_path("../../data/public_suffix_list.dat", __dir__)
      overrides.each { |key, value| public_send("#{key}=", value) }
    end

    def now
      clock.call
    end

    def master_key_bytes
      raw = master_key
      if raw.nil? || raw.empty?
        OpenSSL::Digest::SHA256.digest("domain-guard-development-master-key")
      elsif raw =~ /\A[0-9a-fA-F]{64}\z/
        [raw].pack("H*")
      else
        OpenSSL::Digest::SHA256.digest(raw)
      end
    end

    def verification_fqdn(host)
      "#{verify_label}.#{host}"
    end
  end
end
