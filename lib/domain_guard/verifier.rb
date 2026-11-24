require "domain_guard/errors"
require "domain_guard/crypto"
require "domain_guard/dns_client"
require "domain_guard/models"
require "domain_guard/proof"

module DomainGuard
  # Observes DNS and turns it into a proof verdict.
  #
  # Outcomes, always one of:
  #
  #   :present       this claim's *own* fresh token is published
  #   :absent        an authoritative answer says the record is not there
  #   :inconclusive  we could not find out (timeout, SERVFAIL, lame delegation)
  #
  # Only a value equal to the token generated for *this* claim counts as
  # :present. A leftover record from a previous owner contains that owner's
  # token, which never equals the new claim's token — so it is :absent here and
  # cannot be used to bind the host. This is the property that closes the
  # reported hijack.
  class Verifier
    Observation = Struct.new(:state, :via, :detail, :ttl, keyword_init: true) do
      def present?; state == :present; end
      def absent?; state == :absent; end
      def inconclusive?; state == :inconclusive; end
    end

    def initialize(config:, dns: nil, limiter: nil, clock: nil)
      @config = config
      @dns = dns || DnsClient.new(nameservers: config.resolver_nameservers,
                                  timeout: config.resolver_timeout,
                                  attempts: config.resolver_attempts)
      @limiter = limiter
      @clock = clock || config.clock
    end

    def observe_claim(claim, token)
      if @limiter
        @limiter.check!("verify:#{claim.id}", limit: 30, window: 3600)
      end

      case claim.proof
      when "txt" then observe_txt(claim.host, token)
      when "cname" then observe_cname(claim.host, token)
      else raise Error, "unknown proof type #{claim.proof.inspect}"
      end
    end

    def observe_delegation(delegation, token)
      observe_txt(delegation.registrable_domain, token)
    end

    private

    def observe_txt(host, token)
      lookup = lookup_txt(host, token)
      case lookup[:state]
      when :present
        Observation.new(state: :present, via: "txt", ttl: lookup[:ttl])
      when :absent
        Observation.new(state: :absent, via: "txt",
                        detail: lookup[:detail] || "no matching TXT record")
      else
        Observation.new(state: :inconclusive, detail: lookup[:detail])
      end
    end

    def observe_cname(host, token)
      expected = CnameTarget.build(token: token, config: @config)
      outcome = @dns.cname(host)

      if outcome.records?
        values = outcome.records.map { |r| r.value.to_s.sub(/\.\z/, "").downcase }
        return Observation.new(state: :present, via: "cname", ttl: outcome.ttl) if values.include?(expected)
        return Observation.new(state: :absent, via: "cname", detail: "CNAME points elsewhere")
      end

      return Observation.new(state: :inconclusive, detail: outcome.detail) unless outcome.absent?

      # No CNAME on the host. The claim may also be satisfied by the TXT
      # record (users sometimes add that instead), so fall back to it.
      lookup = lookup_txt(host, token)
      case lookup[:state]
      when :present
        Observation.new(state: :present, via: "txt", ttl: lookup[:ttl])
      when :absent
        Observation.new(state: :absent, via: "cname", detail: "no CNAME or TXT record")
      else
        Observation.new(state: :inconclusive, detail: lookup[:detail])
      end
    end

    # Returns {state: :present|:absent|:inconclusive, detail:, ttl:}.
    #
    # Looks only at `_kite-verify.<host>`; a TXT record at the bare host is a
    # legitimate mail/SPF record owned by the zone and must never be treated as
    # a proof carrier.
    def lookup_txt(host, token)
      fqdn = @config.verification_fqdn(host)
      outcome = @dns.txt(fqdn)

      unless outcome.records?
        return { state: :inconclusive, detail: outcome.detail } unless outcome.absent?
        return { state: :absent, detail: "no TXT record at #{fqdn}" }
      end

      expected = ProofToken.digest(token)
      non_matching = 0
      outcome.records.each do |record|
        value = record.value.to_s
        next unless value.start_with?(ProofToken::PREFIX)

        if Crypto.secure_compare(ProofToken.digest(value), expected)
          return { state: :present, ttl: record.ttl, detail: nil }
        end
        non_matching += 1
      end

      if non_matching.positive?
        { state: :absent,
          detail: "#{non_matching} record(s) present at #{fqdn} but none match this claim" }
      else
        { state: :absent, detail: "no verification record at #{fqdn}" }
      end
    end
  end
end
