require "domain_guard/errors"
require "domain_guard/config"
require "domain_guard/crypto"
require "domain_guard/db"
require "domain_guard/models"
require "domain_guard/idna"
require "domain_guard/public_suffix"
require "domain_guard/proof"
require "domain_guard/claim_policy"
require "domain_guard/verifier"
require "domain_guard/audit"
require "domain_guard/lock"
require "domain_guard/domain_service"
require "domain_guard/ca"
require "domain_guard/issuance_policy"
require "domain_guard/issuer"
require "domain_guard/scheduler"
require "domain_guard/dns_client"

module DomainGuard
  # Composition root. Wires the pieces the way a Rails initializer would, so
  # callers deal with one object.
  #
  #   guard = DomainGuard.boot!(config)
  #   result = guard.domains.claim(account: account, host: "www.example.com")
  #   guard.domains.verify!(result.claim)
  #   guard.issuer.issue(account: account, claims: [claim])
  #   guard.scheduler.tick
  class Platform
    attr_reader :config, :public_suffix, :dns, :vault, :audit, :limiter,
                :verifier, :domains, :issuer, :scheduler, :ca

    def initialize(config:, ca: nil, dns: nil, clock: nil)
      @config = config
      @clock = clock || config.clock
      @public_suffix = PublicSuffix.new(config.public_suffix_path)
      @dns = dns || DnsClient.new(nameservers: config.resolver_nameservers,
                                  timeout: config.resolver_timeout,
                                  attempts: config.resolver_attempts,
                                  clock: @clock)
      @vault = KeyVault.new(master_key: config.master_key_bytes)
      @audit = Audit.new(clock: @clock)
      @notifier = Notifier.new(clock: @clock)
      @limiter = RateLimiter.new(clock: @clock)
      @verifier = Verifier.new(config: config, dns: @dns, limiter: @limiter, clock: @clock)
      @ca = ca || LocalCA.generate(clock: @clock)

      @domains = DomainService.new(
        config: config, public_suffix: @public_suffix, verifier: @verifier,
        audit: @audit, notifier: @notifier, vault: @vault, limiter: @limiter,
        lease: Lease.new(owner: "platform-#{SecureRandom.hex(4)}", clock: -> { @clock.call.to_i })
      )

      policy = IssuancePolicy.new(config: config, dns: @dns, verifier: @verifier,
                                  limiter: @limiter, clock: @clock)
      @issuer = Issuer.new(
        config: config, ca: @ca, policy: policy, vault: @vault, audit: @audit,
        dns: @dns, clock: @clock, limiter: @limiter,
        token_resolver: ->(claim) { @domains.token_for(claim) }
      )

      @scheduler = Scheduler.new(
        config: config, service: @domains, issuer: @issuer,
        lease: Lease.new(owner: "sched-#{SecureRandom.hex(4)}", clock: -> { @clock.call.to_i }),
        clock: @clock
      )
    end
  end

  def self.boot!(config = Config.new, database: ":memory:", ca: nil, dns: nil, logger: nil)
    DB.connect!(database: database, logger: logger)
    Platform.new(config: config, ca: ca, dns: dns)
  end
end
