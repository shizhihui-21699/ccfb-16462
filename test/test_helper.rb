$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift __dir__

require "minitest/autorun"
require "fileutils"
require "domain_guard/db"
require "domain_guard/models"
require "domain_guard/config"
require "domain_guard/crypto"
require "domain_guard/audit"
require "domain_guard/lock"
require "domain_guard/public_suffix"
require "domain_guard/proof"
require "domain_guard/claim_policy"
require "domain_guard/verifier"
require "domain_guard/domain_service"
require "domain_guard/simulated_dns"
require "domain_guard/ca"
require "domain_guard/issuance_policy"
require "domain_guard/issuer"
require "domain_guard/scheduler"

Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |f| require f }

module DomainGuard
  # Shared harness. Each test gets its own in-memory database.
  #
  # Time is injectable so the 7-day reclaim cool-down, the 14-day detach grace
  # and 90-day certificate lifetimes can be exercised without sleeping.
  class TestCase < Minitest::Test
    def setup
      @now = Time.utc(2026, 11, 25, 12, 0, 0)
      @clock = -> { @now }
      DB.connect!
      DomainGuard::Base.descendants.each(&:reset_column_information)

      @config = Config.new(clock: @clock)
      @config.public_suffix_path = File.expand_path("../data/public_suffix_list.dat", __dir__)
      @psl = PublicSuffix.new(@config.public_suffix_path)
      @dns = TestSupport::FakeDns.new
      @limiter = RateLimiter.new(clock: -> { @now.to_i })
      @vault = KeyVault.new(master_key: @config.master_key_bytes)
      @verifier = Verifier.new(config: @config, dns: @dns, limiter: @limiter, clock: @clock)
      @audit = Audit.new(clock: @clock)
      @notifier = Notifier.new(clock: @clock)
      @service = DomainService.new(
        config: @config, public_suffix: @psl, verifier: @verifier,
        audit: @audit, notifier: @notifier, vault: @vault, limiter: @limiter,
        lease: Lease.new(owner: "test", clock: -> { @now.to_i })
      )

      @ca = LocalCA.generate(clock: @clock)
      @issuance_policy = IssuancePolicy.new(
        config: @config, dns: @dns, verifier: @verifier,
        limiter: @limiter, clock: @clock
      )
      @issuer = Issuer.new(
        config: @config, ca: @ca, policy: @issuance_policy, vault: @vault,
        audit: @audit, dns: @dns, clock: @clock, limiter: @limiter,
        token_resolver: ->(claim) { @service.token_for(claim) }
      )
      @scheduler = Scheduler.new(
        config: @config, service: @service, issuer: @issuer,
        lease: Lease.new(owner: "test-sched", clock: -> { @now.to_i }),
        clock: @clock
      )
      @alice = Account.create!(name: "Alice", now: @now)
      @bob = Account.create!(name: "Bob", now: @now)
    end

    def teardown
      ActiveRecord::Base.connection_handler.clear_all_connections!
    end

    def advance(seconds)
      @now += seconds
    end

    def publish_txt(host, token)
      @dns.add_txt(@config.verification_fqdn(host), token)
    end

    def publish_cname(host, token)
      @dns.set_cname(host, CnameTarget.build(token: token, config: @config))
    end

    def active_claim(account, host)
      result = @service.claim(account: account, host: host)
      if result.instructions[:proof] == "cname"
        publish_cname(host, result.token)
      else
        publish_txt(host, result.token)
      end
      obs = @service.verify!(result.claim)
      assert_equal :present, obs.state, "expected claim to verify: #{obs.detail}"
      CustomDomain.find(result.claim.id)
    end
  end
end
