require "test_helper"

module DomainGuard
  # Tested against the real network. These are opt-in because CI may not have
  # outbound DNS; run with `KITE_NETWORK_TESTS=1`.
  class DnsClientTest < Minitest::Test
    def setup
      skip "set KITE_NETWORK_TESTS=1 to run network tests" unless ENV["KITE_NETWORK_TESTS"]
      @dns = DnsClient.new(nameservers: %w[1.1.1.1 8.8.8.8], timeout: 3, attempts: 1)
    end

    def test_present_txt
      outcome = @dns.txt("github.com")
      assert outcome.records?, "github.com should have TXT records"
      assert outcome.records.any? { |r| r.value.include?("=") || r.value.length > 5 }
    end

    def test_present_cname
      outcome = @dns.cname("www.github.com")
      assert outcome.records?
      assert_equal ["github.com"], outcome.records.map { |r| r.value }
    end

    def test_absent_txt_vs_nxdomain_both_reported_absent
      assert_equal :absent, @dns.txt("_kite-verify-does-not-exist.github.com").status
      assert_equal :absent, @dns.txt("no-such-host.invalid").status
    end

    def test_caa_present
      outcome = @dns.caa("github.com")
      assert outcome.records?
      assert outcome.records.any? { |r| r.value[:tag] == "issue" }
    end

    def test_caa_absent
      # A name with no CAA returns absent, not an error.
      assert_equal :absent, @dns.caa("kite-nonexistent-domain.example").status
    end

    # The property that matters: a resolver that times out must not turn into a
    # false "absent". Point at an unroutable address and require inconclusive.
    def test_timeout_is_inconclusive_not_absent
      dead = DnsClient.new(nameservers: ["192.0.2.1"], timeout: 1, attempts: 1)
      outcome = dead.txt("github.com")
      assert_equal :inconclusive, outcome.status,
                   "an unreachable resolver must never look like a missing record"
    end
  end
end
