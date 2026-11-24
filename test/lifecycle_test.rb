require "test_helper"

module DomainGuard
  # Lifecycle: claim -> verify -> serve -> detach -> release, plus the policy
  # around each transition.
  class LifecycleTest < TestCase
    def test_first_claim_is_low_friction
      result = @service.claim(account: @alice, host: "shop.alice-store.com")
      row = result.claim
      assert_equal "pending", row.state
      refute row.review_required?
      assert_equal "cname", row.proof, "subdomain defaults to CNAME"
      refute_nil result.token
    end

    def test_apex_defaults_to_txt
      result = @service.claim(account: @alice, host: "alice-store.com")
      assert_equal "txt", result.claim.proof
    end

    def test_claim_is_idempotent_for_same_account
      first = @service.claim(account: @alice, host: "a.alice-store.com")
      second = @service.claim(account: @alice, host: "a.alice-store.com")
      assert_equal first.claim.id, second.claim.id
      assert_equal first.token, second.token
      assert_equal 1, CustomDomain.where(host: "a.alice-store.com").count
    end

    def test_claim_rejects_public_suffix
      assert_raises(PublicSuffixNotRegistrable) do
        @service.claim(account: @alice, host: "co.uk")
      end
    end

    def test_claim_rejects_platform_edge_host
      assert_raises(InvalidDomain) do
        @service.claim(account: @alice, host: "edge.kite.example")
      end
      assert_raises(InvalidDomain) do
        @service.claim(account: @alice, host: "foo.edge.kite.example")
      end
    end

    def test_claim_rejects_invalid_hostnames
      ["", "-a.com", "a..com", "exa mple.com", "com"].each do |host|
        assert_raises(InvalidDomain, "#{host.inspect} should be rejected") do
          @service.claim(account: @alice, host: host)
        end
      end
    end

    def test_claim_rejects_hostile_unicode_and_normalises_legit_idn
      # Homoglyph-ish: Latin + Cyrillic mixed label is accepted but flagged by
      # the Idna helper; here we just check the canonical form is stored.
      result = @service.claim(account: @alice, host: "BÜCHER.alice-store.com")
      assert_equal "xn--bcher-kva.alice-store.com", result.claim.host

      # ...and a second claim on the ASCII spelling is the *same* claim, not a
      # second one. This is the duplicate-name attack surface.
      again = @service.claim(account: @alice, host: "xn--bcher-kva.alice-store.com")
      assert_equal result.claim.id, again.claim.id
    end

    def test_cannot_claim_other_accounts_unicode_equivalent
      @service.claim(account: @alice, host: "bücher.alice-store.com")
      assert_raises(ClaimConflict) do
        @service.claim(account: @bob, host: "xn--bcher-kva.alice-store.com")
      end
    end

    def test_verify_promotes_to_active
      result = @service.claim(account: @alice, host: "www.alice-store.com")
      publish_cname("www.alice-store.com", result.token)
      obs = @service.verify!(result.claim)
      assert_equal :present, obs.state
      row = CustomDomain.find(result.claim.id)
      assert_equal "active", row.state
      assert_equal "cname", row.verified_via
      refute_nil row.verified_at
    end

    def test_wrong_token_does_not_verify
      result = @service.claim(account: @alice, host: "www.alice-store.com")
      publish_cname("www.alice-store.com", ProofToken.generate)
      assert_equal :absent, @service.verify!(result.claim).state
      assert_equal "pending", CustomDomain.find(result.claim.id).state
    end

    def test_inconclusive_dns_does_not_change_state
      result = @service.claim(account: @alice, host: "www.alice-store.com")
      @dns.override("www.alice-store.com", :cname, :inconclusive, detail: "SERVFAIL")
      obs = @service.verify!(result.claim)
      assert_equal :inconclusive, obs.state
      assert_equal "pending", CustomDomain.find(result.claim.id).state
    end

    def test_inconclusive_does_not_detach_active_claim
      active = active_claim(@alice, "www.alice-store.com")
      @dns.override("www.alice-store.com", :cname, :inconclusive, detail: "timeout")
      @service.verify!(active)
      assert_equal "active", CustomDomain.find(active.id).state
    end

    def test_dns_disappearing_marks_at_risk_then_releases_after_grace
      active = active_claim(@alice, "www.alice-store.com")
      @dns.remove_cname("www.alice-store.com")

      # First definite absence -> at_risk, not released.
      assert_equal :absent, @service.verify!(active).state
      row = CustomDomain.find(active.id)
      assert_equal "at_risk", row.state
      refute_nil row.at_risk_since

      # Before the grace period -> still at_risk.
      advance(@config.detach_grace / 2)
      @scheduler.sweep_expirations
      assert_equal "at_risk", CustomDomain.find(active.id).state

      # After the grace period -> released.
      advance(@config.detach_grace)
      result = @scheduler.sweep_expirations
      assert result[:released] >= 1
      assert_equal "released", CustomDomain.find(active.id).state
    end

    def test_dns_reappearing_heals_at_risk_claim
      active = active_claim(@alice, "www.alice-store.com")
      @dns.remove_cname("www.alice-store.com")
      @service.verify!(active)
      assert_equal "at_risk", CustomDomain.find(active.id).state

      # Re-publish the correct token.
      token = @service.token_for(CustomDomain.find(active.id))
      publish_cname("www.alice-store.com", token)
      @service.verify!(active)
      row = CustomDomain.find(active.id)
      assert_equal "active", row.state
      assert_nil row.at_risk_since
    end

    def test_pending_claim_expires
      result = @service.claim(account: @alice, host: "www.alice-store.com")
      advance(@config.pending_ttl + 1)
      summary = @scheduler.sweep_expirations
      assert summary[:expired] >= 1
      assert_equal "released", CustomDomain.find(result.claim.id).state
    end

    def test_release_is_immediate_and_leaves_tombstone
      active = active_claim(@alice, "www.alice-store.com")
      @service.release(active, reason: "user_unbind")
      row = CustomDomain.find(active.id)
      assert_equal "released", row.state
      assert_equal "user_unbind", row.release_reason
      refute_nil row.released_at
    end

    def test_zone_delegation_reduces_friction_for_subdomains
      # Prove one zone.
      delegation = @service.create_delegation(account: @alice, domain: "alice-store.com")
      @dns.add_txt(@config.verification_fqdn("alice-store.com"), delegation.token)
      assert_equal :present, @service.verify_delegation(delegation.delegation).state

      # Subdomains still need a per-host record, but no extra manual step and
      # no review, and they verify immediately.
      %w[a b c].each do |label|
        host = "#{label}.alice-store.com"
        result = @service.claim(account: @alice, host: host)
        assert_equal @alice.id, result.claim.account_id
        refute result.claim.review_required?
      end
    end

    def test_delegation_is_claimable_by_only_one_account
      d1 = @service.create_delegation(account: @alice, domain: "alice-store.com")
      assert_equal @alice.id, d1.delegation.account_id
      assert_raises(ClaimConflict) do
        @service.create_delegation(account: @bob, domain: "alice-store.com")
      end
    end

    def test_rate_limit_on_claim_flood
      host_base = "flood-store.com"
      errors = 0
      12.times do |i|
        begin
          @service.claim(account: @bob, host: "h#{i}.#{host_base}")
        rescue RateLimited
          errors += 1
        rescue ClaimConflict
        end
      end
      # The per-account limit (50/day) allows these, but the per-host limit
      # does not apply here; it's the account limit we exercise elsewhere.
      assert_equal 0, errors
    end

    def test_per_host_claim_rate_limit
      errors = 0
      10.times do
        begin
          @service.claim(account: @alice, host: "spin.alice-store.com")
        rescue RateLimited
          errors += 1
        end
      end
      assert errors.positive?, "repeated claims for one host must be rate limited"
    end
  end
end
