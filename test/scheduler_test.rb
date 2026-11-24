require "test_helper"

module DomainGuard
  class SchedulerTest < TestCase
    def test_renewal_sweep_renews_only_due_certificates
      c1 = active_claim(@alice, "a.alice-store.com")
      c2 = active_claim(@alice, "b.alice-store.com")
      cert1 = @issuer.issue(account: @alice, claims: [c1])
      cert2 = @issuer.issue(account: @alice, claims: [c2])

      # Put only cert1 in its renewal window; cert2 stays far out.
      Certificate.where(id: cert1.id).update_all(renewal_due_at: (@now - 60).utc.iso8601(6))
      Certificate.where(id: cert2.id).update_all(renewal_due_at: (@now + 30 * 86_400).utc.iso8601(6))

      summary = @scheduler.sweep_renewals
      assert_equal 1, summary[:attempted]
      assert_equal 1, summary[:renewed]
      assert_equal "superseded", Certificate.find(cert1.id).state
      assert_equal "issued", Certificate.find(cert2.id).state
    end

    def test_checks_sweep_only_touches_due_rows
      a = active_claim(@alice, "a.alice-store.com")
      b = active_claim(@alice, "b.alice-store.com")
      # Push both far into the future.
      CustomDomain.where(id: [a.id, b.id]).update_all(next_check_at: (@now + 30 * 86_400).utc.iso8601(6))
      checked = @scheduler.sweep_checks
      assert_equal 0, checked
    end

    def test_checks_sweep_verifies_due_rows_and_detaches_when_gone
      claim = active_claim(@alice, "a.alice-store.com")
      @dns.remove_cname("a.alice-store.com")
      CustomDomain.where(id: claim.id).update_all(next_check_at: (@now - 60).utc.iso8601(6))

      @scheduler.sweep_checks
      row = CustomDomain.find(claim.id)
      assert_equal "at_risk", row.state
    end

    def test_sweep_does_not_release_on_inconclusive
      claim = active_claim(@alice, "a.alice-store.com")
      @dns.override("a.alice-store.com", :cname, :inconclusive, detail: "SERVFAIL")
      CustomDomain.where(id: claim.id).update_all(next_check_at: (@now - 60).utc.iso8601(6))
      @scheduler.sweep_checks
      assert_equal "active", CustomDomain.find(claim.id).state
    end

    # Simulates a large population and asserts the scheduler only issues work
    # for the due subset. This is the guard against an O(N) sweep at 300k.
    def test_sweep_is_bounded_by_due_rows
      account = @alice
      now = @now
      rows = []
      500.times do |i|
        host = "d#{i}.bulk-store.com"
        token = ProofToken.generate
        rows << {
          account_id: account.id, host: host,
          registrable_domain: "bulk-store.com", state: "active", proof: "cname",
          token_digest: ProofToken.digest(token),
          token_blob: @vault.encrypt(token, aad: "claim:#{host}:#{account.id}"),
          verified_at: now.utc.iso8601(6), last_checked_at: now.utc.iso8601(6),
          at_risk_since: nil, review_required: 0, review_reason: nil,
          risk_level: "normal", check_failures: 0,
          next_check_at: (now + 86_400).utc.iso8601(6),
          created_at: now.utc.iso8601(6), updated_at: now.utc.iso8601(6), lock_version: 0
        }
        # The 3 rows that will be due are given the proof they need.
        @dns.set_cname(host, CnameTarget.build(token: token, config: @config)) if i < 3
      end
      ActiveRecord::Base.connection.execute(
        ActiveRecord::Base.sanitize_sql_array(
          ["INSERT INTO custom_domains (#{rows.first.keys.join(',')}) VALUES " +
           Array.new(rows.size, "(#{Array.new(rows.first.size, '?').join(',')})").join(",")] +
          rows.flat_map(&:values)
        )
      )
      # Only 3 are due.
      due_hosts = rows.first(3).map { |r| r[:host] }
      CustomDomain.where(host: due_hosts).update_all(next_check_at: (now - 60).utc.iso8601(6))

      checked = @scheduler.sweep_checks(limit: 10)
      assert_equal 3, checked
    end

    def test_lease_prevents_double_processing
      claim = active_claim(@alice, "a.alice-store.com")
      CustomDomain.where(id: claim.id).update_all(next_check_at: (@now - 60).utc.iso8601(6))

      lease = Lease.new(owner: "worker-a", clock: -> { @now.to_i })
      assert lease.acquire!("check:#{claim.id}", ttl: 60)
      other = Lease.new(owner: "worker-b", clock: -> { @now.to_i })
      refute other.acquire!("check:#{claim.id}", ttl: 60),
             "a second worker must not take a live lease"
    end

    def test_lease_expires
      lease = Lease.new(owner: "worker-a", clock: -> { @now.to_i })
      assert lease.acquire!("x", ttl: 60)
      advance(61)
      other = Lease.new(owner: "worker-b", clock: -> { @now.to_i })
      assert other.acquire!("x", ttl: 60), "an expired lease must be reclaimable"
    end
  end
end
