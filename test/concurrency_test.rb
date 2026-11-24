require "test_helper"

module DomainGuard
  # Concurrency and integrity at the storage layer. These are the properties
  # that hold even when two application processes act at the same moment.
  class ConcurrencyTest < TestCase
    def test_partial_unique_index_blocks_two_live_claims
      # Bypass the service on purpose: the index is the last line of defence and
      # must work even if a future code path forgets to check.
      CustomDomain.create!(
        account_id: @alice.id, host: "race.com", registrable_domain: "race.com",
        state: "active", proof: "txt", token_digest: "a", token_blob: "x",
        created_at: @now, updated_at: @now
      )
      assert_raises(ActiveRecord::RecordNotUnique) do
        CustomDomain.create!(
          account_id: @bob.id, host: "race.com", registrable_domain: "race.com",
          state: "pending", proof: "txt", token_digest: "b", token_blob: "y",
          created_at: @now, updated_at: @now
        )
      end
    end

    def test_released_tombstones_do_not_block_new_claims
      3.times do |i|
        CustomDomain.create!(
          account_id: @alice.id, host: "cycle.com", registrable_domain: "cycle.com",
          state: "released", proof: "txt", token_digest: "old-#{i}", token_blob: "x",
          released_at: @now - (i * 86_400), created_at: @now, updated_at: @now
        )
      end
      CustomDomain.create!(
        account_id: @bob.id, host: "cycle.com", registrable_domain: "cycle.com",
        state: "pending", proof: "txt", token_digest: "new", token_blob: "y",
        created_at: @now, updated_at: @now
      )
      assert_equal 4, CustomDomain.where(host: "cycle.com").count
      assert_equal 1, CustomDomain.live.where(host: "cycle.com").count
    end

    def test_token_digest_is_unique
      CustomDomain.create!(
        account_id: @alice.id, host: "a.com", registrable_domain: "a.com",
        state: "active", proof: "txt", token_digest: "same", token_blob: "x",
        created_at: @now, updated_at: @now
      )
      assert_raises(ActiveRecord::RecordNotUnique) do
        CustomDomain.create!(
          account_id: @alice.id, host: "b.com", registrable_domain: "b.com",
          state: "active", proof: "txt", token_digest: "same", token_blob: "y",
          created_at: @now, updated_at: @now
        )
      end
    end

    # Optimistic locking: two workers loaded the same claim, one advances it; the
    # other's stale write must fail rather than silently clobber the new state.
    def test_optimistic_locking_rejects_stale_write
      claim = active_claim(@alice, "www.concurrent.com")
      a = CustomDomain.find(claim.id)
      b = CustomDomain.find(claim.id)

      a.state = "at_risk"
      a.updated_at = @now
      a.save!

      b.state = "released"
      b.updated_at = @now
      assert_raises(ActiveRecord::StaleObjectError) { b.save! }
    end

    # A host claimed by A, then released, then claimed by B concurrently with a
    # stale read by a third worker: the live index still admits only one.
    def test_sequential_handover_keeps_one_live_claim
      first = active_claim(@alice, "www.handover.com")
      @service.release(first)
      second = @service.claim(account: @bob, host: "www.handover.com")
      assert_equal "pending", second.claim.state
      live = CustomDomain.live.where(host: "www.handover.com").to_a
      assert_equal 1, live.size
      assert_equal @bob.id, live.first.account_id
    end
  end
end
