require "securerandom"
require "domain_guard/errors"
require "domain_guard/models"
require "domain_guard/lock"
require "domain_guard/claim_policy"
require "domain_guard/verifier"

module DomainGuard
  # Periodic work over the whole custom-domain population.
  #
  # Design constraints at ~300k domains:
  #
  #   * No full-table scans. Every sweep is driven by a narrow index
  #     (`next_check_at`, `renewal_due_at`) with keyset pagination, so each run
  #     touches only work that is actually due.
  #   * Work is spread in time. `next_check_at` is stored with jitter, so
  #     checks do not synchronise into a thundering herd.
  #   * Horizontal scale is safe. Each unit of work takes a short lease, so
  #     multiple workers can run sweeps concurrently without double-issuing.
  #   * Failures never lose work: a row is only rescheduled after the work
  #     completes, so a crash leaves it due for the next pass.
  class Scheduler
    attr_reader :config, :service, :issuer

    def initialize(config:, service:, issuer: nil, lease: nil, clock: nil,
                   batch_size: nil)
      @config = config
      @service = service
      @issuer = issuer
      @clock = clock || config.clock
      @batch_size = batch_size || config.scheduler_batch_size
      @lease = lease || Lease.new(owner: "scheduler-#{SecureRandom.hex(4)}",
                                  clock: -> { @clock.call.to_i })
    end

    def now
      @clock.call
    end

    # Expires stale pending claims and releases at_risk claims whose grace has
    # elapsed. Returns {expired:, released:}.
    def sweep_expirations
      expired = 0
      released = 0

      CustomDomain.pending.where("token_expires_at <= ?", now.utc.iso8601(6))
                   .limit(@batch_size).pluck(:id).each do |id|
        next unless @lease.acquire!("expire:#{id}", ttl: @config.lease_ttl)
        begin
          @service.release(CustomDomain.find(id), reason: "verification_expired")
          expired += 1
        ensure
          @lease.release!("expire:#{id}")
        end
      end

      deadline = now - @config.detach_grace
      CustomDomain.at_risk.where("at_risk_since <= ?", deadline.utc.iso8601(6))
                   .limit(@batch_size).pluck(:id).each do |id|
        next unless @lease.acquire!("release:#{id}", ttl: @config.lease_ttl)
        begin
          @service.release(CustomDomain.find(id), reason: "detached_grace_expired")
          released += 1
        ensure
          @lease.release!("release:#{id}")
        end
      end

      { expired: expired, released: released }
    end

    # Checks claims whose next_check_at is due. Uses keyset pagination on id so
    # a long run does not hold a growing OFFSET.
    def sweep_checks(limit: @batch_size)
      ids = CustomDomain.due_for_check(now).order(:next_check_at, :id).limit(limit).pluck(:id)
      checked = 0
      ids.each do |id|
        next unless @lease.acquire!("check:#{id}", ttl: @config.lease_ttl)
        begin
          claim = CustomDomain.find(id)
          token = @service.token_for(claim)
          observation = @service.verifier.observe_claim(claim, token)
          @service.apply_observation!(id, observation)
          checked += 1
        rescue => e
          # A failure here is a bug or a transient DB error. Leave the row due
          # and push its next attempt out slightly so one poisoned row cannot
          # spin the queue.
          SQL.exec("UPDATE custom_domains SET next_check_at = ?, updated_at = ? WHERE id = ?",
                   (now + 300).utc.iso8601(6), now.utc.iso8601(6), id)
          raise if ENV["DOMAIN_GUARD_RAISE"]
          e
        ensure
          @lease.release!("check:#{id}")
        end
      end
      checked
    end

    def sweep_delegations(limit: @batch_size)
      ids = DomainDelegation.live
                            .where("next_check_at IS NOT NULL AND next_check_at <= ?", now.utc.iso8601(6))
                            .limit(limit).pluck(:id)
      ids.each do |id|
        next unless @lease.acquire!("delegcheck:#{id}", ttl: @config.lease_ttl)
        begin
          @service.verify_delegation(DomainDelegation.find(id))
        rescue StandardError
          # Same rationale as above: reschedule, do not lose the row.
          SQL.exec("UPDATE domain_delegations SET next_check_at = ? WHERE id = ?",
                   (now + 3600).utc.iso8601(6), id)
        ensure
          @lease.release!("delegcheck:#{id}")
        end
      end
      ids.length
    end

    # Renews certificates that are inside their renewal window. Returns a
    # summary for ops dashboards.
    def sweep_renewals(limit: @batch_size)
      return { attempted: 0, renewed: 0, failed: 0 } unless @issuer

      attempted = 0
      renewed = 0
      failed = 0

      Certificate.due_for_renewal(now).order(:renewal_due_at).limit(limit).pluck(:id).each do |id|
        next unless @lease.acquire!("renew:#{id}", ttl: @config.lease_ttl)
        attempted += 1
        begin
          @issuer.renew(Certificate.find(id))
          renewed += 1
        rescue IssuanceDenied => e
          # Policy denial (CAA, detached domain, dispute hold): leave the row
          # due so a human sees it in the "expiring" report, and record why.
          failed += 1
          @service.audit.record!(action: "certificate.renewal_denied",
                                 subject_type: "certificate", subject_id: id,
                                 metadata: { reason: e.reason.to_s })
        rescue StandardError => e
          failed += 1
          SQL.exec("UPDATE certificates SET renewal_due_at = ?, updated_at = ? WHERE id = ?",
                   (now + 1800).utc.iso8601(6), now.utc.iso8601(6), id)
          @service.audit.record!(action: "certificate.renewal_error",
                                 subject_type: "certificate", subject_id: id,
                                 metadata: { error: "#{e.class}: #{e.message}" })
        ensure
          @lease.release!("renew:#{id}")
        end
      end

      { attempted: attempted, renewed: renewed, failed: failed }
    end

    def tick
      {
        expirations: sweep_expirations,
        checks: sweep_checks,
        delegations: sweep_delegations,
        renewals: sweep_renewals
      }
    end
  end
end
