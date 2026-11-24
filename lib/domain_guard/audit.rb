require "json"
require "domain_guard/crypto"
require "domain_guard/models"

module DomainGuard
  # Append-only, tamper-evident audit log.
  #
  # entry_hash = SHA256(prev_hash || canonical_json(entry))
  #
  # This is the record an abuse investigator reads after an incident: who
  # claimed what, which proof was observed, when it was released, which
  # certificate was issued or revoked. Because each row commits to its
  # predecessor, deleting or editing history breaks the chain and is detectable
  # with `Audit.verify_chain!`.
  class Audit
    GENESIS = "0" * 64

    def initialize(clock: nil)
      @clock = clock || -> { Time.now.utc }
    end

    def record!(action:, actor_type: nil, actor_id: nil, subject_type: nil,
                subject_id: nil, host: nil, metadata: {})
      now = @clock.call
      DB.transaction do
        prev = AuditEvent.order(:id).last
        prev_hash = prev ? prev.entry_hash : GENESIS
        canonical = JSON.generate(
          "action" => action.to_s,
          "actor_type" => actor_type,
          "actor_id" => actor_id,
          "subject_type" => subject_type,
          "subject_id" => subject_id,
          "host" => host,
          "metadata" => stringify(metadata),
          "created_at" => now.utc.iso8601(6)
        )
        entry_hash = Crypto.hex(Crypto.digest(prev_hash + canonical))

        AuditEvent.create!(
          actor_type: actor_type,
          actor_id: actor_id,
          action: action.to_s,
          subject_type: subject_type,
          subject_id: subject_id,
          host: host,
          metadata: stringify(metadata),
          prev_hash: prev_hash,
          entry_hash: entry_hash,
          created_at: now
        )
      end
    end

    # Returns [ok, first_bad_id]. Recomputes the whole chain; intended for a
    # periodic integrity job, not the hot path.
    def verify_chain!
      prev_hash = GENESIS
      AuditEvent.order(:id).each do |event|
        canonical = JSON.generate(
          "action" => event.action,
          "actor_type" => event.actor_type,
          "actor_id" => event.actor_id,
          "subject_type" => event.subject_type,
          "subject_id" => event.subject_id,
          "host" => event.host,
          "metadata" => event.metadata,
          "created_at" => event.created_at.utc.iso8601(6)
        )
        expected = Crypto.hex(Crypto.digest(prev_hash + canonical))
        return [false, event.id] unless Crypto.secure_compare(expected, event.entry_hash)
        return [false, event.id] unless Crypto.secure_compare(prev_hash, event.prev_hash)

        prev_hash = event.entry_hash
      end
      [true, nil]
    end

    private

    def stringify(hash)
      hash.each_with_object({}) { |(k, v), h| h[k.to_s] = v }
    end
  end

  class Notifier
    def initialize(clock: nil)
      @clock = clock || -> { Time.now.utc }
    end

    def notify!(account_id:, kind:, host: nil, payload: {})
      Notification.create!(
        account_id: account_id,
        kind: kind,
        host: host,
        payload: payload,
        created_at: @clock.call
      )
    end
  end
end
