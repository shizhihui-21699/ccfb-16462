require "securerandom"
require "domain_guard/errors"
require "domain_guard/crypto"
require "domain_guard/models"
require "domain_guard/idna"
require "domain_guard/public_suffix"
require "domain_guard/claim_policy"
require "domain_guard/proof"
require "domain_guard/verifier"
require "domain_guard/audit"
require "domain_guard/proof"
require "domain_guard/lock"

module DomainGuard
  # The binding lifecycle. This is the part that must make the reported attack
  # impossible.
  #
  # State machine (per host claim):
  #
  #   pending ──verify ok──▶ active ──DNS gone──▶ at_risk ──grace──▶ released
  #      │                     │                    │
  #      └──expire/unbind──────┴────unbind──────────┴──▶ released
  #
  #   revoked  (moderator/abuse action; tombstone, never reused silently)
  #
  # Invariants:
  #
  #   I1. At most one live claim per host (partial unique index).
  #   I2. A live claim owned by another account cannot be taken over. There is
  #       no "prove and steal": the incumbent must release or be revoked.
  #   I3. A claim's token is fresh, random and claim-scoped. A record left by a
  #       previous owner never matches a new claim's token.
  #   I4. Release always leaves a tombstone with `released_at` and a reason.
  #   I5. Every transition is audited.
  class DomainService
    ClaimResult = Struct.new(:claim, :token, :instructions, keyword_init: true)
    DelegationResult = Struct.new(:delegation, :token, :fqdn, keyword_init: true)

    attr_reader :config, :policy, :verifier, :audit, :notifier

    def initialize(config:, public_suffix:, verifier:, audit: nil, notifier: nil,
                   vault: nil, limiter: nil, lease: nil)
      @config = config
      @public_suffix = public_suffix
      @policy = ClaimPolicy.new(config: config)
      @verifier = verifier
      @audit = audit || Audit.new(clock: config.clock)
      @notifier = notifier || Notifier.new(clock: config.clock)
      @vault = vault || KeyVault.new(master_key: config.master_key_bytes)
      @limiter = limiter || RateLimiter.new(clock: config.clock)
      @lease = lease || Lease.new(owner: "domain-service-#{SecureRandom.hex(4)}", clock: config.clock)
    end

    def now
      @config.now
    end

    # ---------------------------------------------------------------- claim --

    # Starts a claim on `host` for `account`. Idempotent when the same account
    # already holds a live claim.
    #
    # Returns ClaimResult: the claim, the plaintext token and ready-to-paste
    # DNS instructions.
    def claim(account:, host:, proof: nil)
      canonical = canonical_host(host)
      registrable = registrable_domain(canonical)

      @limiter.check!("claim:acct:#{account.id}", limit: 50, window: 24 * 3600)
      @limiter.check!("claim:host:#{canonical}", limit: 5, window: 3600)

      @lease.acquire!("claim:#{canonical}", ttl: @config.lease_ttl)

      outcome = nil
      DB.transaction do
        live = CustomDomain.live.where(host: canonical).first
        previous = CustomDomain.where(host: canonical)
                               .where.not(state: CustomDomain::LIVE_STATES)
                               .order(Arel.sql("released_at IS NULL, released_at DESC, id DESC"))
                               .first

        zone = DomainDelegation.active.find_by(registrable_domain: registrable,
                                               account_id: account.id)

        decision = @policy.decide_new_claim(
          account: account, host: canonical, previous: previous,
          live_other: (live && live.account_id != account.id ? live : nil),
          zone_delegation: zone
        )

        unless decision.allowed?
          outcome = [:conflict, decision, live]
          raise ActiveRecord::Rollback
        end

        if live && live.account_id == account.id
          outcome = [:existing, live]
          next
        end

        chosen_proof = requested_proof(proof, decision.proof)
        token = ProofToken.generate

        row = CustomDomain.new(
          account_id: account.id,
          host: canonical,
          registrable_domain: registrable,
          state: "pending",
          proof: chosen_proof,
          token_blob: @vault.encrypt(token, aad: "claim:#{canonical}:#{account.id}"),
          token_digest: ProofToken.digest(token),
          token_issued_at: now,
          token_expires_at: now + @config.pending_ttl,
          next_check_at: now,
          risk_level: risk_level_for(decision.reason),
          review_required: decision.review? ? 1 : 0,
          review_reason: decision.review? ? decision.reason.to_s : nil,
          delegation_id: zone&.id,
          created_at: now,
          updated_at: now
        )
        row.save!

        audit.record!(action: "claim.created", actor_type: "account", actor_id: account.id,
                      subject_type: "custom_domain", subject_id: row.id, host: canonical,
                      metadata: { proof: chosen_proof, decision: decision.reason.to_s,
                                  previous_claim_id: previous&.id,
                                  review: decision.review? })

        if decision.notify_previous && previous
          @notifier.notify!(
            account_id: previous.account_id,
            kind: "host_reclaimed",
            host: canonical,
            payload: { by_account_id: account.id, claim_id: row.id,
                       dispute_by: (now + @config.dispute_window).iso8601 }
          )
        end

        outcome = [:created, row, token]
      end

      finish_claim(outcome, account: account, canonical: canonical)
    rescue ActiveRecord::RecordNotUnique
      # Two concurrent claims for the same host: the partial unique index is the
      # final arbiter. Report it as an ordinary conflict rather than leaking a
      # database error, and re-read the winner so the caller sees who holds it.
      winner = CustomDomain.live.find_by(host: canonical)
      audit.record!(action: "claim.conflict", actor_type: "account", actor_id: account.id,
                    subject_type: "custom_domain", subject_id: winner&.id, host: canonical,
                    metadata: { reason: "concurrent_claim" })
      raise ClaimConflict.new("this hostname was just claimed by another account", claim: winner)
    end

    def finish_claim(outcome, account:, canonical:)
      kind, *args = outcome
      case kind
      when :conflict
        decision, live = args
        audit.record!(action: "claim.conflict", actor_type: "account", actor_id: account.id,
                      subject_type: "custom_domain", subject_id: live&.id, host: canonical,
                      metadata: { reason: decision.reason.to_s })
        raise ClaimConflict.new("this hostname is already connected by another account",
                                claim: live)
      when :existing
        existing = args.first
        token = token_for(existing)
        ClaimResult.new(claim: existing, token: token,
                        instructions: instructions_for(existing, token))
      when :created
        row, token = args
        ClaimResult.new(claim: row, token: token,
                        instructions: instructions_for(row, token))
      else
        raise Error, "claim produced no outcome"
      end
    end

    # Re-checks a claim now and applies the outcome.
    def verify!(claim, actor: nil)
      claim = CustomDomain.find(claim.id)
      token = token_for(claim)
      observation = @verifier.observe_claim(claim, token)
      apply_observation!(claim.id, observation, actor: actor)
      observation
    end

    # Applies an observation to a claim. Takes an id so callers cannot pass a
    # stale object and have their in-memory state overwrite a concurrent change.
    #
    # Terminal states (`released`, `revoked`) are never modified: revocation in
    # particular must be irreversible by a later DNS observation, or an abuser
    # could wait out the moderator and have the claim silently restored.
    def apply_observation!(claim_id, observation, actor: nil)
      changed = nil
      DB.transaction do
        claim = CustomDomain.lock.find(claim_id)
        next unless claim.live?

        case observation.state
        when :present
          if claim.pending? || claim.at_risk?
            promote!(claim, observation, actor: actor)
            changed = claim
          else
            touch_healthy!(claim)
          end
        when :absent
          if claim.pending?
            note_pending_attempt!(claim)
          elsif claim.active?
            mark_at_risk!(claim, observation, actor: actor)
            changed = claim
          elsif claim.at_risk?
            note_still_absent!(claim)
          end
        else
          note_inconclusive!(claim)
        end
      end
      changed
    end

    # ---------------------------------------------------------------- release --

    def release(claim, actor: nil, reason: "user_unbind")
      DB.transaction do
        row = CustomDomain.lock.find(claim.id)
        next row unless row.live?

        release_row!(row, reason: reason, actor: actor)
        row
      end
    end

    # Abuse action: unservable immediately, tombstone marked so any later
    # re-claim by anyone is scrutinised.
    def revoke(claim, reason:, actor: nil)
      DB.transaction do
        row = CustomDomain.lock.find(claim.id)
        was_live = row.live?
        row.state = "revoked"
        row.review_required = 1
        row.review_reason = reason.to_s
        row.released_at = now
        row.release_reason = reason.to_s
        row.next_check_at = nil
        row.updated_at = now
        row.save!

        audit.record!(action: "claim.revoked", actor_type: actor_type(actor),
                      actor_id: actor_id(actor), subject_type: "custom_domain",
                      subject_id: row.id, host: row.host,
                      metadata: { reason: reason.to_s, was_live: was_live })
        row
      end
    end

    # A previous owner contesting a reclaim. Flags for review; the current
    # claim keeps serving until a moderator decides, since a fraudulent dispute
    # must not become a denial-of-service primitive.
    def dispute(claim, account:, message: nil)
      row = CustomDomain.find(claim.id)
      raise Error, "you cannot dispute your own claim" if row.account_id == account.id
      unless row.risk_level == "risky_reclaim" || row.review_required.to_i == 1
        raise Error, "there is no recent reclaim on this hostname to dispute"
      end

      DB.transaction do
        row.lock!
        row.reload
        row.review_required = 1
        row.review_reason = "dispute: #{message}".slice(0, 200)
        row.updated_at = now
        row.save!

        audit.record!(action: "claim.disputed", actor_type: "account", actor_id: account.id,
                      subject_type: "custom_domain", subject_id: row.id, host: row.host,
                      metadata: { message: message.to_s.slice(0, 500) })
        @notifier.notify!(account_id: row.account_id, kind: "host_disputed",
                          host: row.host, payload: { by_account_id: account.id })
        row
      end
    end

    # ------------------------------------------------------------- delegation --

    def create_delegation(account:, domain:)
      canonical = canonical_host(domain)
      if canonical != registrable_domain(canonical)
        raise InvalidDomain, "delegations must be on a registrable domain"
      end
      @limiter.check!("delegation:acct:#{account.id}", limit: 30, window: 24 * 3600)

      DB.transaction do
        if DomainDelegation.live.where(registrable_domain: canonical)
                              .where.not(account_id: account.id).exists?
          raise ClaimConflict.new("this domain is already delegated by another account")
        end
        existing = DomainDelegation.live.find_by(registrable_domain: canonical,
                                                 account_id: account.id)
        if existing
          token = token_for_delegation(existing)
          return DelegationResult.new(delegation: existing, token: token,
                                      fqdn: @config.verification_fqdn(canonical))
        end

        token = ProofToken.generate
        row = DomainDelegation.new(
          account_id: account.id,
          registrable_domain: canonical,
          state: "pending",
          token_blob: @vault.encrypt(token, aad: "delegation:#{canonical}:#{account.id}"),
          token_digest: ProofToken.digest(token),
          next_check_at: now,
          created_at: now, updated_at: now
        )
        row.save!
        audit.record!(action: "delegation.created", actor_type: "account", actor_id: account.id,
                      subject_type: "domain_delegation", subject_id: row.id, host: canonical)
        DelegationResult.new(delegation: row, token: token,
                             fqdn: @config.verification_fqdn(canonical))
      end
    end

    def verify_delegation(delegation, actor: nil)
      token = token_for_delegation(DomainDelegation.find(delegation.id))
      observation = @verifier.observe_delegation(delegation, token)

      DB.transaction do
        row = DomainDelegation.lock.find(delegation.id)
        row.last_checked_at = now
        if observation.state == :present
          newly = row.state != "active"
          row.state = "active"
          row.verified_at = now
          row.next_check_at = schedule_next_check
          row.save!
          if newly
            audit.record!(action: "delegation.verified", actor_type: actor_type(actor),
                          actor_id: actor_id(actor), subject_type: "domain_delegation",
                          subject_id: row.id, host: row.registrable_domain)
          end
        else
          row.next_check_at = now + (observation.state == :absent ? @config.health_check_interval : 3600)
          row.save!
        end
        row.updated_at = now
        row.save!
      end
      observation
    end

    # --------------------------------------------------------------- helpers --

    def proof_instructions(claim, account:)
      row = CustomDomain.find(claim.id)
      raise Error, "not your claim" if row.account_id != account.id

      token = token_for(row)
      ClaimResult.new(claim: row, token: token, instructions: instructions_for(row, token))
    end

    def canonical_host(raw)
      ascii = Idna.to_ascii(raw)
      labels = ascii.split(".")
      if labels.length < 2
        raise InvalidDomain, "a hostname with at least two labels is required"
      end
      if Idna.reserved_tld?(ascii)
        raise InvalidDomain, "hostnames under .#{labels.last} cannot be bound"
      end

      edge = @config.edge_domain.to_s
      if !edge.empty? && (ascii == edge || ascii.end_with?(".#{edge}"))
        raise InvalidDomain, "the platform's own hostname cannot be claimed"
      end
      if @public_suffix.public_suffix?(ascii)
        raise PublicSuffixNotRegistrable, "#{ascii} is a public suffix and cannot be bound"
      end
      ascii
    end

    def registrable_domain(ascii_host)
      reg = @public_suffix.registrable_domain(ascii_host)
      raise InvalidDomain, "no registrable domain for #{ascii_host}" if reg.nil?
      reg
    end

    def token_for(claim)
      unless claim.token_available?
        raise KeyVaultError, "claim #{claim.id} has no stored token"
      end
      @vault.decrypt(claim.token_blob, aad: "claim:#{claim.host}:#{claim.account_id}")
    end

    def token_for_delegation(delegation)
      @vault.decrypt(delegation.token_blob,
                     aad: "delegation:#{delegation.registrable_domain}:#{delegation.account_id}")
    end

    private

    def actor_type(actor)
      actor.is_a?(Hash) ? actor[:type] : nil
    end

    def actor_id(actor)
      actor.is_a?(Hash) ? actor[:id] : nil
    end

    def instructions_for(claim, token)
      {
        host: claim.host,
        proof: claim.proof,
        txt: { name: @config.verification_fqdn(claim.host), type: "TXT", value: token },
        cname: { name: claim.host, type: "CNAME",
                 value: CnameTarget.build(token: token, config: @config) },
        expires_at: claim.token_expires_at&.iso8601
      }
    end

    def promote!(claim, observation, actor:)
      claim.state = "active"
      claim.verified_at = now
      claim.verified_via = observation.via
      claim.last_checked_at = now
      claim.next_check_at = schedule_next_check
      claim.check_failures = 0
      claim.at_risk_since = nil
      claim.updated_at = now
      claim.save!

      audit.record!(action: "claim.verified", actor_type: actor_type(actor),
                    actor_id: actor_id(actor), subject_type: "custom_domain",
                    subject_id: claim.id, host: claim.host,
                    metadata: { via: observation.via })
    end

    def mark_at_risk!(claim, observation, actor:)
      claim.state = "at_risk"
      claim.at_risk_since = now
      claim.last_checked_at = now
      claim.check_failures = claim.check_failures.to_i + 1
      claim.next_check_at = now + @config.health_check_interval
      claim.updated_at = now
      claim.save!

      audit.record!(action: "claim.at_risk", actor_type: actor_type(actor),
                    actor_id: actor_id(actor), subject_type: "custom_domain",
                    subject_id: claim.id, host: claim.host,
                    metadata: { via: observation.via, detail: observation.detail })
      @notifier.notify!(account_id: claim.account_id, kind: "host_detached",
                        host: claim.host,
                        payload: { grace_until: (now + @config.detach_grace).iso8601 })
    end

    def touch_healthy!(claim)
      claim.last_checked_at = now
      claim.next_check_at = schedule_next_check
      claim.check_failures = 0
      claim.updated_at = now
      claim.save!
    end

    def note_pending_attempt!(claim)
      claim.last_checked_at = now
      claim.check_failures = claim.check_failures.to_i + 1
      ceiling = claim.token_expires_at || (now + @config.pending_ttl)
      claim.next_check_at = [now + backoff(claim.check_failures), ceiling].min
      claim.updated_at = now
      claim.save!
    end

    def note_still_absent!(claim)
      claim.last_checked_at = now
      claim.check_failures = claim.check_failures.to_i + 1
      claim.next_check_at = now + @config.health_check_interval
      claim.updated_at = now
      claim.save!
    end

    def note_inconclusive!(claim)
      claim.last_checked_at = now
      claim.next_check_at = now + [@config.health_check_interval / 4, 3600].max
      claim.updated_at = now
      claim.save!
    end

    def release_row!(claim, reason:, actor:)
      claim.state = "released"
      claim.released_at = now
      claim.release_reason = reason.to_s
      claim.next_check_at = nil
      claim.updated_at = now
      claim.save!

      audit.record!(action: "claim.released", actor_type: actor_type(actor),
                    actor_id: actor_id(actor), subject_type: "custom_domain",
                    subject_id: claim.id, host: claim.host,
                    metadata: { reason: reason.to_s, proof: claim.proof })
    end

    def schedule_next_check
      jitter = (@config.health_check_jitter * (rand - 0.5)).to_i
      now + @config.health_check_interval + jitter
    end

    def backoff(failures)
      [60 * (2**[failures, 6].min), 3600].min
    end

    def requested_proof(requested, decided)
      return decided if requested.nil?

      requested = requested.to_s
      unless CustomDomain::PROOFS.include?(requested)
        raise InvalidDomain, "unknown proof type #{requested.inspect}"
      end
      # A caller may ask for the stronger proof than required, never weaker.
      return "txt" if decided == "txt" && requested == "cname"

      requested
    end

    def risk_level_for(reason)
      case reason
      when :recent_release_other_account, :previous_abuse_revocation
        "risky_reclaim"
      else
        "normal"
      end
    end
  end
end
