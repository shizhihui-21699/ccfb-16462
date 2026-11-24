require "domain_guard/errors"
require "domain_guard/models"

module DomainGuard
  # Pure decision logic: given the facts about a host, what may happen?
  #
  # Keeping this free of I/O makes the security rules directly testable and
  # reviewable. The service layer gathers facts and applies the decision.
  #
  # The central rule, and the fix for the reported incident:
  #
  #   A leftover DNS record is proof that *somebody* once controlled the name.
  #   It is never proof that the *current claimant* controls it now. Therefore
  #   a record may only satisfy a claim if it carries the fresh, random token
  #   generated for that exact claim — which a previous owner's leftover record
  #   cannot contain.
  #
  # On top of that:
  #   * a live claim by another account is an absolute conflict;
  #   * a host re-claimed soon after release by a *different* account is
  #     allowed only with the strong proof, is queued for review, and notifies
  #     the previous owner.
  class ClaimPolicy
    Decision = Struct.new(:allowed, :proof, :reason, :requires_review, :notify_previous,
                          keyword_init: true) do
      def allowed?; allowed; end
      def review?; requires_review; end
    end

    STRONG_PROOF = "txt".freeze

    def initialize(config:, clock: nil)
      @config = config
      @clock = clock || config.clock
    end

    def now
      @clock.call
    end

    # @param previous [CustomDomain, nil] the most recent *non-live* claim on
    #   this host (released/revoked), if any.
    # @param live_other [CustomDomain, nil] a live claim owned by another
    #   account, if any.
    def decide_new_claim(account:, host:, previous:, live_other:, zone_delegation: nil)
      if live_other && live_other.account_id != account.id
        return Decision.new(
          allowed: false, proof: nil, reason: :live_conflict,
          requires_review: false, notify_previous: false
        )
      end

      return Decision.new(allowed: true, proof: proof_for(host, @config.default_proof),
                          reason: :first_claim, requires_review: false,
                          notify_previous: false) if previous.nil?

      # Same account re-binding a host it previously held: no extra friction.
      if previous.account_id == account.id
        return Decision.new(allowed: true, proof: proof_for(host, @config.default_proof),
                            reason: :reclaim_by_owner, requires_review: false,
                            notify_previous: false)
      end

      # Another account held this host before. If that claim ended in an abuse
      # revocation, treat it with maximum scrutiny.
      if previous.state == "revoked"
        return Decision.new(allowed: true, proof: STRONG_PROOF,
                            reason: :previous_abuse_revocation, requires_review: true,
                            notify_previous: true)
      end

      # Zone-level delegation by the *claimant* removes friction for agencies
      # that already proved control of the registrable domain.
      if zone_delegation && zone_delegation.state == "active" &&
         zone_delegation.account_id == account.id
        return Decision.new(allowed: true, proof: proof_for(host, @config.default_proof),
                            reason: :covered_by_zone_delegation, requires_review: false,
                            notify_previous: false)
      end

      elapsed = previous.released_at ? (now - previous.released_at) : Float::INFINITY
      if elapsed < @config.reclaim_cooldown
        # Recent hand-over to a different account. Allowed, but:
        #   * strong proof only (fresh TXT token), and
        #   * human review, and
        #   * the previous owner is told, so they can dispute a mistake.
        # This is the path the reported attacker would need to take, and it
        # cannot be completed without actually controlling the DNS zone.
        Decision.new(allowed: true, proof: STRONG_PROOF,
                     reason: :recent_release_other_account, requires_review: true,
                     notify_previous: true)
      else
        Decision.new(allowed: true, proof: STRONG_PROOF,
                     reason: :release_cooled_off, requires_review: false,
                     notify_previous: true)
      end
    end

    # Whether a newly verified claim may be promoted to active without a human.
    def auto_activate?(claim)
      !claim.review_required?
    end

    # Whether a claim's proof is recent enough to underwrite a certificate.
    def issuance_fresh?(claim)
      claim.active? && claim.verified_at &&
        (now - claim.verified_at) <= @config.verification_freshness
    end

    # Whether a live claim should be considered detached by the scheduler.
    # `observation` is :present, :absent or :inconclusive.
    def detach_action(claim, observation)
      case observation
      when :present
        :clear_risk
      when :absent
        if claim.at_risk?
          elapsed = now - claim.at_risk_since
          elapsed >= @config.detach_grace ? :release : :stay_at_risk
        else
          :mark_at_risk
        end
      else
        # Never act on an inconclusive observation.
        :no_change
      end
    end

    private

    # "auto" resolves to CNAME when the host can hold one (i.e. it is not an
    # apex), else TXT.
    def proof_for(host, requested)
      return requested unless requested == "auto"

      apex?(host) ? "txt" : "cname"
    end

    def apex?(host)
      host.split(".").length <= 2
    end
  end
end
