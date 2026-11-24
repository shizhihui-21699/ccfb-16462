require "test_helper"

module DomainGuard
  # The reported incident, encoded as tests.
  #
  # Scenario: attacker observes that victim-site.com still publishes the verification
  # record from the platform the victim migrated *away* from. The victim deleted
  # the custom domain on the old platform (which released it) but did not clean
  # up the DNS record. The attacker binds victim-site.com on the platform and
  # obtains a certificate, then serves an impostor site.
  class HijackAttackTest < TestCase
    def setup
      super
      @host = "www.victim-site.com"
    end

    # The central regression test. The leftover record was produced for the
    # victim's *original* claim. It must not satisfy a new claim, because the
    # new claim has a different token and the token in DNS is compared exactly.
    def test_leftover_verification_record_cannot_bind_host
      # Victim's original claim, as it was before they migrated away.
      original = @service.claim(account: @alice, host: @host)
      publish_cname(@host, original.token)
      assert_equal :present, @service.verify!(original.claim).state
      @service.release(CustomDomain.find(original.claim.id))

      # The DNS record is *not* cleaned up (this is the attacker's premise).
      assert @dns.cname(@host).records?, "stale CNAME should still be in DNS"

      # Attacker creates a new claim. It gets a fresh token that differs from
      # the one still published.
      attack = @service.claim(account: @bob, host: @host)
      refute_equal original.token, attack.token

      observation = @service.verify!(attack.claim)
      refute_equal :present, observation.state
      assert_equal "pending", CustomDomain.find(attack.claim.id).state,
                   "leftover record must not activate a new claim"
    end

    # Even the *old token itself*, if an attacker somehow knew it, is useless:
    # the platform only ever compares against the current claim's token. This
    # asserts the token is not reusable by publishing it again.
    def test_old_token_is_not_accepted_for_new_claim
      original = @service.claim(account: @alice, host: @host)
      @service.release(CustomDomain.find(original.claim.id))

      attack = @service.claim(account: @bob, host: @host)
      publish_cname(@host, original.token) # stale value
      assert_equal :absent, @service.verify!(attack.claim).state

      # Now the attacker actually controls DNS and publishes the value this
      # claim asked for. This is the point where binding is legitimate: the
      # proof is fresh and specific to this claim.
      if attack.instructions[:proof] == "txt"
        publish_txt(@host, attack.token)
      else
        publish_cname(@host, attack.token)
      end
      assert_equal :present, @service.verify!(attack.claim).state
    end

    # If a stale record is a TXT record, the same rule applies.
    def test_leftover_txt_record_cannot_bind_apex
      host = "victim-site.com"
      original = @service.claim(account: @alice, host: host)
      publish_txt(host, original.token)
      assert_equal :present, @service.verify!(original.claim).state
      @service.release(CustomDomain.find(original.claim.id))

      attack = @service.claim(account: @bob, host: host)
      assert_equal :absent, @service.verify!(attack.claim).state
    end

    # A close variant: the attacker adds a *new* record containing the old
    # token alongside the stale one. Still must not match.
    def test_multiple_stale_records_do_not_help
      original = @service.claim(account: @alice, host: @host)
      publish_cname(@host, original.token)
      @service.verify!(original.claim)
      @service.release(CustomDomain.find(original.claim.id))
      # A TXT at the same name with a near-miss value.
      publish_txt(@host, "kite-verify=#{Crypto.b64url("garbage")}")

      attack = @service.claim(account: @bob, host: @host)
      assert_equal :absent, @service.verify!(attack.claim).state
    end

    # The attacker cannot skip verification by calling the API "as" the old
    # claim or by replaying the verification endpoint: verification always
    # reads the current claim's own token from the encrypted column.
    def test_verification_is_bound_to_claim_row
      original = @service.claim(account: @alice, host: @host)
      publish_cname(@host, original.token)
      @service.verify!(original.claim)
      @service.release(CustomDomain.find(original.claim.id))

      attack = @service.claim(account: @bob, host: @host)
      # Re-publishing the original record and then asking the *new* claim to
      # verify must still fail, because the tokens differ.
      assert_equal :absent, @service.verify!(attack.claim).state
    end

    # Subdomain hijack via the special-case "the parent domain is on the
    # platform" shortcut. Even if the apex is active for Alice, Bob can only
    # take a subdomain with his own proof.
    def test_subdomain_of_active_claim_is_not_inherited_by_other_account
      apex = active_claim(@alice, "victim-site.com")
      assert apex.active?

      attack = @service.claim(account: @bob, host: "shop.victim-site.com")
      # Nothing is published for Bob's token, so verification fails.
      assert_equal :absent, @service.verify!(attack.claim).state
    end

    # An attacker must not be able to conjure a claim for a host some other
    # account is *currently* serving.
    def test_cannot_claim_live_other_account_host
      active_claim(@alice, @host)
      err = assert_raises(ClaimConflict) do
        @service.claim(account: @bob, host: @host)
      end
      assert_equal "active", err.claim.state
    end

    # Same for a pending claim: squatting a host that is mid-verification is a
    # denial of service otherwise.
    def test_cannot_claim_pending_other_account_host
      @service.claim(account: @alice, host: @host)
      assert_raises(ClaimConflict) { @service.claim(account: @bob, host: @host) }
    end

    # A reclaim soon after release by a *different* account is the risky path:
    # it is permitted only with strong proof, flagged for review, and notifies
    # the previous owner.
    def test_recent_reclaim_by_other_account_is_flagged_and_notified
      original = @service.claim(account: @alice, host: @host)
      publish_cname(@host, original.token)
      @service.verify!(original.claim)
      @service.release(CustomDomain.find(original.claim.id))

      attack = @service.claim(account: @bob, host: @host)
      row = CustomDomain.find(attack.claim.id)
      assert row.review_required?, "recent reclaim must be queued for review"
      assert_equal "risky_reclaim", row.risk_level
      assert_equal "txt", row.proof, "must require the strong proof"

      notification = Notification.where(account_id: @alice.id, kind: "host_reclaimed").first
      refute_nil notification, "previous owner must be notified"
      assert_equal @host, notification.host
    end

    # ...and even after the attacker publishes the strong proof, the claim is
    # not silently trusted: it stays flagged for human review, so the previous
    # owner's dispute has something to attach to.
    def test_risky_reclaim_stays_flagged_after_verification
      original = @service.claim(account: @alice, host: @host)
      @service.release(CustomDomain.find(original.claim.id))

      attack = @service.claim(account: @bob, host: @host)
      publish_txt(@host, attack.token)
      assert_equal :present, @service.verify!(attack.claim).state

      row = CustomDomain.find(attack.claim.id)
      assert row.active?
      assert row.review_required?, "still requires review"
    end

    # The previous owner can dispute. That must not be a denial-of-service
    # primitive: the disputed claim keeps serving until a moderator acts.
    def test_dispute_flags_but_does_not_unserve
      original = @service.claim(account: @alice, host: @host)
      @service.release(CustomDomain.find(original.claim.id))
      attack = @service.claim(account: @bob, host: @host)
      publish_txt(@host, attack.token)
      @service.verify!(attack.claim)

      @service.dispute(CustomDomain.find(attack.claim.id), account: @alice, message: "this is my domain")

      row = CustomDomain.find(attack.claim.id)
      assert row.active?, "dispute must not take the site down"
      assert_match(/dispute/, row.review_reason)
      assert Notification.where(account_id: @bob.id, kind: "host_disputed").exists?
    end

    # An abuse revocation poisons the well: a later claim by a different
    # account is strong-proof-only and reviewed, and the abuser's *own* later
    # claim also goes through the risky path.
    def test_claim_after_abuse_revocation_requires_strong_proof_and_review
      active = active_claim(@alice, @host)
      @service.revoke(active, reason: "phishing", actor: { type: "moderator", id: 7 })

      again = @service.claim(account: @bob, host: @host)
      row = CustomDomain.find(again.claim.id)
      assert_equal "txt", row.proof
      assert row.review_required?
    end

    # Revocation is terminal. An abuser who keeps publishing the token must not
    # be able to have the claim silently restored by the verification path.
    def test_revocation_is_terminal
      active = active_claim(@alice, @host)
      token = @service.token_for(CustomDomain.find(active.id))
      @service.revoke(active, reason: "phishing")
      publish_cname(@host, token) # attacker keeps DNS pointed at their proof

      @service.verify!(CustomDomain.find(active.id))
      assert_equal "revoked", CustomDomain.find(active.id).state
    end
  end
end
