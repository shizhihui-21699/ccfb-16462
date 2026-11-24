require "test_helper"
require "openssl"

module DomainGuard
  class IssuanceTest < TestCase
    def setup
      super
      @host = "www.alice-store.com"
      @claim = active_claim(@alice, @host)
    end

    def test_issue_produces_valid_certificate
      cert = @issuer.issue(account: @alice, claims: [@claim])
      x509 = OpenSSL::X509::Certificate.new(cert.cert_pem)
      assert x509.verify(@ca.certificate.public_key), "certificate must verify against the CA"
      san = x509.extensions.find { |e| e.oid == "subjectAltName" }
      assert_equal "DNS:#{@host}", san.value
      # The chain must contain the issuing CA.
      chain = OpenSSL::X509::Certificate.new(cert.chain_pem)
      assert_equal @ca.certificate.subject.to_s, chain.subject.to_s
      assert cert.not_after > @now
      assert_equal "issued", cert.state
    end

    def test_certificate_private_key_round_trips
      cert = @issuer.issue(account: @alice, claims: [@claim])
      pem = @issuer.private_key(cert)
      key = OpenSSL::PKey.read(pem)
      x509 = OpenSSL::X509::Certificate.new(cert.cert_pem)
      assert x509.check_private_key(key), "cert and key must match"
    end

    def test_cannot_issue_for_other_accounts_claim
      assert_raises(IssuanceDenied) do
        @issuer.issue(account: @bob, claims: [@claim])
      end
    end

    def test_cannot_issue_for_pending_claim
      pending = @service.claim(account: @alice, host: "new.alice-store.com")
      assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [pending.claim])
      end
    end

    # The key regression: an `active` state left over from before DNS changed
    # must not be enough. Issuance re-looks at DNS.
    def test_cannot_issue_when_dns_no_longer_proves_control
      @dns.remove_cname(@host)
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim])
      end
      assert_equal :proof_missing, err.reason
    end

    def test_cannot_issue_for_at_risk_claim
      @dns.remove_cname(@host)
      @service.verify!(@claim)
      assert_equal "at_risk", CustomDomain.find(@claim.id).state
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [CustomDomain.find(@claim.id)])
      end
      assert_equal :not_active, err.reason
    end

    def test_caa_permitted
      @dns.set_caa(@host, [{ flags: 0, tag: "issue", value: "kite-ca.example" }])
      cert = @issuer.issue(account: @alice, claims: [@claim])
      assert_equal "issued", cert.state
    end

    def test_caa_denies_when_platform_ca_not_listed
      @dns.set_caa(@host, [{ flags: 0, tag: "issue", value: "other-ca.example" }])
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim])
      end
      assert_equal :caa, err.reason
    end

    def test_caa_wildcard_only_does_not_permit_non_wildcard
      # An "issuewild" entry alone must not authorise a normal name.
      @dns.set_caa(@host, [{ flags: 0, tag: "issuewild", value: "other-ca.example" }])
      # No "issue" record at all means issuance is forbidden by CAA.
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim])
      end
      assert_equal :caa, err.reason
    end

    def test_caa_inconclusive_is_a_hard_failure
      @dns.override(@host, :caa, :inconclusive, detail: "SERVFAIL")
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim])
      end
      assert_equal :caa_lookup_failed, err.reason
    end

    def test_caa_on_parent_applies_to_subdomain
      @dns.set_caa("alice-store.com", [{ flags: 0, tag: "issue", value: "other-ca.example" }])
      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim])
      end
      assert_equal :caa, err.reason
    end

    def test_recent_reclaim_first_certificate_waits_for_review
      @service.release(@claim)
      attack = @service.claim(account: @bob, host: @host)
      publish_txt(@host, attack.token)
      @service.verify!(attack.claim)
      row = CustomDomain.find(attack.claim.id)
      assert_equal "active", row.state

      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @bob, claims: [row])
      end
      assert_equal :awaiting_review, err.reason
    end

    def test_certificate_superseded_on_renewal
      cert = @issuer.issue(account: @alice, claims: [@claim])
      advance(70 * 86_400)
      renewed = @issuer.renew(CustomDomain.find(@claim.id) && cert)
      assert_equal "issued", renewed.state
      assert_equal "superseded", Certificate.find(cert.id).state
      refute_equal cert.serial, renewed.serial
    end

    def test_renewal_denied_when_domain_lost_proof
      cert = @issuer.issue(account: @alice, claims: [@claim])
      @dns.remove_cname(@host)
      assert_raises(IssuanceDenied) { @issuer.renew(cert) }
      assert_equal "superseded", Certificate.find(cert.id).state,
                   "a certificate whose domain can no longer be proven must not keep renewing"
    end

    def test_serving_certificate_requires_live_claim
      cert = @issuer.issue(account: @alice, claims: [@claim])
      assert_equal cert.id, @issuer.serving_certificate(@host).id

      @service.release(@claim)
      assert_nil @issuer.serving_certificate(@host)
    end

    def test_revocation_makes_certificate_unservable
      cert = @issuer.issue(account: @alice, claims: [@claim])
      @issuer.revoke(cert, reason: "key_compromise")
      assert_nil @issuer.serving_certificate(@host)
      assert_equal "revoked", Certificate.find(cert.id).state
    end

    def test_multi_name_certificate
      c2 = active_claim(@alice, "shop.alice-store.com")
      cert = @issuer.issue(account: @alice, claims: [@claim, c2])
      assert_equal ["shop.alice-store.com", @host], cert.names.sort
      san = OpenSSL::X509::Certificate.new(cert.cert_pem).extensions.find { |e| e.oid == "subjectAltName" }
      assert_includes san.value, "DNS:#{@host}"
      assert_includes san.value, "DNS:shop.alice-store.com"
    end

    def test_too_many_names_rejected
      @config.max_sans = 1
      c2 = active_claim(@alice, "shop.alice-store.com")
      assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [@claim, c2])
      end
    end

    # Dispute semantics: a disputed claim cannot gain a *new* certificate, but
    # its existing certificate may still renew. A dispute is a claim about
    # ownership, not a kill switch, so the incumbent site stays up.
    def test_disputed_claim_cannot_get_new_certificate
      cert = @issuer.issue(account: @alice, claims: [@claim])
      CustomDomain.where(id: @claim.id).update_all(
        review_required: 1, review_reason: "dispute: contested"
      )
      row = CustomDomain.find(@claim.id)

      err = assert_raises(IssuanceDenied) do
        @issuer.issue(account: @alice, claims: [row])
      end
      assert_equal :disputed, err.reason

      # Renewal of the existing cert is still allowed.
      advance(70 * 86_400)
      renewed = @issuer.renew(cert)
      assert_equal "issued", renewed.state
    end

    # A claim that is no longer the account's (ownership moved) cannot renew.
    def test_cannot_renew_after_ownership_change
      cert = @issuer.issue(account: @alice, claims: [@claim])
      @service.release(@claim)
      retaken = @service.claim(account: @bob, host: @host)
      publish_txt(@host, retaken.token)
      @service.verify!(retaken.claim)

      assert_raises(IssuanceDenied) { @issuer.renew(cert) }
    end
  end
end
