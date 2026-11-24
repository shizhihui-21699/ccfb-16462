require "test_helper"

module DomainGuard
  class CryptoTest < Minitest::Test
    def setup
      @master = OpenSSL::Digest::SHA256.digest("master")
      @vault = KeyVault.new(master_key: @master)
    end

    def test_envelope_round_trip
      env = @vault.encrypt("secret", aad: "claim:a.com:1")
      assert_equal "secret", @vault.decrypt(env, aad: "claim:a.com:1")
    end

    def test_envelope_is_bound_to_aad
      env = @vault.encrypt("secret", aad: "claim:a.com:1")
      assert_raises(KeyVaultError) { @vault.decrypt(env, aad: "claim:b.com:1") }
    end

    def test_envelope_detects_tampering
      env = @vault.encrypt("secret", aad: "claim:a.com:1")
      data = JSON.parse(env)
      raw = Crypto.b64url_decode(data["data"])
      raw.setbyte(raw.bytesize - 1, raw.getbyte(raw.bytesize - 1) ^ 0xFF)
      data["data"] = Crypto.b64url(raw)
      assert_raises(KeyVaultError) { @vault.decrypt(JSON.generate(data), aad: "claim:a.com:1") }
    end

    def test_wrong_master_key_fails
      env = @vault.encrypt("secret", aad: "x")
      other = KeyVault.new(master_key: OpenSSL::Digest::SHA256.digest("other"))
      assert_raises(KeyVaultError) { other.decrypt(env, aad: "x") }
    end

    def test_envelopes_are_unique
      a = @vault.encrypt("same", aad: "x")
      b = @vault.encrypt("same", aad: "x")
      refute_equal a, b, "fresh IV and data key each time"
      assert_equal "same", @vault.decrypt(a, aad: "x")
      assert_equal "same", @vault.decrypt(b, aad: "x")
    end

    def test_secure_compare
      assert Crypto.secure_compare("abc", "abc")
      refute Crypto.secure_compare("abc", "abd")
      refute Crypto.secure_compare("abc", "ab")
    end

    def test_hkdf_rfc5869_test_case_1
      ikm = ["0b" * 22].pack("H*")
      salt = ["000102030405060708090a0b0c"].pack("H*")
      info = ["f0f1f2f3f4f5f6f7f8f9"].pack("H*")
      okm = Crypto.hkdf(ikm, salt: salt, info: info, length: 42)
      expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" \
                 "34007208d5b887185865"
      assert_equal expected, okm.unpack1("H*")
    end

    def test_proof_tokens_are_random_and_prefixed
      a = ProofToken.generate
      b = ProofToken.generate
      assert a.start_with?("kite-verify=")
      refute_equal a, b
      # 32 random bytes, base64url without padding -> 43 characters.
      assert_equal "kite-verify=".length + 43, a.length
    end

    def test_proof_digest_ignores_prefix_and_whitespace
      token = ProofToken.generate
      assert_equal ProofToken.digest(token), ProofToken.digest("  #{token}  ")
      bare = token.sub("kite-verify=", "")
      assert_equal ProofToken.digest(token), ProofToken.digest(bare)
    end

    def test_cname_target_round_trip
      config = Config.new
      token = ProofToken.generate
      target = CnameTarget.build(token: token, config: config)
      label = CnameTarget.parse(target, config: config)
      refute_nil label
      assert_equal CnameTarget.label_for(token), label
    end

    def test_cname_target_parser_rejects_foreign_targets
      config = Config.new
      assert_nil CnameTarget.parse("evil.example.com", config: config)
      assert_nil CnameTarget.parse("x.verify.kite.example", config: config)
      assert_nil CnameTarget.parse("", config: config)
    end

    def test_audit_chain_detects_edit
      DB.connect!
      audit = Audit.new(clock: -> { Time.utc(2026, 1, 1) })
      audit.record!(action: "a", host: "x.com")
      audit.record!(action: "b", host: "x.com")
      audit.record!(action: "c", host: "x.com")
      ok, = audit.verify_chain!
      assert ok

      # Tamper with a historical row.
      SQL.exec("UPDATE audit_events SET action = 'evil' WHERE id = 2")
      ok, bad = audit.verify_chain!
      refute ok
      assert_equal 2, bad
    end

    def test_audit_chain_detects_deletion
      DB.connect!
      audit = Audit.new(clock: -> { Time.utc(2026, 1, 1) })
      audit.record!(action: "a")
      audit.record!(action: "b")
      audit.record!(action: "c")
      SQL.exec("DELETE FROM audit_events WHERE id = 2")
      ok, bad = audit.verify_chain!
      refute ok
      assert_equal 3, bad
    end
  end
end
