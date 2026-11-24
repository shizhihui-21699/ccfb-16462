require "openssl"
require "securerandom"
require "base64"
require "json"

module DomainGuard
  # Small, auditable crypto helpers. Ruby 2.6 ships LibreSSL without
  # OpenSSL::KDF, so HKDF and the constant-time comparison are implemented here
  # rather than pulled in as a gem.
  module Crypto
    module_function

    def random_bytes(n = 32)
      SecureRandom.random_bytes(n)
    end

    def random_token(bytes: 32)
      b64url(random_bytes(bytes))
    end

    def b64url(bin)
      Base64.urlsafe_encode64(bin, padding: false)
    end

    def b64url_decode(str)
      s = str.tr("-_", "+/")
      s += "=" * ((4 - s.length % 4) % 4)
      Base64.decode64(s)
    end

    # RFC 5869 HKDF-SHA256.
    def hkdf(ikm, salt:, info:, length: 32)
      prk = OpenSSL::HMAC.digest("SHA256", salt, ikm)
      okm = "".b
      t = "".b
      counter = 1
      while okm.bytesize < length
        t = OpenSSL::HMAC.digest("SHA256", prk, t + info.b + [counter].pack("C"))
        okm << t
        counter += 1
      end
      okm[0, length]
    end

    def hmac(key, data)
      OpenSSL::HMAC.digest("SHA256", key, data)
    end

    def digest(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def hex(bin)
      bin.unpack1("H*")
    end

    def unhex(str)
      [str].pack("H*")
    end

    # Constant-time comparison that tolerates differing lengths.
    def secure_compare(a, b)
      a = a.to_s.b
      b = b.to_s.b
      return false unless a.bytesize == b.bytesize

      result = 0
      a.bytes.zip(b.bytes) { |x, y| result |= x ^ y }
      result.zero?
    end

    # Authenticated encryption, Encrypt-then-MAC.
    #
    # AES-256-CBC + HMAC-SHA256 rather than AES-GCM: the Ruby builds this
    # platform deploys against ship a LibreSSL whose GCM implementation rejects
    # `update`, and EtM with a full-length HMAC is a standard, well-understood
    # construction. Two independent subkeys are derived so the MAC key is never
    # the cipher key.
    #
    # output = iv(16) || ciphertext || tag(32)
    def seal(key, plaintext, aad: "")
      enc_key, mac_key = split_keys(key)
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.encrypt
      cipher.key = enc_key
      iv = random_bytes(16)
      cipher.iv = iv
      ct = cipher.update(plaintext.to_s.b) + cipher.final
      tag = OpenSSL::HMAC.digest("SHA256", mac_key, maced(iv, ct, aad))
      iv + ct + tag
    end

    def open(key, blob, aad: "")
      blob = blob.to_s.b
      raise KeyVaultError, "ciphertext too short" if blob.bytesize < 16 + 32 + 16

      iv = blob.byteslice(0, 16)
      tag = blob.byteslice(blob.bytesize - 32, 32)
      ct = blob.byteslice(16, blob.bytesize - 16 - 32)
      enc_key, mac_key = split_keys(key)

      expected = OpenSSL::HMAC.digest("SHA256", mac_key, maced(iv, ct, aad))
      raise KeyVaultError, "ciphertext failed authentication" unless secure_compare(expected, tag)

      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.key = enc_key
      cipher.iv = iv
      cipher.update(ct) + cipher.final
    end

    def maced(iv, ct, aad)
      [aad.to_s.b.bytesize].pack("Q>") + aad.to_s.b + iv + ct
    end

    def split_keys(key)
      material = hkdf(key, salt: "domain-guard-etm", info: "keys", length: 64)
      [material.byteslice(0, 32), material.byteslice(32, 32)]
    end
  end

  # Envelope encryption: every secret gets its own data key, sealed under a key
  # derived from the master key and bound to the secret's identity (so a
  # ciphertext cannot be swapped between rows).
  class KeyVault
    KEY_VERSION = 2

    def initialize(master_key:, context: "domain-guard")
      @master = master_key
      @context = context
    end

    def encrypt(plaintext, aad:)
      data_key = Crypto.random_bytes(32)
      aad_bytes = "#{@context}|v#{KEY_VERSION}|#{aad}"
      sealed = Crypto.seal(data_key, plaintext, aad: aad_bytes)
      wrapped_key = Crypto.seal(@master, data_key, aad: "wrap|#{aad_bytes}")

      JSON.generate(
        "v" => KEY_VERSION,
        "data" => Crypto.b64url(sealed),
        "key" => Crypto.b64url(wrapped_key)
      )
    end

    def decrypt(envelope, aad:)
      data = JSON.parse(envelope)
      raise KeyVaultError, "unsupported envelope version" unless data["v"] == KEY_VERSION

      aad_bytes = "#{@context}|v#{KEY_VERSION}|#{aad}"
      data_key = Crypto.open(@master, Crypto.b64url_decode(data["key"]),
                             aad: "wrap|#{aad_bytes}")
      Crypto.open(data_key, Crypto.b64url_decode(data["data"]), aad: aad_bytes)
    end
  end
end
