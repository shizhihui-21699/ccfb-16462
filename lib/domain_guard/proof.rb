require "domain_guard/errors"
require "domain_guard/crypto"
require "domain_guard/models"

module DomainGuard
  # Proof tokens.
  #
  # Invariants this module exists to guarantee:
  #
  #   * Every claim gets a *fresh* random token, unrelated to the hostname. A
  #     record left behind by a previous owner can therefore never match a
  #     later claim's token.
  #   * The token is never accepted as caller input. The only value that
  #     satisfies a claim is the token this platform generated for that exact
  #     claim row.
  #   * Comparison uses a digest; the plaintext is envelope-encrypted only so
  #     the owner can re-display it. A database dump alone yields neither.
  module ProofToken
    PREFIX = "kite-verify=".freeze

    module_function

    def generate
      "#{PREFIX}#{Crypto.b64url(Crypto.random_bytes(32))}"
    end

    # Accepts a full record value ("kite-verify=..."), hashes the token part.
    def digest(value)
      token = value.to_s.strip
      token = token.sub(/\A#{Regexp.escape(PREFIX)}/, "")
      Crypto.hex(Crypto.digest(token))
    end
  end

  # The per-claim CNAME target:
  #
  #   <host>  CNAME  <label>.<cname_suffix>
  #
  # The label is derived from the claim's own token, so a leftover CNAME from a
  # previous owner points at that owner's label — not this claimant's. The edge
  # routes a request only when the CNAME target resolves to a live claim.
  module CnameTarget
    LABEL_LENGTH = 26

    module_function

    def build(token:, config:)
      "#{label_for(token)}.#{config.cname_suffix}"
    end

    # Returns the label if `target` is one of our CNAME targets, else nil.
    def parse(target, config:)
      target = target.to_s.sub(/\.\z/, "").downcase
      suffix = ".#{config.cname_suffix}".downcase
      return nil unless target.end_with?(suffix)

      label = target[0, target.length - suffix.length]
      label =~ /\A[a-z0-9]{#{LABEL_LENGTH}}\z/ ? label : nil
    end

    def label_for(token)
      Crypto.hex(Crypto.digest(token.to_s))[0, LABEL_LENGTH]
    end
  end
end
