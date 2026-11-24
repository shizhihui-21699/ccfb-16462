module DomainGuard
  class Error < StandardError; end

  # Raised when a caller tries to bind a domain that another account is
  # currently routing. Never merged with "domain not found": the conflict is
  # actionable for the user ("this domain is already connected to a site").
  class ClaimConflict < Error
    attr_reader :claim

    def initialize(message = nil, claim: nil)
      super(message || "domain is already claimed by another account")
      @claim = claim
    end
  end

  # The domain is in the post-release cool-down window and the caller has not
  # produced the stronger proof of control that lifts it.
  class VerificationRequired < Error
    attr_reader :claim

    def initialize(message = nil, claim: nil)
      super(message || "additional proof of domain control is required")
      @claim = claim
    end
  end

  class InvalidDomain < Error; end
  class PublicSuffixNotRegistrable < InvalidDomain; end

  # Raised by the issuance policy. Deliberately a *deny by default* path:
  # every condition that is not provably satisfied results in this error.
  class IssuanceDenied < Error
    attr_reader :reason

    def initialize(reason, message = nil)
      @reason = reason
      super(message || "certificate issuance denied: #{reason}")
    end
  end

  class RateLimited < Error
    attr_reader :key, :retry_after

    def initialize(key, retry_after)
      @key = key
      @retry_after = retry_after
      super("rate limit exceeded for #{key}, retry in #{retry_after}s")
    end
  end

  class AcmeError < Error
    attr_reader :problem

    def initialize(message, problem: nil)
      @problem = problem
      super(message)
    end
  end

  class KeyVaultError < Error; end
end
