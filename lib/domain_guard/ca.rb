require "openssl"
require "securerandom"
require "domain_guard/errors"
require "domain_guard/crypto"

module DomainGuard
  # Certificate bodies. Either a local CA (for the self-contained demo and for
  # tests, which need real parseable certificates) or the platform's ACME
  # client (production). Both produce the same IssuedCertificate struct.
  module Keys
    module_function

    def generate(config)
      case config.key_algorithm
      when "rsa" then OpenSSL::PKey::RSA.new(config.rsa_bits)
      else OpenSSL::PKey::EC.generate("prime256v1")
      end
    end

    def private_pem(key)
      key.private_to_pem
    rescue NoMethodError
      key.to_pem
    end
  end

  IssuedCertificate = Struct.new(:cert_pem, :chain_pem, :serial, :not_before,
                                 :not_after, :private_key_pem, keyword_init: true)

  # A minimal but standards-shaped CA. It exists so the whole flow — policy,
  # issuance, renewal, revocation — can be demonstrated and tested without an
  # external dependency. Certificates it issues carry proper SANs,
  # basicConstraints and EKU, and are parseable by any TLS stack.
  class LocalCA
    attr_reader :certificate

    def initialize(key:, certificate:)
      @key = key
      @certificate = certificate
    end

    def self.generate(common_name: "Kite Internal CA", days: 3650, clock: -> { Time.now.utc })
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = SecureRandom.random_number(2**64)
      cert.subject = OpenSSL::X509::Name.parse("/O=Kite/CN=#{common_name}")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      now = clock.call
      cert.not_before = now - 60
      cert.not_after = now + (days * 86_400)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign,digitalSignature", true))
      cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      new(key: key, certificate: cert)
    end

    def self.load(key_pem:, cert_pem:)
      new(key: OpenSSL::PKey.read(key_pem), certificate: OpenSSL::X509::Certificate.new(cert_pem))
    end

    def issue(names:, key:, lifetime:, clock:)
      raise IssuanceDenied.new(:no_names, "no names requested") if names.empty?

      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = SecureRandom.random_number(2**128)
      primary = names.first
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{primary.gsub(/[^a-zA-Z0-9.\-]/, '')}")

      issuer_cert = @certificate
      cert.issuer = issuer_cert.subject
      cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? key : key.public_key

      not_before = clock.call - 300 # small backdate for clock skew
      not_after = not_before + lifetime
      cert.not_before = not_before
      cert.not_after = not_after

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = issuer_cert
      cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
      cert.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
      cert.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth", false))
      cert.add_extension(ef.create_extension("subjectAltName", names.map { |n| "DNS:#{n}" }.join(","), false))
      cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always", false))

      # A CA must sign with its own key. In a real deployment this call is where
      # the ACME finalize happens and the CA is remote.
      cert.sign(@key, OpenSSL::Digest::SHA256.new)

      IssuedCertificate.new(
        cert_pem: cert.to_pem,
        chain_pem: issuer_cert.to_pem,
        serial: cert.serial.to_s,
        not_before: not_before,
        not_after: not_after,
        private_key_pem: Keys.private_pem(key)
      )
    end

    def revoke(_serial, _reason); true; end
  end

  # Adapter boundary for the production ACME client (order → challenges →
  # finalize → download). The demo and tests use LocalCA instead.
  #
  # Deliberately *not* a working implementation: a stub that returns a fake
  # certificate would be worse than an explicit failure, because it would look
  # like issuance succeeded. A real implementation must also prove control at
  # finalize time using the same claim tokens this library already manages, so
  # it is wired with a token resolver.
  class AcmeClient
    def initialize(config:, dns:, token_resolver:, clock: nil)
      @config = config
      @dns = dns
      @token_resolver = token_resolver
      @clock = clock || config.clock
    end

    def issue(names:, key:, lifetime:, clock:)
      raise NotImplementedError,
            "AcmeClient is an adapter seam; wire the platform's ACME client here. " \
            "It must resolve each name's claim token and pass ACME challenge " \
            "verification before finalizing."
    end

    def revoke(_serial, _reason)
      raise NotImplementedError, "AcmeClient#revoke is not implemented"
    end
  end
end
