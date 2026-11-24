require "domain_guard/punycode"

module DomainGuard
  # Pragmatic UTS #46 non-transitional mapping plus label validation.
  #
  # The binding path only needs enough IDNA to guarantee one thing: two
  # spellings of the same name always normalise to the same ASCII form. That
  # property is what stops a claim on "bücher.example" from coexisting with a
  # claim on "xn--bcher-kva.example" and being routed to a different account.
  module Idna
    MAX_LABEL = 63
    MAX_HOST = 253

    # Characters that some clients silently drop or that render as nothing.
    # They have no business in a hostname we bind.
    INVISIBLE = /[​-‏‪-‮⁠-⁤﻿]/

    # Labels we refuse to bind even though they are syntactically valid.
    RESERVED_TLDS = %w[local localhost internal test invalid example onion].freeze

    module_function

    def to_ascii(host)
      raise InvalidDomain, "hostname is required" if host.nil? || host.to_s.strip.empty?

      mapped = map(host)
      # One trailing dot is the DNS root and is equivalent to no dot.
      mapped = mapped[0..-2] if mapped.end_with?(".")
      labels = mapped.split(".", -1)
      raise InvalidDomain, "hostname has an empty label" if labels.any? { |l| l.empty? }

      ascii = labels.map { |l| label_to_ascii(l) }.join(".")
      if ascii.bytesize > MAX_HOST
        raise InvalidDomain, "hostname exceeds #{MAX_HOST} bytes"
      end

      ascii
    end

    def to_unicode(host)
      to_ascii(host).split(".").map { |l| label_to_unicode(l) }.join(".")
    end

    # Lowercase, NFC-normalise, and fold the various dot characters that users
    # paste in from documents and IMEs.
    def map(host)
      s = host.to_s.strip
      s = s.gsub(/。|．|｡/, ".") # 。．｡
      s = s.unicode_normalize(:nfc)
      s = s.downcase
      raise InvalidDomain, "hostname contains invisible characters" if s =~ INVISIBLE
      s
    end

    def label_to_ascii(label)
      raise InvalidDomain, "empty label" if label.empty?

      if label.bytes.all? { |b| b < 0x80 }
        ascii_label(label)
      else
        unicode_label(label)
      end
    end

    def label_to_unicode(label)
      return label unless label.start_with?("xn--")

      Punycode.decode(label[4..-1])
    rescue ArgumentError
      label
    end

    def ascii_label(label)
      unless label =~ /\A[a-z0-9-]+\z/
        raise InvalidDomain, "invalid character in label #{label.inspect}"
      end
      if label.bytesize > MAX_LABEL
        raise InvalidDomain, "label exceeds #{MAX_LABEL} bytes"
      end

      if label.start_with?("xn--")
        raw = label[4..-1]
        decoded = begin
          Punycode.decode(raw)
        rescue ArgumentError
          raise InvalidDomain, "invalid punycode label #{label.inspect}"
        end

        # An A-label must decode to something non-ASCII and re-encode to the
        # identical string; otherwise it is a non-canonical alias that could
        # be used to register the same name twice.
        if decoded.bytes.all? { |b| b < 0x80 } || Punycode.encode(decoded) != raw
          raise InvalidDomain, "non-canonical punycode label #{label.inspect}"
        end

        validate_unicode_label(decoded)
      else
        check_hyphens(label)
      end

      label
    end

    def unicode_label(label)
      validate_unicode_label(label)
      encoded = "xn--#{Punycode.encode(label)}"
      if encoded.bytesize > MAX_LABEL
        raise InvalidDomain, "label exceeds #{MAX_LABEL} bytes"
      end
      check_hyphens(encoded, contain: false)
      encoded
    end

    def validate_unicode_label(label)
      raise InvalidDomain, "empty label" if label.empty?
      check_hyphens(label)

      ok = label.codepoints.all? do |cp|
        next true if cp == 0x2D # hyphen
        next true if cp >= 0x30 && cp <= 0x39 # ASCII digits
        next true if cp >= 0x61 && cp <= 0x7A # ASCII lowercase (mapping downcased)
        next false if cp < 0x80

        ch = cp.chr(Encoding::UTF_8)
        # Letters, combining marks and decimal digits only. This rejects
        # symbols, emoji, spaces and format characters outright rather than
        # trying to enumerate every confusable.
        ch =~ /\A[\p{L}\p{M}\p{N}]\z/
      end
      raise InvalidDomain, "label contains disallowed characters" unless ok

      if label.codepoints.all? { |cp| cp >= 0x30 && cp <= 0x39 }
        raise InvalidDomain, "label is all digits"
      end
    end

    # UTS #46 CheckHyphens: no leading/trailing hyphen, and no "--" in
    # positions 3 and 4 (reserved for the xn-- tag).
    def check_hyphens(label, contain: true)
      if label.start_with?("-") || label.end_with?("-")
        raise InvalidDomain, "label must not start or end with a hyphen"
      end
      return unless contain
      return if label.start_with?("xn--")

      if label[2, 2] == "--"
        raise InvalidDomain, "label must not contain '--' in positions 3-4"
      end
    end

    def reserved_tld?(ascii_host)
      tld = ascii_host.split(".").last
      RESERVED_TLDS.include?(tld)
    end

    # Coarse mixed-script detection. Not a rejection: legitimate businesses do
    # use mixed-script names. It feeds the review flag, because a Latin/Cyrillic
    # mix is the classic homograph shape and a human should look at it.
    def mixed_script?(label)
      return false if label.bytes.all? { |b| b < 0x80 }

      scripts = %w[Latin Cyrillic Greek Armenian Hebrew Arabic Han Hiragana Katakana Hangul Thai Devanagari]
      present = scripts.select { |s| label =~ /\p{#{s}}/ }
      return false if present.size < 2

      # Han + Kana/Hangul is normal in Japanese/Korean names.
      return false if present.include?("Han") && (present - %w[Han Hiragana Katakana Hangul]).empty?

      true
    end
  end
end
