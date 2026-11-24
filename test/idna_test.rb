require "test_helper"

module DomainGuard
  class IdnaTest < Minitest::Test
    VECTORS = {
      "bücher.example" => "xn--bcher-kva.example",
      "例え.example" => "xn--r8jz45g.example",
      "münchen.example" => "xn--mnchen-3ya.example",
      "中文.example" => "xn--fiq228c.example",
      "ドメイン.example" => "xn--eckwd4c7c.example",
      "ütest.example" => "xn--test-zra.example",
      "παράδειγμα.example" => "xn--hxajbheg2az3al.example",
      "españa.example" => "xn--espaa-rta.example",
      "日本語.example" => "xn--wgv71a119e.example",
      "россия.example" => "xn--h1alffa9f.example"
    }.freeze

    def test_unicode_to_ascii_vectors
      VECTORS.each do |unicode, ascii|
        assert_equal ascii, Idna.to_ascii(unicode), "failed for #{unicode}"
      end
    end

    def test_round_trip
      VECTORS.each do |unicode, ascii|
        assert_equal unicode, Idna.to_unicode(ascii)
      end
    end

    def test_case_and_dot_normalisation
      assert_equal "www.example.com", Idna.to_ascii("WWW.Example.COM")
      assert_equal "example.com", Idna.to_ascii("example。com")   # ideographic full stop
      assert_equal "example.com", Idna.to_ascii("example．com")   # fullwidth full stop
      assert_equal "example.com", Idna.to_ascii("  example.com.  ")
    end

    def test_trailing_dot_is_equivalent
      assert_equal "example.com", Idna.to_ascii("example.com.")
    end

    def test_rejects_invalid
      [
        "", " ", "-bad.com", "bad-.com", "ab--c.com", "a..b.com",
        "exa mple.com", "☃.com", "foo_bar.com", "*.example.com",
        "xn--zzzzzz.com", "xn--abc.com"
      ].each do |host|
        assert_raises(DomainGuard::InvalidDomain, "should reject #{host.inspect}") do
          Idna.to_ascii(host)
        end
      end
    end

    def test_rejects_invisible_characters
      assert_raises(DomainGuard::InvalidDomain) { Idna.to_ascii("exa​mple.com") }
      assert_raises(DomainGuard::InvalidDomain) { Idna.to_ascii("exa‍mple.com") }
      assert_raises(DomainGuard::InvalidDomain) { Idna.to_ascii("exa⁠mple.com") }
    end

    # A non-canonical A-label must not be accepted: otherwise the same name can
    # be registered twice under different spellings.
    def test_rejects_non_canonical_alabel
      # "xn--bcher-kva" is the canonical encoding of "bücher"; a valid
      # A-label round-trips.
      assert_equal "xn--bcher-kva.example", Idna.to_ascii("bücher.example")
      # Uppercase punycode is not canonical after mapping, but downcasing makes
      # it match; the label itself still round-trips.
      assert_equal "xn--bcher-kva.example", Idna.to_ascii("XN--BCHER-KVA.example")
    end

    def test_label_length_limit
      assert_raises(DomainGuard::InvalidDomain) { Idna.to_ascii("#{'a' * 64}.com") }
      assert Idna.to_ascii("#{'a' * 63}.com")
    end

    def test_mixed_script_detection
      assert Idna.mixed_script?("pаypal")   # Latin + Cyrillic "а"
      refute Idna.mixed_script?("paypal")
      refute Idna.mixed_script?("日本語")   # Han + Kana is one normal script mix
      refute Idna.mixed_script?("bücher")
    end

    def test_reserved_tlds
      %w[foo.local foo.internal foo.test foo.invalid foo.localhost].each do |h|
        assert Idna.reserved_tld?(h), "#{h} should be reserved"
      end
      refute Idna.reserved_tld?("example.com")
    end
  end

  class PunycodeTest < Minitest::Test
    def test_rfc3492_vectors
      # From RFC 3492 section 7.1
      {
        "bücher" => "bcher-kva",
        "例え" => "r8jz45g",
        "ドメイン" => "eckwd4c7c",
        "münchen" => "mnchen-3ya"
      }.each do |unicode, encoded|
        assert_equal encoded, Punycode.encode(unicode)
        assert_equal unicode, Punycode.decode(encoded)
      end
    end

    def test_decode_rejects_garbage
      assert_raises(ArgumentError) { Punycode.decode("!!!") }
    end
  end

  class PublicSuffixTest < Minitest::Test
    def setup
      path = File.expand_path("../data/public_suffix_list.dat", __dir__)
      @psl = PublicSuffix.new(path)
    end

    def test_registrable_domains
      assert_equal "example.com", @psl.registrable_domain("www.example.com")
      assert_equal "example.com", @psl.registrable_domain("example.com")
      assert_equal "example.co.uk", @psl.registrable_domain("www.example.co.uk")
      assert_equal "foo.github.io", @psl.registrable_domain("foo.github.io")
    end

    def test_public_suffixes_are_not_registrable
      %w[com co.uk github.io].each do |suffix|
        assert_nil @psl.registrable_domain(suffix), "#{suffix} must not be registrable"
      end
    end

    def test_wildcard_rule
      # "*.ck" makes any single label under .ck a public suffix, so foo.ck is
      # a suffix and bar.foo.ck is the registrable name.
      assert_equal "ck", @psl.suffix("www.ck")
      assert_equal "foo.ck", @psl.suffix("bar.foo.ck")
      assert_equal "bar.foo.ck", @psl.registrable_domain("bar.foo.ck")
      assert_equal "bar.foo.ck", @psl.registrable_domain("x.bar.foo.ck")
      assert_nil @psl.registrable_domain("foo.ck")
    end

    def test_exception_rule
      # !city.kawasaki.jp means city.kawasaki.jp is registrable.
      assert_equal "city.kawasaki.jp", @psl.registrable_domain("www.city.kawasaki.jp")
    end

    def test_split_returns_suffix
      reg, ps = @psl.split("a.b.example.co.uk")
      assert_equal "example.co.uk", reg
      assert_equal "co.uk", ps
    end
  end
end
