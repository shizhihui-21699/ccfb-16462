module DomainGuard
  # RFC 3492 Punycode. Implemented locally because the runtime ships Ruby 2.6
  # without an IDNA codec, and because the binding path must not depend on a
  # native extension whose version we cannot audit.
  module Punycode
    BASE = 36
    TMIN = 1
    TMAX = 26
    SKEW = 38
    DAMP = 700
    INITIAL_BIAS = 72
    INITIAL_N = 128
    DELIMITER = "-"

    module_function

    def adapt(delta, numpoints, first_time)
      delta = first_time ? delta / DAMP : delta / 2
      delta += delta / numpoints
      k = 0
      while delta > ((BASE - TMIN) * TMAX) / 2
        delta /= (BASE - TMIN)
        k += BASE
      end
      k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    end

    def encode_digit(d)
      d < 26 ? (d + 97).chr : (d - 26 + 48).chr
    end

    def decode_digit(char)
      o = char.ord
      if o >= 48 && o <= 57
        o - 22
      elsif o >= 65 && o <= 90
        o - 65
      elsif o >= 97 && o <= 122
        o - 97
      else
        BASE
      end
    end

    def encode(input)
      codepoints = input.codepoints
      n = INITIAL_N
      delta = 0
      bias = INITIAL_BIAS

      output = codepoints.select { |c| c < 0x80 }.map { |c| c.chr(Encoding::UTF_8) }.join
      basic = output.length
      handled = basic
      output << DELIMITER if basic > 0

      while handled < codepoints.length
        m = codepoints.select { |c| c >= n }.min
        raise ArgumentError, "invalid codepoint" if m.nil?

        delta += (m - n) * (handled + 1)
        n = m

        codepoints.each do |c|
          if c < n
            delta += 1
          elsif c == n
            q = delta
            k = BASE
            loop do
              t = if k <= bias
                    TMIN
                  elsif k >= bias + TMAX
                    TMAX
                  else
                    k - bias
                  end
              break if q < t

              output << encode_digit(t + ((q - t) % (BASE - t)))
              q = (q - t) / (BASE - t)
              k += BASE
            end
            output << encode_digit(q)
            bias = adapt(delta, handled + 1, handled == basic)
            delta = 0
            handled += 1
          end
        end

        delta += 1
        n += 1
      end

      output
    end

    def decode(input)
      input = input.to_s
      n = INITIAL_N
      i = 0
      bias = INITIAL_BIAS
      output = []

      if (delim = input.rindex(DELIMITER))
        prefix = input[0...delim]
        prefix.each_byte { |b| output << b.chr(Encoding::UTF_8) }
        pos = delim + 1
      else
        pos = 0
      end

      while pos < input.length
        old_i = i
        w = 1
        k = BASE
        loop do
          raise ArgumentError, "truncated punycode" if pos >= input.length

          digit = decode_digit(input[pos])
          raise ArgumentError, "invalid punycode digit" if digit >= BASE

          pos += 1
          i += digit * w
          t = if k <= bias
                TMIN
              elsif k >= bias + TMAX
                TMAX
              else
                k - bias
              end
          break if digit < t

          w *= (BASE - t)
          k += BASE
        end

        length = output.length + 1
        bias = adapt(i - old_i, length, old_i == 0)
        n += i / length
        raise ArgumentError, "invalid codepoint" if n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF)

        i %= length
        output.insert(i, [n].pack("U"))
        i += 1
      end

      output.join
    end
  end
end
