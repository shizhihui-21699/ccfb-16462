require "resolv"
require "socket"
require "securerandom"
require "domain_guard/errors"
require "domain_guard/crypto"

module DomainGuard
  # Minimal stub resolver over UDP with explicit outcome classification.
  #
  # Why not Resolv#getresources: it collapses NXDOMAIN, NODATA, SERVFAIL and
  # timeouts into "empty list". For this feature that distinction is the whole
  # security argument, because "the record is definitely gone" (detach the
  # domain) and "I could not find out" (do nothing) must never be conflated.
  #
  # Outcome is one of:
  #   :records      - at least one matching record was returned
  #   :absent       - an authoritative response says the record does not exist
  #   :inconclusive - timeout, SERVFAIL, REFUSED, malformed, or truncation
  #
  # Only :absent may drive a state change. :inconclusive is always retried.
  class DnsClient
    Outcome = Struct.new(:status, :records, :ttl, :rcode, :detail, keyword_init: true) do
      def records?; status == :records; end
      def absent?; status == :absent; end
      def inconclusive?; status == :inconclusive; end
    end

    Record = Struct.new(:type, :value, :ttl, keyword_init: true)

    CAA_TYPE = 257

    def initialize(nameservers:, timeout: 3, attempts: 2, clock: nil)
      @nameservers = nameservers
      @timeout = timeout
      @attempts = attempts
      @clock = clock || -> { Time.now.utc }
    end

    def txt(name)
      query(name, Resolv::DNS::Resource::IN::TXT) do |res|
        res.strings.join("")
      end
    end

    def cname(name)
      query(name, Resolv::DNS::Resource::IN::CNAME) do |res|
        res.name.to_s.sub(/\.\z/, "").downcase
      end
    end

    def caa(name)
      query(name, caa_class) do |res|
        data = res.data
        next nil if data.nil? || data.bytesize < 2

        flags = data.getbyte(0)
        tag_len = data.getbyte(1)
        next nil if data.bytesize < 2 + tag_len

        { flags: flags, tag: data.byteslice(2, tag_len).downcase,
          value: data.byteslice(2 + tag_len, data.bytesize - 2 - tag_len) }
      end
    end

    def a(name)
      query(name, Resolv::DNS::Resource::IN::A) { |res| res.address.to_s }
    end

    private

    def caa_class
      @caa_class ||= begin
        existing = Resolv::DNS::Resource::ClassHash[[CAA_TYPE, 1]]
        existing || begin
          klass = Resolv::DNS::Resource::Generic.create(CAA_TYPE, 1)
          Resolv::DNS::Resource::ClassHash[[CAA_TYPE, 1]] = klass
          klass
        end
      end
    end

    # One logical lookup: try each attempt, each attempt asking one nameserver.
    # A single definitive :absent wins immediately; otherwise a successful
    # :records wins; otherwise we return the worst outcome we saw.
    # One logical lookup, with voting across nameservers and attempts.
    #
    # Presence is easy: any resolver returning the record wins.
    #
    # Absence is what drives *detaching a live site*, so it needs a quorum. A
    # record is reported :absent only when every resolver that produced a
    # definitive response agrees, and at least one did. A split result (one
    # resolver says absent, another times out) is :inconclusive — this is what
    # prevents a single broken or lying resolver from detaching a domain.
    def query(name, type_class, &block)
      last = nil
      @attempts.times do |attempt|
        results = @nameservers.map { |ns| exchange(name, type_class, ns, &block) }

        present = results.find(&:records?)
        return present if present

        absent = results.count(&:absent?)
        inconclusive = results.count(&:inconclusive?)
        if absent == results.length
          return results.first
        end
        if absent.positive?
          last = Outcome.new(status: :inconclusive, records: [],
                             detail: "resolvers disagree (#{absent} absent, #{inconclusive} inconclusive)")
        else
          last = results.find(&:inconclusive?) || last
        end
        sleep_backoff(attempt)
      end
      last || Outcome.new(status: :inconclusive, records: [], detail: "no nameserver answered")
    end

    def exchange(name, type_class, nameserver, &block)
      attempt_query(name, type_class, nameserver, false, &block)
    rescue Resolv::DNS::DecodeError, Resolv::DNS::EncodeError => e
      Outcome.new(status: :inconclusive, records: [], detail: "malformed response: #{e.class}")
    rescue StandardError => e
      Outcome.new(status: :inconclusive, records: [], detail: "#{e.class}: #{e.message}")
    end

    def attempt_query(name, type_class, nameserver, tcp, &block)
      msg = Resolv::DNS::Message.new(SecureRandom.random_number(65_535))
      msg.rd = 1
      msg.add_question(name, type_class)
      payload = msg.encode

      response = if tcp
                   tcp_exchange(nameserver, payload)
                 else
                   udp_exchange(nameserver, payload)
                 end
      return Outcome.new(status: :inconclusive, records: [], detail: "timeout") if response.nil?

      # TC bit: the answer did not fit in UDP. Must retry over TCP, never treat
      # a truncated response as "record absent".
      if response.tc.to_i == 1 && !tcp
        return attempt_query(name, type_class, nameserver, true, &block)
      end

      classify(response, type_class, &block)
    end

    def classify(response, type_class, &block)
      wanted = [type_class].flatten

      case response.rcode
      when Resolv::DNS::RCode::NoError
        records = []
        cname_match = false
        response.each_answer do |_name, ttl, res|
          if wanted.any? { |k| res.is_a?(k) }
            value = yield(res)
            records << Record.new(type: res.class, value: value, ttl: ttl) unless value.nil?
          elsif res.is_a?(Resolv::DNS::Resource::IN::CNAME) && wanted.include?(Resolv::DNS::Resource::IN::CNAME)
            cname_match = true
          end
        end

        if records.empty?
          # NOERROR with no answer of the requested type. Distinguish the two
          # cases that matter for us:
          #  - CNAME present pointing elsewhere: the record is not at this name.
          #  - an SOA in the authority section: authoritative "no such record"
          #    (NODATA / minimal-NXDOMAIN). Either way there is no record here.
          rrsig_ok = response.answer.any? { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::CNAME) }
          soa = response.authority.any? { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::SOA) }
          if soa
            Outcome.new(status: :absent, records: [], ttl: nil, rcode: response.rcode)
          elsif rrsig_ok
            # CNAME present but no record of the wanted type: the chain ends
            # elsewhere, so the record is not at this name. Only authoritative
            # for a CNAME lookup when nothing matched above.
            Outcome.new(status: :absent, records: [], ttl: nil, rcode: response.rcode)
          else
            # Empty answer, no SOA: a lame/recursive-empty answer. Not proof.
            Outcome.new(status: :inconclusive, records: [], rcode: response.rcode,
                        detail: "empty answer without authority")
          end
        else
          ttl = records.map { |r| r.ttl }.compact.min
          Outcome.new(status: :records, records: records, ttl: ttl, rcode: response.rcode)
        end
      when Resolv::DNS::RCode::NXDomain
        Outcome.new(status: :absent, records: [], rcode: response.rcode)
      else
        Outcome.new(status: :inconclusive, records: [], rcode: response.rcode,
                    detail: "rcode=#{response.rcode}")
      end
    end

    def udp_exchange(nameserver, payload)
      socket = UDPSocket.new
      socket.connect(nameserver, 53)
      socket.send(payload, 0)
      ready = IO.select([socket], nil, nil, @timeout)
      return nil unless ready

      raw = socket.recv(65_535)
      Resolv::DNS::Message.decode(raw)
    ensure
      socket.close if socket && !socket.closed?
    end

    def tcp_exchange(nameserver, payload)
      socket = Socket.tcp(nameserver, 53, connect_timeout: @timeout)
      socket.write([payload.bytesize].pack("n") + payload)
      len = socket.read(2)
      return nil if len.nil? || len.bytesize < 2

      body = socket.read(len.unpack1("n"))
      return nil if body.nil?

      Resolv::DNS::Message.decode(body)
    rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, IOError
      nil
    ensure
      socket.close if socket && !socket.closed?
    end

    def sleep_backoff(attempt)
      sleep([0.05 * (2**attempt), 0.4].min)
    end
  end
end
