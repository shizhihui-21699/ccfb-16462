require "domain_guard/dns_client"

module DomainGuard
  # In-memory DNS simulator used by the demo and the test suite.
  #
  # Production uses DnsClient over the network; this exists so the whole
  # lifecycle can run deterministically and offline, and so failure modes that
  # are hard to provoke against real DNS (SERVFAIL, REFUSED, timeout) can be
  # exercised on demand.
  #
  # It exposes the same surface as DnsClient (txt/cname/a/caa returning a
  # DnsClient::Outcome).
  class SimulatedDns
    def initialize
      @txt = Hash.new { |h, k| h[k] = [] }
      @cname = {}
      @a = Hash.new { |h, k| h[k] = [] }
      @caa = Hash.new { |h, k| h[k] = [] }
      @overrides = {}
      @queries = []
    end

    def add_txt(name, value, ttl: 300)
      @txt[normalize(name)] << [value, ttl]
      self
    end

    def remove_txt(name, value = nil)
      key = normalize(name)
      if value
        @txt[key].reject! { |v, _| v == value }
      else
        @txt.delete(key)
      end
      self
    end

    def set_cname(name, target, ttl: 300)
      @cname[normalize(name)] = [target, ttl]
      self
    end

    def remove_cname(name)
      @cname.delete(normalize(name))
      self
    end

    def set_caa(name, records)
      @caa[normalize(name)] = records
      self
    end

    # Force a specific outcome for a name/type pair.
    #   override("a.com", :txt, :inconclusive, detail: "SERVFAIL")
    def override(name, type, state, detail: nil)
      @overrides[[normalize(name), type]] = [state, detail]
      self
    end

    def clear_overrides
      @overrides.clear
      self
    end

    def queries
      @queries.dup
    end

    def txt(name)
      forced = @overrides[[normalize(name), :txt]]
      return forced_outcome(forced) if forced

      @queries << [:txt, normalize(name)]
      key = normalize(name)
      if !@txt[key].empty?
        records = @txt[key].map { |val, ttl| DnsClient::Record.new(type: :txt, value: val, ttl: ttl) }
        DnsClient::Outcome.new(status: :records, records: records,
                               ttl: records.map(&:ttl).min, rcode: 0)
      else
        DnsClient::Outcome.new(status: :absent, records: [], rcode: 3)
      end
    end

    def cname(name)
      forced = @overrides[[normalize(name), :cname]]
      return forced_outcome(forced) if forced

      @queries << [:cname, normalize(name)]
      key = normalize(name)
      if @cname[key]
        target, ttl = @cname[key]
        DnsClient::Outcome.new(
          status: :records, ttl: ttl, rcode: 0,
          records: [DnsClient::Record.new(type: :cname, value: target, ttl: ttl)]
        )
      else
        DnsClient::Outcome.new(status: :absent, records: [], rcode: 0)
      end
    end

    def a(name)
      forced = @overrides[[normalize(name), :a]]
      return forced_outcome(forced) if forced

      @queries << [:a, normalize(name)]
      key = normalize(name)
      if !@a[key].empty?
        records = @a[key].map { |ip, ttl| DnsClient::Record.new(type: :a, value: ip, ttl: ttl) }
        DnsClient::Outcome.new(status: :records, records: records,
                               ttl: records.map(&:ttl).min, rcode: 0)
      else
        DnsClient::Outcome.new(status: :absent, records: [], rcode: 3)
      end
    end

    def caa(name)
      forced = @overrides[[normalize(name), :caa]]
      return forced_outcome(forced) if forced

      @queries << [:caa, normalize(name)]
      records = @caa[normalize(name)]
      if records.empty?
        DnsClient::Outcome.new(status: :absent, records: [], rcode: 0)
      else
        mapped = records.map { |rec| DnsClient::Record.new(type: :caa, value: rec, ttl: 300) }
        DnsClient::Outcome.new(status: :records, records: mapped, ttl: 300, rcode: 0)
      end
    end

    private

    def forced_outcome(forced)
      state, detail = forced
      if state == :absent
        DnsClient::Outcome.new(status: :absent, records: [], rcode: 3, detail: detail)
      else
        DnsClient::Outcome.new(status: :inconclusive, records: [],
                               detail: detail || state.to_s)
      end
    end

    def normalize(name)
      name.to_s.downcase.sub(/\.\z/, "")
    end
  end
end
