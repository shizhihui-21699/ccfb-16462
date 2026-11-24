require "set"
require "domain_guard/idna"

module DomainGuard
  # Public Suffix List evaluation (https://publicsuffix.org/list/).
  #
  # The binding path uses this for two things, both security-relevant:
  #
  #   1. Reject claims on a public suffix ("co.uk", "github.io"), which are not
  #      registrable and whose "owner" is the registry or a hosting provider.
  #   2. Find the registrable domain ("example.co.uk") so that a domain which
  #      has just changed hands inside the same registrable name can be treated
  #      as related for risk purposes.
  #
  # Rules are stored in their Unicode form in the list and converted to ASCII so
  # that lookups use exactly the same canonical form as claims.
  class PublicSuffix
    DEFAULT_RULE = "*"

    attr_reader :rule_count

    def initialize(path, include_private: true)
      @exact = Set.new
      @wildcard = Set.new
      @exception = Set.new
      load_list(path, include_private: include_private)
    end

    # Returns the public suffix for an ASCII hostname. Follows the PSL algorithm
    # (https://publicsuffix.org/list/):
    #
    #   1. Find every rule that matches; a rule matches when its labels are a
    #      suffix of the host's labels, with "*" matching exactly one label.
    #   2. The prevailing rule is the one with the most labels.
    #   3. If it is an exception rule ("!..."), drop its leftmost label and use
    #      the rest as the public suffix.
    #   4. If no rule matches, "*" prevails: the TLD is the suffix.
    def suffix(ascii_host)
      labels = ascii_host.split(".")
      best = nil # [label_count, kind, rule_labels]

      (0...labels.length).each do |i|
        candidate = labels[i..-1]
        key = candidate.join(".")

        if @exception.include?(key)
          best = consider(best, [candidate.length, :exception, candidate])
        end
        if @exact.include?(key)
          best = consider(best, [candidate.length, :exact, candidate])
        end
        # Wildcard "*.parent": the matched suffix is this label plus `parent`.
        parent = (i + 1 < labels.length) ? labels[(i + 1)..-1].join(".") : nil
        if parent && @wildcard.include?(parent)
          best = consider(best, [candidate.length, :wildcard, candidate])
        end
      end

      unless best
        # No rule matched: default "*" means the last label is the suffix.
        return labels.last
      end

      count, kind, rule_labels = best
      if kind == :exception
        rule_labels[1..-1].join(".")
      else
        rule_labels.join(".")
      end
    end

    # Returns [registrable_domain, public_suffix]. registrable_domain is nil
    # when the host is a public suffix or a bare TLD.
    def split(ascii_host)
      labels = ascii_host.split(".")
      ps = suffix(ascii_host)
      ps_labels = ps.split(".")
      if labels.length <= ps_labels.length
        return [nil, ps]
      end
      [labels[-(ps_labels.length + 1)..-1].join("."), ps]
    end

    def registrable_domain(ascii_host)
      split(ascii_host).first
    end

    def public_suffix?(ascii_host)
      registrable_domain(ascii_host).nil?
    end

    private

    def consider(best, candidate)
      return best if best && best[0] >= candidate[0]
      candidate
    end

    def load_list(path, include_private:)
      raise ArgumentError, "public suffix list not found: #{path}" unless File.exist?(path)

      in_private = false
      File.foreach(path, encoding: "UTF-8") do |line|
        line = line.strip
        next if line.empty?

        if line.start_with?("//")
          in_private = true if line =~ /===BEGIN PRIVATE DOMAINS===/
          in_private = false if line =~ /===END PRIVATE DOMAINS===/
          next
        end
        next if in_private && !include_private

        rule = normalize_rule(line)
        next if rule.nil?

        if rule.start_with?("!")
          @exception << rule[1..-1]
        elsif rule.start_with?("*.")
          @wildcard << rule[2..-1]
        else
          @exact << rule
        end
      end
      @rule_count = @exact.size + @wildcard.size + @exception.size
    end

    def normalize_rule(rule)
      # Rules may be Unicode; claims are ASCII, so store ASCII.
      Idna.to_ascii(rule.sub(/\A(!|\*\.)/, ""))
      prefix = rule[/\A!|\A\*\./] || ""
      body = rule.sub(/\A(!|\*\.)/, "")
      ascii = begin
        Idna.to_ascii(body)
      rescue DomainGuard::InvalidDomain
        # A handful of list entries are not valid hostnames under our strict
        # mapping (e.g. "*.compute.amazonaws.com.cn" is fine, but some entries
        # contain underscores or are otherwise degenerate). Skip them: they can
        # never match a canonical claim anyway.
        return nil
      end
      "#{prefix}#{ascii}"
    end
  end
end
