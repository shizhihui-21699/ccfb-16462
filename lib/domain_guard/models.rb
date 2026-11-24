require "json"
require "time"
require "domain_guard/db"

module DomainGuard
  # Timestamps are stored as ISO-8601 UTC text (SQLite has no native type) and
  # exposed as Time objects so that every comparison is timezone-safe.
  module TimeAttribute
    def time_attr(*names)
      names.each do |name|
        define_method(name) do
          raw = self[name]
          raw && (raw.is_a?(Time) ? raw : Time.parse(raw.to_s).utc)
        end

        define_method("#{name}=") do |value|
          self[name] = value.nil? ? nil : value.utc.iso8601(6)
        end
      end
    end

    def json_attr(*names)
      names.each do |name|
        define_method(name) do
          raw = self[name]
          return raw unless raw.is_a?(String)
          JSON.parse(raw)
        end

        define_method("#{name}=") do |value|
          self[name] = JSON.generate(value)
        end
      end
    end
  end

  class Base < ActiveRecord::Base
    self.abstract_class = true
    extend TimeAttribute

    def touch_times(now)
      self.created_at ||= now
      self.updated_at = now
    end
  end

  # A tenant. In a real deployment ids come from the existing users table;
  # this model exists so the domain layer is self-contained and testable.
  class Account < Base
    self.table_name = "accounts"
    time_attr :created_at, :updated_at

    has_many :custom_domains, class_name: "DomainGuard::CustomDomain"

    def self.create!(name:, email: nil, now: Time.now.utc)
      a = new(name: name, email: email)
      a.created_at = now
      a.updated_at = now
      a.save!
      a
    end
  end

  # A claim on a hostname by an account.
  #
  #   pending   - token issued, DNS proof not yet observed
  #   active    - proof observed and fresh
  #   at_risk   - was active, proof has disappeared (user migrated away, or
  #               the DNS record was changed); serving continues but no new
  #               certificates are issued, and the claim auto-releases after
  #               `detach_grace`
  #   released  - tombstone; the host is free for a new claim
  #   revoked   - removed by abuse/moderator action; tombstone
  class CustomDomain < Base
    self.table_name = "custom_domains"
    time_attr :token_issued_at, :token_expires_at, :verified_at, :last_checked_at,
              :next_check_at, :at_risk_since, :released_at, :created_at, :updated_at

    STATES = %w[pending active at_risk released revoked].freeze
    LIVE_STATES = %w[pending active at_risk].freeze
    PROOFS = %w[txt cname].freeze

    belongs_to :account, class_name: "DomainGuard::Account"

    validates :host, presence: true
    validates :state, inclusion: { in: STATES }
    validates :proof, inclusion: { in: PROOFS }

    scope :live, -> { where(state: LIVE_STATES) }
    scope :active, -> { where(state: "active") }
    scope :pending, -> { where(state: "pending") }
    scope :at_risk, -> { where(state: "at_risk") }
    scope :due_for_check, ->(now) { where(state: LIVE_STATES).where("next_check_at <= ?", now.utc.iso8601(6)) }
    scope :for_host, ->(host) { where(host: host) }

    def live?
      LIVE_STATES.include?(state)
    end

    def active?
      state == "active"
    end

    def pending?
      state == "pending"
    end

    def at_risk?
      state == "at_risk"
    end

    def released?
      state == "released"
    end

    def token_expired?(now = Time.now.utc)
      token_expires_at.nil? || token_expires_at <= now
    end

    def token_available?
      !token_blob.nil? && !token_blob.empty?
    end

    def review_required?
      review_required.to_i == 1
    end

    def flagged_for?(reason_prefix)
      review_required? && review_reason.to_s.start_with?(reason_prefix)
    end

    def risky_reclaim?
      risk_level == "risky_reclaim"
    end

    # A claim is only usable for issuance while the proof is both present and
    # recent. Serving is deliberately more permissive than issuance.
    def verifiable_for_issuance?(now, freshness)
      active? && verified_at && (now - verified_at) <= freshness
    end
  end

  # A zone-level proof: a TXT token at `_kite-verify.<registrable_domain>`
  # proves control of the whole registrable domain for one account. Subdomains
  # claimed by that account are then verified without a per-host record.
  #
  # This is the main friction reducer: an agency with 400 subdomains places one
  # record, and adding a subdomain is instant. It is scoped to one account, so
  # it never lets another tenant claim under the zone.
  class DomainDelegation < Base
    self.table_name = "domain_delegations"
    time_attr :verified_at, :last_checked_at, :next_check_at, :released_at,
              :created_at, :updated_at

    STATES = %w[pending active released].freeze

    belongs_to :account, class_name: "DomainGuard::Account"

    scope :live, -> { where(state: %w[pending active]) }
    scope :active, -> { where(state: "active") }

    def active?
      state == "active"
    end
  end

  class Certificate < Base
    self.table_name = "certificates"
    time_attr :not_before, :not_after, :issued_at, :renewal_due_at, :revoked_at,
              :created_at, :updated_at
    json_attr :names

    STATES = %w[issued revoked superseded].freeze

    has_many :certificate_domains, class_name: "DomainGuard::CertificateDomain",
                                   foreign_key: :certificate_id
    has_many :custom_domains, through: :certificate_domains

    scope :live, -> { where(state: "issued") }
    scope :due_for_renewal, ->(now) {
      where(state: "issued").where("renewal_due_at <= ?", now.utc.iso8601(6))
    }
    scope :expiring_before, ->(t) {
      where(state: "issued").where("not_after <= ?", t.utc.iso8601(6))
    }

    def covers?(host)
      names.include?(host)
    end
  end

  class CertificateDomain < Base
    self.table_name = "certificate_domains"

    belongs_to :certificate, class_name: "DomainGuard::Certificate"
    belongs_to :custom_domain, class_name: "DomainGuard::CustomDomain"
  end

  # An ACME-style order. The challenge state is stored per (name, type) so the
  # platform's own challenge responder can consult it.
  class CertOrder < Base
    self.table_name = "cert_orders"
    time_attr :expires_at, :finalized_at, :created_at, :updated_at
    json_attr :names, :challenges

    STATES = %w[pending ready processing valid invalid expired].freeze

    def challenge_for(name, type)
      (challenges[name.to_s] || []).find { |c| c["type"] == type }
    end
  end

  # Append-only audit log with a hash chain. Each entry commits to the previous
  # one, so removing or editing a historical row is detectable even by someone
  # with database access.
  class AuditEvent < Base
    self.table_name = "audit_events"
    time_attr :created_at
    json_attr :metadata

    GENESIS = "0" * 64
  end

  class Notification < Base
    self.table_name = "notifications"
    time_attr :read_at, :created_at
    json_attr :payload
  end
end
