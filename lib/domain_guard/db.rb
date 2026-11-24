require "active_record"
require "json"
require "domain_guard/errors"

module DomainGuard
  # Schema + connection management.
  #
  # The tables are shaped for a platform with hundreds of thousands of custom
  # domains:
  #
  #   * One live claim per host, enforced by a *partial* unique index so that
  #     released claims can be kept as tombstones (needed for cool-downs,
  #     previous-owner notification and disputes) without blocking a re-bind.
  #   * Every hot scheduler query is covered by an index
  #     (state + next check / next renewal), so daily sweeps never scan.
  #   * Claims are immutable in identity (host) and mutable only in state, with
  #     optimistic locking guarding concurrent transitions.
  module DB
    SCHEMA = <<~SQL
      CREATE TABLE IF NOT EXISTS accounts (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        email         TEXT,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS custom_domains (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id          INTEGER NOT NULL REFERENCES accounts(id),
        host                TEXT NOT NULL,
        registrable_domain  TEXT NOT NULL,
        site_id             TEXT,
        state               TEXT NOT NULL,
        proof               TEXT NOT NULL,
        token_blob          TEXT,
        token_digest        TEXT NOT NULL,
        token_issued_at     TEXT,
        token_expires_at    TEXT,
        verified_at         TEXT,
        verified_via        TEXT,
        last_checked_at     TEXT,
        next_check_at       TEXT,
        check_failures      INTEGER NOT NULL DEFAULT 0,
        at_risk_since       TEXT,
        released_at         TEXT,
        release_reason      TEXT,
        risk_level          TEXT NOT NULL DEFAULT 'normal',
        review_required     INTEGER NOT NULL DEFAULT 0,
        review_reason       TEXT,
        delegation_id       INTEGER,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL,
        lock_version        INTEGER NOT NULL DEFAULT 0
      );

      -- At most one *live* claim per host. Released/revoked rows are tombstones
      -- and may coexist with a fresh claim.
      CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_live_host
        ON custom_domains(host) WHERE state IN ('pending','active','at_risk');

      CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_token
        ON custom_domains(token_digest);

      CREATE INDEX IF NOT EXISTS idx_domains_account_state
        ON custom_domains(account_id, state);

      CREATE INDEX IF NOT EXISTS idx_domains_registrable
        ON custom_domains(registrable_domain, state);

      CREATE INDEX IF NOT EXISTS idx_domains_next_check
        ON custom_domains(next_check_at) WHERE state IN ('pending','active','at_risk');

      CREATE INDEX IF NOT EXISTS idx_domains_released
        ON custom_domains(host, released_at);

      CREATE TABLE IF NOT EXISTS domain_delegations (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id          INTEGER NOT NULL REFERENCES accounts(id),
        registrable_domain  TEXT NOT NULL,
        state               TEXT NOT NULL,
        token_blob          TEXT NOT NULL,
        token_digest        TEXT NOT NULL,
        verified_at         TEXT,
        last_checked_at     TEXT,
        next_check_at       TEXT,
        released_at         TEXT,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL,
        lock_version        INTEGER NOT NULL DEFAULT 0
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_delegations_live
        ON domain_delegations(registrable_domain) WHERE state IN ('pending','active');

      CREATE UNIQUE INDEX IF NOT EXISTS idx_delegations_token
        ON domain_delegations(token_digest);

      CREATE TABLE IF NOT EXISTS certificates (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id      INTEGER NOT NULL REFERENCES accounts(id),
        names           TEXT NOT NULL,
        serial          TEXT NOT NULL,
        not_before      TEXT NOT NULL,
        not_after       TEXT NOT NULL,
        state           TEXT NOT NULL,
        key_blob        TEXT NOT NULL,
        cert_pem        TEXT NOT NULL,
        chain_pem       TEXT,
        issued_at       TEXT NOT NULL,
        renewal_due_at  TEXT NOT NULL,
        revoked_at      TEXT,
        revoke_reason   TEXT,
        order_id        INTEGER,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_serial ON certificates(serial);
      CREATE INDEX IF NOT EXISTS idx_certs_renewal
        ON certificates(state, renewal_due_at);
      CREATE INDEX IF NOT EXISTS idx_certs_account ON certificates(account_id, state);

      CREATE TABLE IF NOT EXISTS certificate_domains (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        certificate_id    INTEGER NOT NULL REFERENCES certificates(id),
        custom_domain_id  INTEGER NOT NULL REFERENCES custom_domains(id),
        name              TEXT NOT NULL
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_domains_pair
        ON certificate_domains(certificate_id, custom_domain_id);
      CREATE INDEX IF NOT EXISTS idx_cert_domains_domain
        ON certificate_domains(custom_domain_id);
      CREATE INDEX IF NOT EXISTS idx_cert_domains_name ON certificate_domains(name);

      CREATE TABLE IF NOT EXISTS cert_orders (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id    INTEGER NOT NULL REFERENCES accounts(id),
        state         TEXT NOT NULL,
        names         TEXT NOT NULL,
        challenges    TEXT NOT NULL,
        error         TEXT,
        expires_at    TEXT NOT NULL,
        finalized_at  TEXT,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_orders_state ON cert_orders(state, expires_at);
      CREATE INDEX IF NOT EXISTS idx_orders_account ON cert_orders(account_id, created_at);

      CREATE TABLE IF NOT EXISTS audit_events (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_type    TEXT,
        actor_id      INTEGER,
        action        TEXT NOT NULL,
        subject_type  TEXT,
        subject_id    INTEGER,
        host          TEXT,
        metadata      TEXT NOT NULL DEFAULT '{}',
        prev_hash     TEXT NOT NULL,
        entry_hash    TEXT NOT NULL,
        created_at    TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_audit_host ON audit_events(host, created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_events(subject_type, subject_id);

      CREATE TABLE IF NOT EXISTS rate_limit_buckets (
        bucket_key    TEXT NOT NULL,
        window_start  INTEGER NOT NULL,
        count         INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_key, window_start)
      );

      CREATE TABLE IF NOT EXISTS leases (
        name          TEXT PRIMARY KEY,
        owner         TEXT NOT NULL,
        expires_at    INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id    INTEGER NOT NULL REFERENCES accounts(id),
        kind          TEXT NOT NULL,
        host          TEXT,
        payload       TEXT NOT NULL DEFAULT '{}',
        read_at       TEXT,
        created_at    TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_notifications_account
        ON notifications(account_id, read_at);
    SQL

    class << self
      attr_accessor :connection_config

      def connect!(database: ":memory:", logger: nil)
        ActiveRecord::Base.establish_connection(
          adapter: "sqlite3",
          database: database,
          timeout: 15_000,
          pool: 10
        )
        ActiveRecord::Base.logger = logger
        self.connection_config = database
        ActiveRecord::Base.connection.execute("PRAGMA foreign_keys = ON")
        # Multiple worker processes touch these tables; wait rather than fail.
        ActiveRecord::Base.connection.execute("PRAGMA busy_timeout = 15000")
        ActiveRecord::Base.connection.execute("PRAGMA journal_mode = WAL") unless database == ":memory:"
        migrate!
      end

      def migrate!
        ActiveRecord::Base.connection.execute("PRAGMA foreign_keys = OFF")
        SCHEMA.split(";").map(&:strip).reject(&:empty?).each do |stmt|
          ActiveRecord::Base.connection.execute(stmt)
        end
        ActiveRecord::Base.connection.execute("PRAGMA foreign_keys = ON")
      end

      def transaction(&block)
        ActiveRecord::Base.transaction(requires_new: false, &block)
      end
    end
  end
end
