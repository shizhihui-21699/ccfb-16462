require "domain_guard/errors"
require "domain_guard/crypto"
require "domain_guard/dns_client"
require "domain_guard/idna"
require "domain_guard/models"

module DomainGuard
  # Raw-SQL helpers that bind values properly (AR's execute/select_one bind
  # handling differs between versions, so sanitise explicitly).
  module SQL
    module_function

    def exec(sql, *binds)
      ActiveRecord::Base.connection.execute(sql_for(sql, binds))
    end

    def one(sql, *binds)
      ActiveRecord::Base.connection.select_one(sql_for(sql, binds))
    end

    def value(sql, *binds)
      ActiveRecord::Base.connection.select_value(sql_for(sql, binds))
    end

    def sql_for(sql, binds)
      ActiveRecord::Base.sanitize_sql_array([sql, *binds])
    end
  end

  # Fixed-window counters backed by the database, so limits are shared across
  # worker processes. Good enough for abuse control at this scale; a Redis
  # implementation would slot in behind the same interface.
  class RateLimiter
    # `clock` may return a Time or a numeric epoch; both are normalised here so
    # callers cannot accidentally pass the wrong shape.
    def initialize(clock: nil)
      @clock = clock || -> { Time.now.to_i }
    end

    def epoch_now
      t = @clock.call
      t.is_a?(Time) ? t.to_i : Integer(t)
    end

    # Raises RateLimited when the key has exceeded `limit` in the trailing
    # `window` seconds. Counts the attempt before raising so a blocked caller
    # cannot spin without consuming budget.
    def check!(key, limit:, window:)
      now = epoch_now
      window_start = now - (now % window)

      DB.transaction do
        row = SQL.one(
          "SELECT count FROM rate_limit_buckets WHERE bucket_key = ? AND window_start = ?",
          key, window_start
        )
        count = row ? row["count"].to_i : 0
        if count >= limit
          raise RateLimited.new(key, window_start + window - now)
        end

        SQL.exec(
          "INSERT INTO rate_limit_buckets (bucket_key, window_start, count) VALUES (?, ?, 1) " \
          "ON CONFLICT(bucket_key, window_start) DO UPDATE SET count = count + 1",
          key, window_start
        )
      end
      true
    end

    # Non-raising probe used by the issuance path to report remaining budget.
    def count(key, window:)
      now = epoch_now
      window_start = now - (now % window)
      row = SQL.one(
        "SELECT count FROM rate_limit_buckets WHERE bucket_key = ? AND window_start = ?",
        key, window_start
      )
      row ? row["count"].to_i : 0
    end

    def prune!(older_than:)
      SQL.exec("DELETE FROM rate_limit_buckets WHERE window_start < ?", older_than)
    end
  end

  # Cross-process mutual exclusion for one unit of work, with a TTL so a
  # crashed worker cannot wedge a host forever.
  class Lease
    def initialize(owner:, clock: nil)
      @owner = owner
      @clock = clock || -> { Time.now.to_i }
    end

    def epoch_now
      t = @clock.call
      t.is_a?(Time) ? t.to_i : Integer(t)
    end

    def acquire!(name, ttl:)
      now = epoch_now
      DB.transaction do
        SQL.exec("DELETE FROM leases WHERE name = ? AND expires_at < ?", name, now)
        begin
          SQL.exec(
            "INSERT INTO leases (name, owner, expires_at) VALUES (?, ?, ?)",
            name, @owner, now + ttl
          )
          true
        rescue ActiveRecord::StatementInvalid, ActiveRecord::RecordNotUnique
          row = SQL.one("SELECT owner FROM leases WHERE name = ?", name)
          row && row["owner"] == @owner
        end
      end
    end

    def release!(name)
      SQL.exec("DELETE FROM leases WHERE name = ? AND owner = ?", name, @owner)
    end
  end
end
