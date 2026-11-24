source "https://rubygems.org"

# Deliberately small. Everything security-sensitive (X.509, HKDF, AEAD,
# Punycode, DNS wire format) is implemented on the standard library so the
# verification and issuance paths stay auditable and do not depend on a native
# extension's version.
#
# ActiveRecord + SQLite are the only runtime dependencies; on the platform they
# come from the existing Rails app.
gem "activerecord", "~> 6.0"
gem "activesupport", "~> 6.0"
gem "sqlite3", "~> 1.4"

group :development, :test do
  gem "rake", "~> 12.3"
  gem "minitest", "~> 5.11"
end
