# Kite custom domains

A Ruby implementation of custom-domain binding and certificate issuance for a
multi-tenant site builder, rebuilt after an incident where a released domain
still carrying its old verification record was re-bound by an attacker and
issued a certificate.

The full write-up is in **[DESIGN.md](DESIGN.md)**. This file is the short
version and how to run it.

## The vulnerability, in one line

> A verification record proved *the domain*, not *the claim*. A record left in
> DNS by a previous owner was accepted as proof for anyone's new claim.

## The fix, in one line

> Every claim gets a fresh random token; a record only satisfies the claim it
> was issued for. Released domains are reclaimed under extra scrutiny instead
> of being free for the taking.

Concretely:

- **Per-claim tokens.** `kite-verify=<32 random bytes>`, unrelated to the
  hostname, never accepted as input, compared by digest. A leftover record
  carries a different token and fails the exact match.
- **Claim-scoped CNAME targets** derived from the same token, so the routing
  record is claimant-specific too.
- **Tombstones on release** (who, when, why) drive a reclaim policy: within 7
  days a *different* account must publish a fresh TXT token, the reclaim is
  queued for review, and the previous owner is notified and can dispute.
- **Issuance re-checks everything** — ownership, liveness, fresh DNS proof,
  review state, CAA, quotas — on every issue *and* every renewal. A stored
  `active` state is never enough.
- **Only authoritative absence detaches a domain.** Timeouts, SERVFAIL and
  resolver disagreement are inert, so nobody can detach a domain by breaking
  its resolution.
- **Hash-chained audit log** for after-the-fact investigation.

## Run it

Requires Ruby 2.6+ with the standard library. No bundler install needed for the
demo or tests; ActiveRecord and SQLite come from the platform's existing gems.

```sh
ruby -Ilib bin/demo      # narrated walkthrough of the attack and the fix
rake test                # 101 tests (5 network DNS tests are opt-in)
DOMAINS=300000 DUE=3000 ruby -Ilib bin/benchmark
```

`bin/kite` is a small CLI for manual operation:

```sh
KITE_DB=tmp/dev.sqlite3 KITE_SIMULATED=1 bin/kite claim --account 1 --host www.example.com
KITE_DB=tmp/dev.sqlite3 KITE_SIMULATED=1 bin/kite verify --claim 1
```

`KITE_SIMULATED=1` uses an in-memory DNS simulator; without it, real DNS is
queried.

## Library use

```ruby
require "domain_guard"

config = DomainGuard::Config.new(master_key: ENV["KITE_MASTER_KEY"])
platform = DomainGuard.boot!(config, database: "domains.sqlite3")

account = DomainGuard::Account.create!(name: "Acme")
result  = platform.domains.claim(account: account, host: "www.acme.com")
# => publish result.instructions[:cname] (or [:txt]) in DNS
platform.domains.verify!(result.claim)          # => :present once DNS is right

claim = DomainGuard::CustomDomain.find(result.claim.id)
cert  = platform.issuer.issue(account: account, claims: [claim])

platform.scheduler.tick                          # expiries, health checks, renewals
platform.audit.verify_chain!                     # => [true, nil]
```

## Test suite

| File | What it covers |
|---|---|
| `test/hijack_attack_test.rb` | **the reported incident**, plus its variants |
| `test/lifecycle_test.rb` | claim → verify → detach → release, delegation |
| `test/issuance_test.rb` | ownership, proof freshness, CAA, review gating, renewal |
| `test/scheduler_test.rb` | due-only sweeps, leases, at_risk/detach rules |
| `test/concurrency_test.rb` | unique index, tombstones, optimistic locking |
| `test/idna_test.rb` | IDNA/Punycode vectors, PSL rules, normalisation |
| `test/crypto_test.rb` | envelope encryption, tamper detection, audit chain |
| `test/dns_client_network_test.rb` | real-DNS behaviour (`KITE_NETWORK_TESTS=1`) |

## Configuration

All policy lives in `DomainGuard::Config` (see `lib/domain_guard/config.rb`):
token TTLs, reclaim cool-down, detach grace, renewal lead time, CAA
identifiers, resolver settings, key algorithm and quotas. The security posture
is therefore a single reviewable object rather than constants spread across the
code.
