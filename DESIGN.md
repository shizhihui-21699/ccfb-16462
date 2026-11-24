# Custom domains and certificate issuance — ownership verification redesign

## The incident

A user pointed their domain at the platform, showed the verification record the
platform asked for, got a certificate, and was served correctly. Later they
migrated to another provider: they removed the custom domain **on the platform**
but did not delete the **DNS record** that had been used to prove ownership.

Someone else noticed the dangling record, added the same domain on the platform,
and got a certificate — so the attacker's site was served at a domain the victim
still controlled in DNS and still believed was theirs.

Two separate weaknesses let that happen:

1. **The proof was treated as a property of the domain, not of the claim.**
   Any verification record ever published for a hostname was implicitly good
   for any future claim on that hostname. A record left in DNS is durable,
   public, and outlives the account that created it.
2. **Unbinding did not gate rebinding.** Releasing a domain left no trace that
   anyone could act on, so a new claim after release looked exactly like a
   first-time claim.

## The fix, in one sentence

> A DNS record only ever proves control **to the claim it was issued for**, and a
> hostname that recently changed hands is **reclaimed under extra scrutiny**
> rather than being free for the taking.

Everything below follows from those two rules.

## Design

### 1. Per-claim, random, unguessable tokens

Every claim gets its own token:

```
kite-verify=<43 chars of base64url(32 random bytes)>
```

- The token is **not derived from the hostname**. Two claims on the same host
  have unrelated tokens, so a record published by the first owner can never
  satisfy the second claim.
- The token is **never accepted as input**. Verification reads the token the
  platform stored (encrypted) for *that claim row*, looks it up in DNS, and
  compares. A value copied out of public DNS cannot be "submitted" to shortcut
  anything.
- Only a **digest** is used for comparison; the plaintext is kept
  envelope-encrypted under a KMS-held master key so the owner can re-display
  their instructions. A database dump yields neither the preimage nor the
  token, and a token copied from the database is useless without control of
  the DNS zone.

This alone closes the reported attack: the leftover record contains the *old*
token, the new claim has a *new* token, and the exact-match check fails.

### 2. Two proof methods, both claim-scoped

| Method | Record | Used for |
|---|---|---|
| CNAME | `<host>` → `<label>.verify.kite.example`, label = first 26 hex chars of the token digest | subdomains (the record is needed for routing anyway) |
| TXT | `_kite-verify.<host>` → `kite-verify=<token>` | apex names, and every high-risk reclaim |

The CNAME target is token-derived too, so the routing record itself is
claimant-specific. The edge routes a request only when the CNAME target is one
the platform issued for a **currently live** claim.

Apex vs. subdomain is chosen automatically (`auto` in `Config#default_proof`)
so a first-time user adds one record and is done.

### 3. Claim lifecycle with explicit release

```
pending ──proof observed──▶ active ──proof gone──▶ at_risk ──14d──▶ released
   │                          │                      │
   └──7d expiry───────────────┴───user unbind────────┴──▶ released
   revoked  (abuse action; tombstone)
```

- `released` and `revoked` are **tombstones**, not deletions. They record *who*
  held the host, *when*, and *why* it ended, and they are what the reclaim
  policy reads. The partial unique index
  `UNIQUE(host) WHERE state IN ('pending','active','at_risk')` means tombstones
  never block a new claim.
- `at_risk` exists so that a legitimate user who edits DNS (or whose provider
  hiccups) is not disconnected immediately. Serving continues during the grace
  period; only *new* certificates are blocked. A moderator/notification path
  runs in parallel.
- **Only an authoritative "record is gone" can move a claim out of `active`.**
  `SERVFAIL`, timeouts, REFUSED and lame delegations are `inconclusive` and
  change nothing — otherwise anyone could detach anyone's domain by making the
  resolver fail. This is enforced by `DnsClient`'s outcome classification and
  covered by tests.

### 4. Reclaim policy

When a host is claimed, `ClaimPolicy` looks at the most recent tombstone:

| Situation | Proof required | Review | Previous owner notified |
|---|---|---|---|
| No history | default (CNAME/TXT) | no | — |
| Same account re-binding | default | no | — |
| Different account, ≤ 7 days after release | **TXT only** | yes | yes |
| Different account, after 7 days | TXT | no | yes |
| Previous claim was **revoked for abuse** | TXT | yes | yes |
| Claimant holds an active **zone delegation** | default | no | no |

The "≤ 7 days" row is the direct answer to the incident. It is not a hard
block — real domains do change hands — but it means the new claimant must
publish a *fresh* TXT token they can only know by controlling the zone, a human
sees the reclaim, and the previous owner can dispute it for 14 days.

Serving during a reclaim is deliberate: the new claimant may be legitimate, and
removing a live site because *someone* filed a dispute would hand attackers a
denial-of-service primitive. New issuance waits for review; existing service and
renewals continue.

### 5. Zone delegation (the friction reducer)

An agency with hundreds of subdomains does not want hundreds of records. They
prove one registrable domain once:

```
_kite-verify.<registrable-domain>  TXT  kite-verify=<token>
```

After that, subdomains under that zone claimed **by the same account** verify
with the ordinary per-host record but skip reclaim review. The delegation is
scoped to one account, so it never lets anyone else claim under the zone. This
keeps the common "one site, many subdomains" case at one record while staying
claimant-specific.

### 6. Issuance re-checks everything, every time

`IssuancePolicy#authorize!` is deny-by-default and runs on **every** issuance
and **every** renewal:

1. every name belongs to the requesting account and is `active`;
2. every name's DNS proof is **observed again right now** — a stored `active`
   state is never sufficient;
3. a claim under a dispute gets no new certificate (renewals still allowed, so
   the incumbent stays up);
4. a recent risky reclaim waits for manual review before its first certificate;
5. **CAA** (RFC 8659) is honoured: a CAA RRset that does not list this
   platform's CA identifier blocks issuance; an *inconclusive* CAA lookup is a
   hard failure, because a certificate cannot be un-issued;
6. ACME-style quotas (per account, per registrable domain, global) apply.

Certificates that can no longer be justified are marked `superseded` by the
renewal path rather than silently extended, and `serving_certificate` requires
the host to have a **live claim owned by the certificate's account**.

### 7. Operational integrity

- **Audit hash chain.** Every transition appends
  `entry_hash = H(prev_hash ‖ entry)`. Editing or deleting history breaks the
  chain and `Audit#verify_chain!` reports the first bad row. This is the record
  an abuse investigator reads after an incident.
- **Rate limits** on claims (per account and per host), verification attempts,
  and ACME orders. Fixed windows live in the database so limits hold across
  workers.
- **Leases** make every unit of scheduler work single-owner across processes,
  with a TTL so a crashed worker cannot wedge a host.
- **Notifications** on detach, reclaim, and dispute, so the previous owner
  learns about a reclaim while they can still act.

## Scale: 300k domains, periodic renewal

The scheduler never scans the population. Every sweep reads a narrow index:

```sql
SELECT id FROM custom_domains
 WHERE state IN ('pending','active','at_risk') AND next_check_at <= ?
 ORDER BY next_check_at, id LIMIT 500
```

`next_check_at` carries ±6h of jitter so checks spread out instead of arriving
in one burst; pending claims back off exponentially. Measured on this machine
with `bin/benchmark` (in-memory SQLite, 300 000 domains, 3 000 due per pass):

```
Populating 300000 domains (3000 due)…
  inserted in 35.71s
Population: 300000, due: 3000
sweep_checks:     1.779s for 3000 rows (0.6 ms/row)
sweep_expirations:0.067s
query plan: SEARCH custom_domains USING INDEX idx_domains_next_check (next_check_at<?)
```

A full pass over the due set is ~1.8 s and the query plan is an index search,
not a table scan. With checks spaced 24 h ± 6 h, the due rate is roughly
`300 000 / 86 400 ≈ 3.5` rows/second, so a few workers keep up with large margin.
Renewals are likewise index-driven (`idx_certs_renewal`), and issuance is
idempotent — an identical live certificate is reused rather than re-ordered.

The whole test suite (87 tests) runs in ~11 s.

## Migrating users / avoiding churn

Domain moves are the stated attrition risk, so the design makes the safe paths
cheap:

- **First bind:** one record, auto-chosen. No account-level DNS changes.
- **Moving a domain *to* the platform:** the normal claim. If the old provider's
  record is still in DNS it is irrelevant — the token is new.
- **Moving a domain *off* and back:** the same account is exempt from reclaim
  review.
- **Many subdomains:** one zone delegation, then per-host CNAMEs that double as
  routing records.
- **No waiting:** placeholder "coming soon" serving and certificate issuance can
  be enabled once the claim is `active`; the reclaim review path is the only one
  that is deliberately slow, and it is rare.

## What changed vs. the old system

| Old | New |
|---|---|
| A verification record proved the *domain* | A token proves the *claim*; tokens are per-claim and random |
| Verification state stored once, trusted forever | Issuance re-observes DNS and re-runs all policy |
| Unbind deleted the domain; rebind looked like a first claim | Unbind leaves a tombstone; reclaim policy reads it |
| DNS failure could detach a domain | Only authoritative absence can; errors are inert |
| No record of who did what | Append-only hash-chained audit |

## Files

```
lib/domain_guard/
  idna.rb, punycode.rb     canonical hostnames (IDN, UTS-46 mapping, Punycode)
  public_suffix.rb          PSL evaluation (registrable domains, public suffixes)
  dns_client.rb             stub resolver with explicit present/absent/inconclusive
  simulated_dns.rb          deterministic in-memory DNS for demo + tests
  proof.rb                  per-claim tokens and CNAME targets
  crypto.rb                 HKDF, constant-time compare, Encrypt-then-MAC vault
  claim_policy.rb           reclaim decision table
  verifier.rb               DNS observation → proof verdict
  domain_service.rb         claim / verify / release / revoke / dispute / delegation
  issuance_policy.rb        deny-by-default issuance gate (ownership, freshness, CAA, quotas)
  issuer.rb                 issue / renew / revoke / serving lookup
  ca.rb                     local CA (real X.509) + ACME interface
  scheduler.rb              indexed, leased, jittered sweeps
  audit.rb                  hash-chained audit + notifications
  lock.rb                   rate limiter + leases
  db.rb, models.rb          schema and models
bin/demo                    narrated walkthrough of the incident and the fix
bin/benchmark               300k-domain scale measurement
bin/kite                    CLI for manual operations
test/                       87 tests; hijack_attack_test.rb encodes the incident
```

## Running it

```
ruby -Ilib lib/demo.rb          # narrated end-to-end run
rake test                       # 87 tests
DOMAINS=300000 DUE=3000 ruby -Ilib bin/benchmark
```

## Known limits / next steps

- The local CA is for the demo and tests; production plugs the ACME client
  behind `AcmeClient` — the policy and scheduler interfaces do not change.
- SQLite is used for a self-contained demo. The schema and queries are portable;
  on Postgres, add `FOR UPDATE SKIP LOCKED` to the sweep for cheaper concurrency.
- Deleted-zone detection could be strengthened by also watching the registrable
  domain's NS records, so a wholesale zone deletion is noticed even if the
  individual record is still served from cache.
