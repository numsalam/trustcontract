# TrustContract

Declarative capability contracts, signed approvals, and a tamper-evident
audit log — **pure Python, zero dependencies, fail closed**.

TrustContract extracts the permission/approval pattern already proven twice
in the wild — **Numa's approval queue** (life-agent) and **SKILLSEED's
permission-gated skills** — into a standalone library any agent or service
can adopt:

| proven pattern | here |
| --- | --- |
| undeclared capability → never runs | `default` + fail-closed engine |
| state-changing ops need a human | `default: ask` → escalate → signed grant |
| irreversible ops need the human to say so | Consequence Engine → acknowledgments |
| every decision leaves a trail | hash-chained append-only audit log |

## Philosophy

- **Fail closed.** Unknown capability, corrupt store, bad signature, invalid
  contract — every failure path narrows access. Nothing widens it.
- **Zero dependencies.** Standard library only. Contract files are YAML via
  a built-in minimal parser (PyYAML is used if you happen to have it).
- **Bounded.** Names, notes, records, grant counts, lifetimes — everything
  has a limit. No unbounded input is accepted anywhere.
- **Decide, don't execute.** The engine returns decisions. Consuming a
  one-shot grant is explicit, so read-only checks never burn approvals.

## Install

```bash
pip install .            # from this directory
```

Or just put `trustcontract/` on your path — there is nothing to build.

## Quickstart

```bash
$ trustcontract init-key                       # writes ~/.trustcontract/key.hex
$ trustcontract contracts --contracts examples/contracts.yaml
$ trustcontract request --principal numa --capability file.write \
    --contracts examples/contracts.yaml
escalate: approval required
  acknowledge [notice]: This action can only be undone manually.
$ trustcontract approve --principal numa --capability file.write \
    --contracts examples/contracts.yaml --note "deploy script"
granted file.write to numa
  id: g_9f2c1a4b7e03  expires_at: 1732199464.123  uses: 1
$ trustcontract request --principal numa --capability file.write \
    --contracts examples/contracts.yaml --consume
allow: authorized by grant
  grant: g_9f2c1a4b7e03
  grant consumed (one use spent)
$ trustcontract verify --audit ~/.trustcontract/audit.jsonl
ok: 4 records
```

Files resolve under `--home` (default `~/.trustcontract`): `contracts.yaml`,
`grants.json`, `audit.jsonl`, `key.hex`. Each has a `--contracts/--grants/
--audit/--key` override. Exit codes: `0` allowed, `1` denied, `2` escalation
required, `3` error — so callers can branch mechanically.

## Contracts

A contract is the single source of truth for one capability:

```yaml
contracts:
  - name: shell.exec          # ^[a-z0-9][a-z0-9._-]{0,99}$
    description: Execute a shell command
    risk: critical            # low | medium | high | critical
    default: ask              # allow | ask | deny
    locked: false             # true = never grantable, always denied
    expiry_seconds: 600       # suggested grant lifetime
    max_uses: 1               # suggested grant uses (1 = one-shot)
    consequences:
      side_effects:           # filesystem network process credential
        - process             # deletion money public-content
        - filesystem
      reversibility: irreversible   # reversible | manual | irreversible
      blast_radius: single-host     # process | single-host | multi-host | public
```

Invalid contracts fail at **load** time, never at decision time. Duplicate
names are rejected. The dependency-free YAML parser supports nested
mappings, `- ` block lists, comments, and plain/quoted scalars — no flow
style (`[a, b]`), no anchors, no tabs. (Install PyYAML and full YAML is
used automatically.)

## The decision model

Evaluated in order, fail closed at every step:

1. unknown capability → **deny** (`undeclared capability`)
2. contract `locked` → **deny** (`capability is locked`) — grants cannot override
3. valid signed grant → **allow** (cites the grant id)
4. `default: allow` → **allow** (still audited)
5. `default: ask` → **escalate** (approval required, acknowledgments attached)
6. `default: deny` → **deny** (`denied by contract`)

Every evaluation is appended to the audit log.

## Grants & signatures

A grant authorizes one `(principal, capability)` pair:

- **Signed** — HMAC-SHA256 over the record's canonical JSON under a 32-byte
  key (`secrets`-generated, hex, mode 0600). Verification is constant-time;
  a tampered field, wrong key, or malformed signature all fail.
- **Expiring** — every grant carries `expires_at`; suggested lifetime comes
  from the contract.
- **One-shot by default** — `uses` decrements on explicit consume; a used-up
  grant is dead.
- **Revocable** — `revoke` kills a grant (only validly-signed ones are
  touched, so revocation can never launder a forgery).
- **Fail-closed store** — a corrupt `grants.json` yields zero grants *and*
  refuses modifications; saves are atomic (tmp + rename).

## The Consequence Engine

Contracts declare what a capability does to the world; the engine turns
that into what a human must acknowledge before approving:

| declaration | acknowledgment |
| --- | --- |
| `reversibility: irreversible` | "This action cannot be undone." |
| `reversibility: manual` | "This action can only be undone manually." |
| `blast_radius: multi-host`/`public` | "Effects extend beyond this host." |
| `blast_radius: public` | "Effects are publicly visible." |
| `credential` / `deletion` / `money` side effect | explicit notice per effect |
| `risk: critical` | **typed confirmation** — `approve --confirm <name>` |

Acknowledgments appear only on escalations — `allow` decisions never nag.

## Audit

One JSON line per record, hash-chained:

```json
{"event": "grant.added", "grant_id": "g_...", "hash": "sha256...",
 "prev": "sha256 of previous record", "seq": 4, "ts": 1732196464.123, ...}
```

`trustcontract verify` walks the chain — any edit, deletion, or reordering
after the fact is detected and reported with the first bad record.

## Library use

```python
from trustcontract import (
    AuditLog, DecisionEngine, GrantStore, Request,
    load_contracts_file, load_key,
)

contracts = load_contracts_file("contracts.yaml")
grants = GrantStore("grants.json", load_key("key.hex"))
audit = AuditLog("audit.jsonl")
engine = DecisionEngine(contracts, grants, audit)

decision = engine.evaluate(Request(principal="numa", capability="file.write"))
if decision.outcome == "escalate":
    ...  # surface decision.acknowledgments to the human
elif decision.outcome == "allow":
    ...  # act, then engine.consume(request) for one-shot grants
```

## CLI reference

```
init-key [path]                  generate a signing key (0600)
contracts                        list contracts (validates the file)
request --principal --capability [--args JSON] [--context JSON] [--consume]
approve --principal --capability [--by] [--expiry N] [--uses N]
        [--note TXT] [--confirm NAME]
revoke --grant-id
grants                           list grants with computed status
purge                            drop expired/used-up/invalid grants
verify                           verify the audit hash chain
tail [--n N]                     last N audit records
```

## Limitations (honest)

- Single-writer audit log; concurrent appenders can interleave lines.
- HMAC keys are symmetric — the approver and the verifier share the key.
  Asymmetric (Ed25519) signatures would need a dependency; the seam is
  `approvals.py` when that day comes.
- The minimal YAML parser covers the contract subset only (install PyYAML
  for full YAML).
- Grants are per-host state in one JSON file — no replication, no consensus.
- The engine decides; it does not sandbox execution. Pair it with an
  executor that respects the decision.

## Layout

```
trustcontract/
  yaml_min.py       minimal YAML subset parser (PyYAML optional)
  consequences.py   Consequence Engine → acknowledgments
  contract.py       Contract model + loading/validation
  approvals.py      HMAC-SHA256 sign/verify (stdlib only)
  grants.py         signed, expiring, one-shot grant store
  audit.py          append-only hash-chained audit log
  engine.py         DecisionEngine: allow / deny / escalate
  cli.py            command line interface
examples/contracts.yaml
tests/
```

## License

MIT — Numsalam (NUMAWARE).
