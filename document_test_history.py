"""Offline accepted-classification history ledger for BL-038 tranche 3t (test-only).

Tranches 3f..3s each recorded, at their merge, what the classification shard they
touched was: its bytes, its parsed content, its entry/line counts and its category
breakdown. Those are facts about the PAST and must never be rewritten to fit a
newer tree.

Up to tranche 3s the only place those facts existed was inside assertions that
hashed the CURRENT shard file against them. That conflates two propositions:

    HISTORY  "at tranche N's merge, shard X was exactly this."
    CURRENT  "shard X right now is still exactly that."

Tranche 3t is the FOUNDATION half of separating them: it gives the historical facts
an independent, offline home so that a later tranche can retarget the current-side
guards without having to re-derive, weaken or rewrite history. The ledger is never
recomputed from a live shard and never fetched over the network; `LEDGER_DIGEST`
pins it, the classification tests spell that digest out again, and every accepted
SHA and merge commit is cross-checked against BL-038's own acceptance record in
BACKLOG.md.

Scope boundary, deliberately: tranche 3t does NOT yet use this ledger to decide
anything about the current tree, and does NOT replace the existing byte/index-based
guards. Those still hold exactly as they did on main, so Category C source
conversion remains blocked after 3t. The migration-aware current lifecycle -- an
explicit retired/successors mapping, `live - successors + retired == accepted`,
nested accepted windows -- is tranche 3u.

`contracts_digest` is recorded here as historical evidence of WHICH document
contracts a tranche accepted -- (file, class, method, targets) as a multiset. It is
verified against the real file at the accepting merge commit (see BL-038's tranche
3t verification record) and is what 3u will need to tell a legitimate structural
conversion from a silent deletion. Nothing in 3t reads it against a live shard.
"""

import hashlib
import json

LEDGER_FILENAME = "document_test_classification_history.json"
LEDGER_SCHEMA_VERSION = 1

# Tamper-evidence pin. Every accepted fact was verified against the real file at its
# accepting merge commit before being recorded (BL-038 tranche 3t verification
# record). It moves only when acceptance history legitimately grows -- never because
# the current tree moved.
LEDGER_DIGEST = "5ed8d7b27837589ab3571a02a0fbdbd3c94db1f93cfa3fc687227320ef59160d"

# What "the same accepted document contract" means: which target an assertion in a
# given test method binds to. Excludes id/ordinal (a future split renumbers them,
# and `validate_manifest` already owns their correctness) and the fields a
# conversion may rewrite (assertion_api, fingerprint, category, action,
# contract_summary, rationale).
CONTRACT_FIELDS = ("file", "class", "method", "targets")

_RECORD_KEYS = ("tranche", "pull_request", "merge_commit", "shard", "scope_slice",
                "historical")
_HISTORICAL_KEYS = ("sha256", "line_count", "entry_count", "content_digest",
                    "category_counts", "contracts_digest")
_CATEGORIES = ("A", "B", "C", "D")
_HEX = frozenset("0123456789abcdef")


def _canonical(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _is_hex(value, width):
    return isinstance(value, str) and len(value) == width and set(value) <= _HEX


def _is_count(value, minimum=1):
    return type(value) is int and value >= minimum


def load_ledger(root):
    """Parsed accepted-history ledger. Reads ONLY the ledger file."""
    return json.loads((root / LEDGER_FILENAME).read_text(encoding="utf-8"))


def ledger_digest(root):
    """Any edit to any accepted fact moves this, so history cannot be re-fitted."""
    return hashlib.sha256(_canonical(load_ledger(root))).hexdigest()


def accepted(root, tranche):
    """One tranche's accepted record; KeyError if absent, so a typo cannot skip it."""
    for record in load_ledger(root)["accepted"]:
        if record["tranche"] == tranche:
            return record
    raise KeyError(f"no accepted ledger record for tranche {tranche!r}")


def contract_of(entry):
    return tuple(json.dumps(entry[field], ensure_ascii=False, sort_keys=True)
                 for field in CONTRACT_FIELDS)


def contracts_digest(scope, contracts):
    """Digest over a window's multiset of document contracts. Order-insensitive by
    design: a future split renumbers assertions without changing which contracts the
    window covers."""
    return hashlib.sha256(_canonical({
        "scope": scope, "contracts": sorted(list(c) for c in contracts),
    })).hexdigest()


def window_contracts(entries):
    return [contract_of(entry) for entry in entries]


def ledger_shape_failures(root, indexed_shards=None):
    """Shape problems in the accepted ledger; empty means well-formed. Fail-closed on
    unknown keys, wrong types, bools posing as ints, and a category breakdown that
    disagrees with the accepted entry count."""
    problems = []
    ledger = load_ledger(root)
    if tuple(ledger.keys()) != ("schema_version", "accepted"):
        problems.append(f"ledger-keys:{tuple(ledger.keys())}")
    version = ledger.get("schema_version")
    if isinstance(version, bool) or version != LEDGER_SCHEMA_VERSION:
        problems.append(f"ledger-schema-version:{version!r}")
    if not isinstance(ledger.get("accepted"), list) or not ledger["accepted"]:
        problems.append("ledger-accepted-not-a-nonempty-list")
        return problems
    seen = set()
    for record in ledger["accepted"]:
        tranche = record.get("tranche") if isinstance(record, dict) else None
        if not isinstance(record, dict) or tuple(record.keys()) != _RECORD_KEYS:
            problems.append(f"{tranche}:record-keys")
            continue
        if not (isinstance(tranche, str) and tranche.strip()):
            problems.append(f"{tranche!r}:tranche-not-a-name")
        if tranche in seen:
            problems.append(f"{tranche}:duplicate-tranche")
        seen.add(tranche)
        if isinstance(record["pull_request"], bool) or not _is_count(record["pull_request"]):
            problems.append(f"{tranche}:pull-request:{record['pull_request']!r}")
        if not _is_hex(record["merge_commit"], 40):
            problems.append(f"{tranche}:merge-commit:{record['merge_commit']!r}")
        shard = record["shard"]
        if not (isinstance(shard, str) and shard.strip()):
            problems.append(f"{tranche}:shard:{shard!r}")
        elif indexed_shards is not None and shard not in indexed_shards:
            problems.append(f"{tranche}:shard-not-indexed:{shard}")
        span = record["scope_slice"]
        if not (isinstance(span, list) and len(span) == 2
                and all(type(v) is int and not isinstance(v, bool) and v >= 0 for v in span)
                and span[0] < span[1]):
            problems.append(f"{tranche}:scope-slice:{span!r}")
        historical = record["historical"]
        if not isinstance(historical, dict) or tuple(historical.keys()) != _HISTORICAL_KEYS:
            problems.append(f"{tranche}:historical-keys")
            continue
        for label in ("sha256", "contracts_digest"):
            if not _is_hex(historical[label], 64):
                problems.append(f"{tranche}:historical-{label}:{historical[label]!r}")
        digest = historical["content_digest"]
        if digest is not None and not _is_hex(digest, 64):
            problems.append(f"{tranche}:historical-content-digest:{digest!r}")
        for label in ("line_count", "entry_count"):
            value = historical[label]
            if isinstance(value, bool) or not _is_count(value):
                problems.append(f"{tranche}:historical-{label}:{value!r}")
        counts = historical["category_counts"]
        if not isinstance(counts, dict) or tuple(sorted(counts)) != _CATEGORIES:
            problems.append(f"{tranche}:category-counts-keys:{counts!r}")
        elif any(isinstance(counts[c], bool) or not _is_count(counts[c], 0)
                 for c in _CATEGORIES):
            problems.append(f"{tranche}:category-counts-values:{counts!r}")
        elif sum(counts[c] for c in _CATEGORIES) != historical["entry_count"]:
            problems.append(f"{tranche}:category-counts-sum:{counts!r}"
                            f"!={historical['entry_count']}")
    return problems


def assert_accepted_history(case, root, tranche, sha256=None, content_digest=None,
                            line_count=None, entry_count=None, category_counts=None,
                            contracts_digest=None):
    """Assert accepted facts from the offline ledger ONLY -- never a live shard, never
    the network. Each keyword is the inline constant that already records the same
    accepted fact; requiring the two independent copies to agree is what keeps history
    honest, and the ledger pin catches an edit to the ledger alone.

    Callers must pass only history-only constants. A constant that is ALSO a current
    value (a live line count, a live entry count) must not be routed through here:
    that is exactly the coupling BL-038 tranche 3t exists to undo.
    """
    case.assertEqual(ledger_digest(root), LEDGER_DIGEST)
    record = accepted(root, tranche)
    for label, expected in (("sha256", sha256), ("content_digest", content_digest),
                            ("line_count", line_count), ("entry_count", entry_count),
                            ("category_counts", category_counts),
                            ("contracts_digest", contracts_digest)):
        if expected is not None:
            case.assertEqual(record["historical"][label], expected, f"{tranche}.{label}")
    return record
