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


# ---------------------------------------------------------------------------
# BL-038 tranche 3u: the MIGRATION layer. 3t gave the accepted facts an offline home
# but left the pre-3t guards holding the current tree to accepted BYTES and
# POSITIONS, so Category C conversion stayed blocked. 3u replaces that with
# `live_contracts - successors + retired == accepted contracts_digest`, where a
# contract is (file, class, method, targets) -- deliberately NOT id or ordinal. That
# is what makes pure ordinal drift free: a split renumbers every later assertion in
# its method without changing which contract any of them covers, so only a genuinely
# retired, split, merged or re-targeted contract needs an entry.
MIGRATIONS_FILENAME = "document_test_classification_migrations.json"
MIGRATION_SCHEMA_VERSION = 1
MIGRATION_KINDS = ("split", "merge", "retarget", "replace")
_MIGRATION_KEYS = ("id", "tranche", "kind", "reason", "retired", "successors")
_MEMBER_KEYS = ("id", "targets")

# Each tranche's accepted scope descriptor, recorded once from the ACCEPTING MERGE
# COMMIT rather than re-derived from where those entries sit today. Windows are
# selected by (file, class) ownership, never by a positional slice, so an append or
# insert elsewhere cannot move them. Pinned by ACCEPTED_SCOPES_DIGEST.
ACCEPTED_SCOPES = {
    "3f": [{"file":"test_custom_domain.py","classes":["DocsCnameFileTest","CnameSurvivesGenerationTest","ArticleBriefContractUnchangedTest","Bl007DocumentationTest","ReadmePublicUrlTest","Bl007ClosureRecordTest","TicketIdTypoTest"]},{"file":"test_ui_spec.py","classes":["UiSpecDocumentTest","Bl036ArticleAttributionUiSpecTest"]},{"file":"test_status.py","classes":["StatusSourceOfTruthTest","Sd031DecisionTest","Bl035ActiveWorkTest","StatusSecurityOperationsSourceOfTruthTest","Bl036PostMergeRecordFixTest","Bl036ProductionEvidenceSyncTest"]},{"file":"test_security_requirements.py","classes":["Bl031AcceptanceAndBl032RegistrationTest","Bl034Round2ReviewCorrectionsTest","Bl034ImplementationAcceptanceTest","Bl034CloseoutTest","StatusSecurityRequirementsSourceOfTruthTest"]}],
    "3h": [{"file":"test_security_operations.py","classes":["SecurityOperationsContractTest","Bl031SecurityOperationsReconciliationTest"]}],
    "3i": [{"file":"test_security_operations.py","classes":["SecurityOperationsContractTest","Bl031SecurityOperationsReconciliationTest"]},{"file":"test_security_requirements.py","classes":["Bl031SecurityRequirementsReconciliationTest"]}],
    "3j": [{"file":"test_security_operations.py","classes":["Bl035DraftSyncTest"]}],
    "3k": [{"file":"test_security_operations.py","classes":["Bl035DraftSyncTest"]},{"file":"test_pr_ci_workflow.py","classes":["PullRequestCIWorkflowTest"]}],
    "3l": [{"file":"test_security_operations.py","classes":["Bl035DraftSyncTest"]},{"file":"test_pr_ci_workflow.py","classes":["PullRequestCIWorkflowTest"]},{"file":"test_workflow_action_pinning.py","classes":["WorkflowActionPinningTest","DependabotConfigurationTest"]}],
    "3m": [{"file":"test_security_operations.py","classes":["Bl035DraftSyncTest"]},{"file":"test_pr_ci_workflow.py","classes":["PullRequestCIWorkflowTest"]},{"file":"test_workflow_action_pinning.py","classes":["WorkflowActionPinningTest","DependabotConfigurationTest"]},{"file":"test_security_requirements.py","classes":["Bl034Round1ReviewCorrectionsTest"]}],
    "3o": [{"file":"test_security_requirements.py","classes":["SecurityRequirementsTest"],"method_range":{"start":"test_document_is_approved_version_14_maintenance_update","end":"test_bl028_is_recorded_verbatim_as_complete"}}],
    "3p": [{"file":"test_source_usage_policy.py","classes":["SourceUsagePolicyTest"],"method_range":{"start":"test_gemini_gate_references_point_to_chapter_5","end":"test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified"}}],
    "3q": [{"file":"test_security_requirements.py","classes":["SecurityRequirementsTest"],"method_range":{"start":"test_bl029_is_recorded_verbatim_as_complete","end":"test_bl015_is_complete_and_removed_from_active_work"}}],
    "3r": [{"file":"test_security_requirements.py","classes":["SecurityRequirementsTest"],"method_range":{"start":"test_sd024_sd025_and_follow_up_tickets_are_recorded","end":"test_security_requirements_internal_markdown_links_resolve"}}],
    "3s": [{"file":"test_source_usage_policy.py","classes":["SourceUsagePolicyTest"],"method_range":{"start":"test_mandiant_distinguishes_rss_evidence_from_terms_evidence","end":"test_relationship_section_defers_enforcement_to_bl032"}}],
}
ACCEPTED_SCOPES_DIGEST = "243fd2d139f75bffb8a887fc3c797ce75dcca5601c11518a4657d55f2a1ec991"


def accepted_scopes_digest():
    return hashlib.sha256(_canonical(ACCEPTED_SCOPES)).hexdigest()


def load_migrations(root):
    """Parsed migration ledger. Empty until a real conversion tranche retires an
    accepted contract; tranche 3u ships it empty on purpose."""
    return json.loads((root / MIGRATIONS_FILENAME).read_text(encoding="utf-8"))


def _member_contract(member):
    file_name, class_name, method, _ = member["id"].split("::")
    return contract_of({"file": file_name, "class": class_name, "method": method,
                        "targets": member["targets"]})


def accepted_window(root, tranche):
    """(accepted scope descriptor, live entries it owns), by (file, class) ownership,
    so the window survives renumbering, appends and inserts elsewhere in the shard."""
    record = accepted(root, tranche)
    scope = ACCEPTED_SCOPES[tranche]
    owned = {(s["file"], c) for s in scope for c in s["classes"]}
    shard = json.loads((root / record["shard"]).read_text(encoding="utf-8"))
    return scope, [e for e in shard["assertions"] if (e["file"], e["class"]) in owned]


def migrations_for(root, tranche):
    """Migrations touching this window, matched by (file, class) ownership rather than
    a declared tranche name. Accepted windows nest -- shard 002's 3k/3l/3m are
    prefixes of one another -- so one split departs from all three accepted states and
    must satisfy each from a SINGLE recorded migration."""
    scope = ACCEPTED_SCOPES[tranche]
    owned = {(s["file"], c) for s in scope for c in s["classes"]}
    picked = []
    for migration in load_migrations(root)["migrations"]:
        members = migration["retired"] + migration["successors"]
        if any(tuple(m["id"].split("::")[:2]) in owned for m in members):
            picked.append(migration)
    return picked


def reconstruct_accepted_contracts(root, tranche, live_entries):
    """Undo the recorded migrations against the live window. LookupError if a migration
    claims a successor the live window lacks, so a wrong or invented successor cannot
    silently balance the equation."""
    contracts = window_contracts(live_entries)
    for migration in migrations_for(root, tranche):
        for successor in migration["successors"]:
            contract = _member_contract(successor)
            if contract not in contracts:
                raise LookupError(
                    f"{migration['id']}: successor {successor['id']} is not a live "
                    f"contract of accepted tranche {tranche}")
            contracts.remove(contract)
        for retired in migration["retired"]:
            contracts.append(_member_contract(retired))
    return contracts


def migration_shape_failures(root):
    """Fail-closed shape and cross-record checks for the migration ledger."""
    problems = []
    data = load_migrations(root)
    if tuple(data.keys()) != ("schema_version", "migrations"):
        problems.append(f"migrations-keys:{tuple(data.keys())}")
    version = data.get("schema_version")
    if isinstance(version, bool) or version != MIGRATION_SCHEMA_VERSION:
        problems.append(f"migrations-schema-version:{version!r}")
    if not isinstance(data.get("migrations"), list):
        return problems + ["migrations-not-a-list"]
    seen_ids, retired_ids, successor_ids = set(), set(), set()
    for index, migration in enumerate(data["migrations"]):
        label = migration.get("id", f"#{index}") if isinstance(migration, dict) else f"#{index}"
        if not isinstance(migration, dict) or tuple(migration.keys()) != _MIGRATION_KEYS:
            problems.append(f"{label}:migration-keys")
            continue
        if not (isinstance(migration["id"], str) and migration["id"].strip()):
            problems.append(f"{label}:migration-id")
        elif migration["id"] in seen_ids:
            problems.append(f"{label}:duplicate-migration-id")
        seen_ids.add(migration["id"])
        if not (isinstance(migration["tranche"], str) and migration["tranche"].strip()):
            problems.append(f"{label}:tranche")
        if migration["kind"] not in MIGRATION_KINDS:
            problems.append(f"{label}:unknown-kind:{migration['kind']!r}")
        if not (isinstance(migration["reason"], str) and migration["reason"].strip()):
            problems.append(f"{label}:empty-reason")
        sides = {}
        for side, pool in (("retired", retired_ids), ("successors", successor_ids)):
            members = migration[side]
            if not (isinstance(members, list) and members):
                problems.append(f"{label}:{side}-empty")
                continue
            local, contracts = set(), []
            for member in members:
                if not isinstance(member, dict) or tuple(member.keys()) != _MEMBER_KEYS:
                    problems.append(f"{label}:{side}-member-keys")
                    continue
                mid = member["id"]
                if not (isinstance(mid, str) and mid.count("::") == 3
                        and all(mid.split("::")) and mid.split("::")[3].startswith("assert-")):
                    problems.append(f"{label}:{side}-id:{mid!r}")
                    continue
                if mid in local:
                    problems.append(f"{label}:duplicate-{side}-id:{mid}")
                local.add(mid)
                if mid in pool:
                    problems.append(f"{label}:{side}-id-claimed-twice:{mid}")
                pool.add(mid)
                if not (isinstance(member["targets"], list) and member["targets"]
                        and all(isinstance(t, str) and t for t in member["targets"])):
                    problems.append(f"{label}:{side}-targets:{member['targets']!r}")
                    continue
                contracts.append(_member_contract(member))
            sides[side] = sorted(contracts)
        if sides.get("retired") and sides.get("retired") == sides.get("successors"):
            problems.append(f"{label}:no-op-migration")
    return problems


def assert_accepted_contracts_accounted_for(case, root, tranche):
    """Every accepted contract is still live, or explicitly retired by a recorded
    migration. One-to-one conversion and pure ordinal drift need NO entry; a split,
    merge or retarget passes only once recorded; a silent deletion cannot pass."""
    scope, live = accepted_window(root, tranche)
    rebuilt = reconstruct_accepted_contracts(root, tranche, live)
    case.assertEqual(
        contracts_digest(scope, rebuilt), accepted(root, tranche)["historical"]["contracts_digest"],
        f"{tranche}: accepted contracts are not accounted for by the live window plus the "
        f"recorded migrations ({len(live)} live, {len(rebuilt)} reconstructed)")


def assert_accepted(case, root, tranche, **historical):
    """Both halves at one call site: accepted facts from the offline ledger, and the
    current tree still accounting for every accepted contract."""
    case.assertEqual(accepted_scopes_digest(), ACCEPTED_SCOPES_DIGEST)
    record = assert_accepted_history(case, root, tranche, **historical)
    assert_accepted_contracts_accounted_for(case, root, tranche)
    return record
