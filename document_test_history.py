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


def ledger_shape_failures(root):
    """Shape problems in the accepted ledger; empty means well-formed. Fail-closed on
    unknown keys, wrong types, bools posing as ints, and a category breakdown that
    disagrees with the accepted entry count.

    BL-038 tranche 3y-a (N5): `record["shard"]` is validated as a non-empty historical
    LOCATOR only. It is deliberately NOT required to name a currently indexed shard.
    Requiring that contradicted this module's own contract -- `live_entries` reads every
    indexed manifest rather than the shard a record names, precisely so a later legal
    re-shard leaves accepted history where it is -- and it would have forced the accepted
    ledger (and `LEDGER_DIGEST`) to be rewritten to follow the current physical layout.
    """
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
        if not (isinstance(shard, str) and shard.strip() and shard.endswith(".json")):
            problems.append(f"{tranche}:shard:{shard!r}")
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
# BL-038 tranche 3u: the MIGRATION ENGINE. 3t gave the accepted facts an offline
# home; 3u supplies the rule a later tranche will hold the current tree to:
#
#     live_contracts - successors + retired == accepted contracts_digest
#
# A contract is (file, class, method, targets) -- deliberately NOT id or ordinal.
# That is what makes pure ordinal drift free: a split renumbers every later
# assertion in its method without changing which contract any of them covers, so
# only a genuinely retired, split, merged or re-targeted contract needs an entry.
#
# Retargeting the repository's ~67 historical/current coupled tests onto this rule
# is tranche 3v. 3u fixes the engine contract only, so Category C stays blocked.
INDEX_FILENAME = "document_test_classification_index.json"
MIGRATIONS_FILENAME = "document_test_classification_migrations.json"
MIGRATION_SCHEMA_VERSION = 1
MIGRATION_KINDS = ("split", "merge", "retarget", "replace")
_MIGRATION_KEYS = ("id", "tranche", "kind", "reason", "retired", "successors")
_MEMBER_KEYS = ("id", "targets")

# Each tranche's accepted scope descriptor, taken once from its ACCEPTING MERGE
# COMMIT rather than re-derived from where those entries sit today, and pinned by
# ACCEPTED_SCOPES_DIGEST. Windows are resolved by LOGICAL ownership against these,
# never by a positional slice or by the shard a record happens to name, so a later
# tranche may re-shard an accepted contract without history moving.
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
# For method_range scopes, the accepted method list of that range -- also taken from
# the accepting merge commit. A range owns exactly these methods: the current source
# order is never consulted, so a later insertion cannot silently widen a historical
# range, and a boundary method that disappears fails closed rather than shrinking it.
ACCEPTED_RANGE_METHODS = {
    "3o": {"test_security_requirements.py::SecurityRequirementsTest":["test_document_is_approved_version_14_maintenance_update","test_required_sections_are_present","test_sr_ids_are_stable_unique_and_contiguous_through_047","test_published_output_correction_requirement_and_gap_are_recorded","test_operations_requirements_are_met_by_documentation_only","test_semantic_risk_is_evidenced_without_impossibility_generalization","test_gap_ids_and_classifications_are_complete_and_limited","test_current_control_mapping_breakdowns_match_individual_sr_states","test_met_definition_is_repository_limited","test_exception_output_inventory_is_comprehensive_and_precise","test_external_response_size_audit_and_gap_are_recorded","test_custom_domain_preflight_is_future_only_and_complete","test_dast_is_not_duplicated","test_translation_cache_gap_is_resolved_by_bl030","test_approved_roadmap_decisions_are_bounded_and_not_implemented","test_workflows_and_dependabot_reflect_bl026_implementation","test_bl006_backlog_entry_records_completed_brand_migration","test_bl006_accepted_head_final_head_and_merge_commit_are_distinct","test_bl028_is_recorded_verbatim_as_complete"]},
    "3p": {"test_source_usage_policy.py::SourceUsagePolicyTest":["test_gemini_gate_references_point_to_chapter_5","test_attribution_references_point_to_chapter_6","test_no_stale_chapter_7_attribution_references_remain","test_document_is_approved_01","test_required_chapters_are_present","test_17_source_ids_match_source_definitions_exactly","test_every_table_has_proposed_mode_and_checked_at_columns","test_checked_at_is_2026_07_29_except_google_terms_sources","test_mode_counts_are_5_4_2_2_4_by_proposed_mode_column","test_proposed_mode_matches_the_table_the_row_appears_in","test_all_17_sources_disallow_rich_content","test_metadata_only_disallows_ai_processing","test_disabled_legal_review_disallows_network_fetch","test_feed_summary_is_gated_by_gemini_paid_service_confirmation","test_gemini_data_use_status_is_paid_verified","test_gemini_owner_verification_is_recorded_without_secrets","test_gemini_gate_no_longer_lists_unknown_as_current_unresolved_issue","test_feed_summary_production_enforcement_still_deferred_to_bl032","test_google_terms_2026_07_30_recheck_is_recorded_as_completed","test_mandiant_and_google_tag_recheck_triggers_are_specific","test_google_terms_recheck_moved_to_confirmed_in_unknowns_section","test_attribution_requirements_are_recorded_for_each_group","test_limited_feed_analysis_mode_definition_is_present","test_limited_feed_analysis_rows_have_expected_allow_flags","test_risk_acceptance_rationale_is_recorded_and_not_asserted_as_permission","test_metadata_only_allows_metadata_fetch_and_does_not_prohibit_human_browsing","test_cisco_talos_and_krebs_uncertainty_is_not_asserted_as_definitive","test_official_evidence_url_contains_only_urls_or_a_bare_dash","test_official_evidence_url_has_no_descriptive_text_mixed_in","test_multi_url_rows_have_matching_evidence_type_count_when_types_differ","test_krebs_about_page_is_recorded_as_supporting_source_page_not_a_terms_url","test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified"]},
    "3q": {"test_security_requirements.py::SecurityRequirementsTest":["test_bl029_is_recorded_verbatim_as_complete","test_bl028_bl029_registration_does_not_reopen_or_merge_other_tickets","test_sd027_partially_supersedes_sd021_and_preserves_its_other_contracts","test_bl028_kickoff_does_not_reopen_bl017_or_bl022","test_bl027_acceptance_head_is_distinct_from_pr54_final_head","test_bl027_backlog_entry_records_completed_workflow_dispatch_validation","test_bl026_closure_records_pending_run_limitation_and_leaves_other_gaps_unchanged","test_current_gaps_non_required_and_triggers_are_distinct","test_future_components_are_not_misstated_as_current","test_no_secret_value_or_local_absolute_path_is_present","test_bl015_is_complete_and_removed_from_active_work"]},
    "3r": {"test_security_requirements.py::SecurityRequirementsTest":["test_sd024_sd025_and_follow_up_tickets_are_recorded","test_owner_checklist_mandatory_items_are_resolved_without_sensitive_data","test_agents_references_security_docs_without_blanket_authorization","test_agents_ui_spec_reference_delegates_version_too","test_agents_describes_pr_ci_and_fetch_yml_triggers_accurately","test_agents_pr_ci_checkout_target_is_the_merge_candidate_not_the_head","test_agents_distinguishes_unittest_target_diff_check_range_and_head_association","test_agents_pr_ci_secret_and_token_wording_is_precise","test_security_requirements_internal_markdown_links_resolve"]},
    "3s": {"test_source_usage_policy.py::SourceUsagePolicyTest":["test_mandiant_distinguishes_rss_evidence_from_terms_evidence","test_output_similarity_controls_are_recorded_as_bl032_merged","test_output_similarity_controls_distinguish_mechanical_from_residual_risk","test_relationship_section_defers_enforcement_to_bl032"]},
}
ACCEPTED_SCOPES_DIGEST = "5dd7454cfdbcbbafcbf5d3a9d231d47c1592c24271e8a16d2d194b62d9e8c4b5"


def accepted_scopes_digest():
    return hashlib.sha256(_canonical([ACCEPTED_SCOPES, ACCEPTED_RANGE_METHODS])).hexdigest()


def owns(tranche, file_name, class_name, method):
    """Does this tranche's accepted scope own that assertion?

    Whole-class scope: every method of the class. Method-range scope: only the
    methods the range accepted, listed explicitly in ACCEPTED_RANGE_METHODS. The two
    forms share one predicate, so 3k/3l/3m (nested whole-class) and 3o/3q/3r plus
    3p/3s (disjoint ranges over ONE class) are decided by the same rule.
    """
    for scope in ACCEPTED_SCOPES[tranche]:
        if scope["file"] != file_name or class_name not in scope["classes"]:
            continue
        if "method_range" not in scope:
            return True
        if method in ACCEPTED_RANGE_METHODS[tranche][f"{file_name}::{class_name}"]:
            return True
    return False


def load_migrations(root):
    """Parsed migration ledger. Empty until a conversion tranche retires a contract."""
    return json.loads((root / MIGRATIONS_FILENAME).read_text(encoding="utf-8"))


def live_entries(root):
    """Every classified entry, from every manifest the index lists -- NOT from the
    shard a historical record happens to name. An accepted contract may therefore be
    re-sharded by a later tranche without the accepted evidence moving with it."""
    index = json.loads((root / INDEX_FILENAME).read_text(encoding="utf-8"))
    return [entry for name in index["shards"]
            for entry in json.loads((root / name).read_text(encoding="utf-8"))["assertions"]]


def accepted_window(root, tranche, entries=None):
    """(accepted scope descriptor, the live entries it logically owns)."""
    entries = live_entries(root) if entries is None else entries
    return ACCEPTED_SCOPES[tranche], [e for e in entries
                                      if owns(tranche, e["file"], e["class"], e["method"])]


def window_boundary_failures(root, tranche, entries=None):
    """Fail closed when a method_range's accepted boundary method has vanished with
    nothing accounting for it: the window would otherwise silently shrink and take
    accepted coverage with it.

    A boundary whose contracts were explicitly retired by a recorded migration IS
    accounted for, so a legitimate move out of the boundary method is not blocked --
    only an unexplained disappearance or rename is.
    """
    entries = live_entries(root) if entries is None else entries
    retired_methods = {m["id"].split("::")[2]
                       for migration in migrations_for(root, tranche)
                       for m in migration["retired"] if _member_owned(tranche, m)}
    problems = []
    for scope in ACCEPTED_SCOPES[tranche]:
        if "method_range" not in scope:
            continue
        for class_name in scope["classes"]:
            live = {e["method"] for e in entries
                    if e["file"] == scope["file"] and e["class"] == class_name}
            for edge in ("start", "end"):
                method = scope["method_range"][edge]
                if method not in live and method not in retired_methods:
                    problems.append(f"{tranche}:{edge}-boundary-method-missing:{method}")
    return problems


def _member_contract(member):
    file_name, class_name, method, _ = member["id"].split("::")
    return contract_of({"file": file_name, "class": class_name, "method": method,
                        "targets": member["targets"]})


def migrations_for(root, tranche):
    """Migrations touching this accepted window, decided by the SAME ownership
    predicate as the window itself -- not by a declared tranche name.

    Nested whole-class windows (shard 002's 3k/3l/3m) therefore all see one recorded
    split, while disjoint ranges over one class (3o/3q/3r, 3p/3s) never see each
    other's migrations.
    """
    picked = []
    for migration in load_migrations(root)["migrations"]:
        for member in migration["retired"] + migration["successors"]:
            file_name, class_name, method, _ = member["id"].split("::")
            if owns(tranche, file_name, class_name, method):
                picked.append(migration)
                break
    return picked


def _member_owned(tranche, member):
    file_name, class_name, method, _ = member["id"].split("::")
    return owns(tranche, file_name, class_name, method)


def reconstruct_accepted_contracts(root, tranche, live_window_entries):
    """Undo the recorded migrations against the live window.

    Each side is filtered by whether THIS window owns it, which is what lets an
    accepted contract move to another method or range: the losing window adds its
    retired contract back and ignores a successor that landed outside it, while the
    window the successor landed in subtracts it and ignores the retired side. A
    successor this window DOES own must be present, so a wrong or invented in-window
    successor still cannot silently balance the equation.
    """
    contracts = window_contracts(live_window_entries)
    for migration in migrations_for(root, tranche):
        for successor in migration["successors"]:
            if not _member_owned(tranche, successor):
                continue
            contract = _member_contract(successor)
            if contract not in contracts:
                raise LookupError(
                    f"{migration['id']}: successor {successor['id']} is not a live "
                    f"contract of accepted tranche {tranche}")
            contracts.remove(contract)
        for retired in migration["retired"]:
            if _member_owned(tranche, retired):
                contracts.append(_member_contract(retired))
    return contracts


def successor_reference_failures(root, entries=None):
    """Successor ids are load-bearing, not decoration: each must name exactly one
    live entry whose file/class/method/targets match the member.

    The asymmetry is deliberate. A SUCCESSOR is a claim about the CURRENT tree, so it
    is checked against it exactly. A RETIRED member is a historical locator only --
    its ordinal belonged to a state that no longer exists -- so its semantic identity
    is the contract (file, class, method, targets) and its id is never required to
    exist now. Requiring retired ids to resolve would re-freeze exactly the ordinal
    identity this tranche exists to release.
    """
    entries = live_entries(root) if entries is None else entries
    by_id = {}
    for entry in entries:
        by_id.setdefault(entry["id"], []).append(entry)
    problems = []
    for migration in load_migrations(root)["migrations"]:
        for member in migration["successors"]:
            found = by_id.get(member["id"], [])
            if len(found) != 1:
                problems.append(f"{migration['id']}:successor-id-resolves-to-{len(found)}"
                                f"-live-entries:{member['id']}")
                continue
            entry, parts = found[0], member["id"].split("::")
            if [entry["file"], entry["class"], entry["method"]] != parts[:3]:
                problems.append(f"{migration['id']}:successor-id-does-not-match-its-entry:"
                                f"{member['id']}")
            if entry["targets"] != member["targets"]:
                problems.append(f"{migration['id']}:successor-targets-mismatch:"
                                f"{member['id']} {member['targets']} != {entry['targets']}")
    return problems


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
    seen_ids, pools = set(), {"retired": set(), "successors": set()}
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
        for side in ("retired", "successors"):
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
                if mid in pools[side]:
                    problems.append(f"{label}:{side}-id-claimed-twice:{mid}")
                pools[side].add(mid)
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
    """Every contract the tranche accepted is still live, or explicitly retired by a
    recorded migration. One-to-one conversion and pure ordinal drift need NO entry; a
    split, merge or retarget passes only once recorded; a silent deletion cannot."""
    entries = live_entries(root)
    case.assertEqual(window_boundary_failures(root, tranche, entries), [])
    case.assertEqual(successor_reference_failures(root, entries), [])
    scope, window = accepted_window(root, tranche, entries)
    rebuilt = reconstruct_accepted_contracts(root, tranche, window)
    case.assertEqual(
        contracts_digest(scope, rebuilt), accepted(root, tranche)["historical"]["contracts_digest"],
        f"{tranche}: accepted contracts are not accounted for by the live window plus the "
        f"recorded migrations ({len(window)} live, {len(rebuilt)} reconstructed)")


def assert_accepted(case, root, tranche, **historical):
    """Both halves at one call site: accepted facts from the offline ledger, and the
    current tree still accounting for every accepted contract."""
    case.assertEqual(accepted_scopes_digest(), ACCEPTED_SCOPES_DIGEST)
    record = assert_accepted_history(case, root, tranche, **historical)
    assert_accepted_contracts_accounted_for(case, root, tranche)
    return record
