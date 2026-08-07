#!/usr/bin/env python3
"""BL-038 tranche 3f: declared-scope/count structural guard for
document_test_classification.json, now spanning test_custom_domain.py
(tranche 3b, 97 entries, unchanged), test_ui_spec.py (tranche 3c, 185
entries, unchanged), test_status.py (tranche 3d, 98 entries, unchanged),
and test_security_requirements.py (tranche 3e's 143 entries, unchanged,
plus tranche 3f's 62 new Bl031AcceptanceAndBl032RegistrationTest entries
= 205).

Tranche 3f adds Bl031AcceptanceAndBl032RegistrationTest to the existing
test_security_requirements.py scope entry, placed FIRST because its
`class` statement precedes Bl034Round2ReviewCorrectionsTest's in the
source file -- every scoped file's declared class order equals its file
source order. enumerate_assertions() walks that tuple in order, so the
62 new entries land in the corresponding manifest block and all 523
pre-existing entries stay byte-identical and in unchanged order.

document_test_inventory.py's validator can only check a manifest against
whatever scope it *declares* -- it cannot detect a class/file being
silently removed from that declared scope (both `scope` and the matching
`assertions` shrinking together, staying internally consistent), nor can
it detect the two scoped files being silently reordered. This suite pins
the expected scope/class-set/count/order as *hardcoded literals*,
independent of whatever the manifest file currently says, so scope
shrinkage or reordering is caught here even though the validator alone
would not catch it (tranche 3b round 1, Blocker 4: `_assert_expected_scope()`
is exercised both directly and against deliberately-mutated copies,
demonstrated not just asserted).

Tranche 3g adds no classification at all. It introduces the explicit
shard index (document_test_classification_index.json) that lets FUTURE
classification go into an additional shard, and pins here that the base
manifest is still byte-for-byte what origin/main holds, that the index
lists it exactly once, and that the combined (index-driven) result is
identical to the single-manifest result.
"""

import ast
import hashlib
import itertools
import json
import re
import unittest
from collections import Counter, OrderedDict
from pathlib import Path

import document_test_inventory as dti

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "document_test_classification.json"
INDEX_PATH = ROOT / dti.INDEX_FILENAME
# The manifest as accepted and merged in PR #88 (merge commit 66ef88e5).
# Sharding exists so the 585 classified entries never have to move.
BASE_MANIFEST_SHA256 = "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a"
BASE_MANIFEST_LINE_COUNT = 596
BASE_MANIFEST_LINE_CAP = 600

CUSTOM_DOMAIN_SOURCE_FILE = "test_custom_domain.py"
UI_SPEC_SOURCE_FILE = "test_ui_spec.py"
STATUS_SOURCE_FILE = "test_status.py"
SECURITY_REQUIREMENTS_SOURCE_FILE = "test_security_requirements.py"
SCOPE_FILES = (
    CUSTOM_DOMAIN_SOURCE_FILE, UI_SPEC_SOURCE_FILE, STATUS_SOURCE_FILE, SECURITY_REQUIREMENTS_SOURCE_FILE,
)

# Hardcoded literal contracts -- NOT derived from the manifest or from a
# live AST scan. This, and the exact scope ORDER below, is what makes
# scope shrinkage/reordering detectable.
CUSTOM_DOMAIN_EXPECTED_CLASSES = (
    "DocsCnameFileTest",
    "CnameSurvivesGenerationTest",
    "ArticleBriefContractUnchangedTest",
    "Bl007DocumentationTest",
    "ReadmePublicUrlTest",
    "Bl007ClosureRecordTest",
    "TicketIdTypoTest",
)
UI_SPEC_EXPECTED_CLASSES = (
    "UiSpecDocumentTest",
    "Bl036ArticleAttributionUiSpecTest",
)
STATUS_EXPECTED_CLASSES = (
    "StatusSourceOfTruthTest",
    "Sd031DecisionTest",
    "Bl035ActiveWorkTest",
    "StatusSecurityOperationsSourceOfTruthTest",
    "Bl036PostMergeRecordFixTest",
    "Bl036ProductionEvidenceSyncTest",
)
SECURITY_REQUIREMENTS_EXPECTED_CLASSES = (
    # Tranche 3f's class, first because it is first in the source file.
    "Bl031AcceptanceAndBl032RegistrationTest",
    "Bl034Round2ReviewCorrectionsTest",
    "Bl034ImplementationAcceptanceTest",
    "Bl034CloseoutTest",
    "StatusSecurityRequirementsSourceOfTruthTest",
)
EXPECTED_SCOPE_ORDER = (
    (CUSTOM_DOMAIN_SOURCE_FILE, CUSTOM_DOMAIN_EXPECTED_CLASSES),
    (UI_SPEC_SOURCE_FILE, UI_SPEC_EXPECTED_CLASSES),
    (STATUS_SOURCE_FILE, STATUS_EXPECTED_CLASSES),
    (SECURITY_REQUIREMENTS_SOURCE_FILE, SECURITY_REQUIREMENTS_EXPECTED_CLASSES),
)

CUSTOM_DOMAIN_EXPECTED_ASSERTION_COUNT = 97
UI_SPEC_EXPECTED_ASSERTION_COUNT = 185
STATUS_EXPECTED_ASSERTION_COUNT = 98
SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT = 205  # 143 (tranche 3e) + 62 (tranche 3f)
BASE_EXPECTED_ASSERTION_COUNT = (
    CUSTOM_DOMAIN_EXPECTED_ASSERTION_COUNT
    + UI_SPEC_EXPECTED_ASSERTION_COUNT
    + STATUS_EXPECTED_ASSERTION_COUNT
    + SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT
)

# Tranche 3b's exact per-ID category membership record -- content
# UNCHANGED from tranche 3b, only renamed (from EXPECTED_A_IDS etc.) for
# clarity now that a second file shares this module. Round 2 review,
# Blocker 3: category *counts* alone cannot catch a B/C entry being
# swapped for another B/C entry (counts stay the same). The manifest is a
# human-reviewed per-assertion record, so A/C/D membership is pinned as
# hardcoded literal ID sets -- B is checked as the exact remainder.
CUSTOM_DOMAIN_EXPECTED_A_IDS = frozenset({
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_cname_survives_generate_archive_outputs::assert-01",
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_cname_survives_generate_archive_outputs::assert-02",
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_cname_survives_repeated_full_archive_regeneration::assert-01",
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_cname_survives_repeated_full_archive_regeneration::assert-02",
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_atomic_write_text_never_touches_sibling_files::assert-01",
    "test_custom_domain.py::CnameSurvivesGenerationTest::test_atomic_write_text_never_touches_sibling_files::assert-02",
    "test_custom_domain.py::Bl007DocumentationTest::test_no_wildcard_dns_is_instructed_anywhere_in_bl007::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_retains_ownership_txt_and_forbids_wildcard::assert-02",
})
CUSTOM_DOMAIN_EXPECTED_C_IDS = frozenset({
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-02",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-03",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-04",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-05",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-06",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-07",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-08",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-09",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_does_not_infer_domain_as_unacquired::assert-03",
    "test_custom_domain.py::Bl007DocumentationTest::test_sd011_status_is_unchanged::assert-02",
    "test_custom_domain.py::Bl007DocumentationTest::test_sd028_records_the_implementation_decision::assert-03",
    "test_custom_domain.py::Bl007DocumentationTest::test_sd028_records_the_implementation_decision::assert-04",
    "test_custom_domain.py::Bl007DocumentationTest::test_no_wildcard_dns_is_instructed_anywhere_in_bl007::assert-02",
    "test_custom_domain.py::ReadmePublicUrlTest::test_readme_does_not_embed_runbook_or_dns_details::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_distinguishes_its_own_work_from_the_scheduled_run::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_distinguishes_its_own_work_from_the_scheduled_run::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_distinguishes_its_own_work_from_the_scheduled_run::assert-03",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_context_is_historical_not_current::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_context_is_historical_not_current::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_approved_plan_as_a_separate_history_item::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_approved_plan_as_a_separate_history_item::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_approved_plan_as_a_separate_history_item::assert-03",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_actual_automatic_activation_order_separately::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_actual_automatic_activation_order_separately::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_actual_automatic_activation_order_separately::assert-03",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_does_not_claim_the_plan_was_executed_as_planned::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_does_not_claim_the_plan_was_executed_as_planned::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_no_unintended_commit_from_custom_domain_activation::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_and_sd028_observed_facts_do_not_contradict::assert-03",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_and_sd028_observed_facts_do_not_contradict::assert-04",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_and_sd028_observed_facts_do_not_contradict::assert-05",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_and_sd028_observed_facts_do_not_contradict::assert-06",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_retains_ownership_txt_and_forbids_wildcard::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_does_not_retain_stale_pre_closure_wording::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_does_not_retain_stale_pre_closure_wording::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_https_enforced_and_certificate_approved::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_https_enforced_and_certificate_approved::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_https_enforced_and_certificate_approved::assert-03",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_cname_merge_activation_as_an_observation_not_a_guarantee::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_cname_merge_activation_as_an_observation_not_a_guarantee::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_records_minimal_dns_with_no_wildcard::assert-01",
})
CUSTOM_DOMAIN_EXPECTED_D_IDS = frozenset({
    "test_custom_domain.py::DocsCnameFileTest::test_cname_content_is_exactly_the_apex_domain_with_trailing_newline::assert-01",
    "test_custom_domain.py::ArticleBriefContractUnchangedTest::test_article_and_brief_prompt_versions_are_unchanged::assert-01",
    "test_custom_domain.py::ArticleBriefContractUnchangedTest::test_article_and_brief_prompt_versions_are_unchanged::assert-02",
    "test_custom_domain.py::ArticleBriefContractUnchangedTest::test_daily_json_schema_version_is_unchanged::assert-01",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-10",
    "test_custom_domain.py::Bl007DocumentationTest::test_bl007_is_recorded_as_complete_with_confirmed_policy::assert-11",
    "test_custom_domain.py::Bl007DocumentationTest::test_status_records_bl007_as_recently_completed::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_bl007_records_the_scheduled_run_commit_sha::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_evidence_records_merge_commit_and_public_state::assert-01",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_evidence_records_merge_commit_and_public_state::assert-02",
    "test_custom_domain.py::Bl007ClosureRecordTest::test_sd028_evidence_records_merge_commit_and_public_state::assert-03",
})
assert not (CUSTOM_DOMAIN_EXPECTED_A_IDS & CUSTOM_DOMAIN_EXPECTED_C_IDS)
assert not (CUSTOM_DOMAIN_EXPECTED_A_IDS & CUSTOM_DOMAIN_EXPECTED_D_IDS)
assert not (CUSTOM_DOMAIN_EXPECTED_C_IDS & CUSTOM_DOMAIN_EXPECTED_D_IDS)
CUSTOM_DOMAIN_EXPECTED_CATEGORY_COUNTS = {
    "A": len(CUSTOM_DOMAIN_EXPECTED_A_IDS),
    "B": CUSTOM_DOMAIN_EXPECTED_ASSERTION_COUNT
    - len(CUSTOM_DOMAIN_EXPECTED_A_IDS)
    - len(CUSTOM_DOMAIN_EXPECTED_C_IDS)
    - len(CUSTOM_DOMAIN_EXPECTED_D_IDS),
    "C": len(CUSTOM_DOMAIN_EXPECTED_C_IDS),
    "D": len(CUSTOM_DOMAIN_EXPECTED_D_IDS),
}

# Tranche 3c's exact per-ID category membership record for test_ui_spec.py,
# built the same way as tranche 3b's: A/C/D pinned as hardcoded literal ID
# sets, B checked as the exact remainder of the 185 UI-spec IDs.
UI_SPEC_EXPECTED_A_IDS = frozenset({
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_sd016_and_user_adjudication_are_recorded_verbatim::assert-01",
    "test_ui_spec.py::UiSpecDocumentTest::test_sd016_and_user_adjudication_are_recorded_verbatim::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_version_is_17_approved_with_acceptance_date::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_version_is_17_approved_with_acceptance_date::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_version_is_17_approved_with_acceptance_date::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-02",
})
UI_SPEC_EXPECTED_C_IDS = frozenset({
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-07",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-08",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-09",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-10",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-11",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-13",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-14",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-15",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-16",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-18",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-19",
    "test_ui_spec.py::UiSpecDocumentTest::test_confirmed_axis_and_related_tag_contracts_are_explicit::assert-01",
    "test_ui_spec.py::UiSpecDocumentTest::test_confirmed_axis_and_related_tag_contracts_are_explicit::assert-02",
    "test_ui_spec.py::UiSpecDocumentTest::test_confirmed_axis_and_related_tag_contracts_are_explicit::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_confirmed_axis_and_related_tag_contracts_are_explicit::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_confirmed_axis_and_related_tag_contracts_are_explicit::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-07",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-08",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-09",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-10",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-11",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-12",
    "test_ui_spec.py::UiSpecDocumentTest::test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain::assert-13",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-02",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-09",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-17",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-18",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-01",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-02",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-07",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-11",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-12",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-13",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-06",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-07",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-13",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-14",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-17",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-18",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-20",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-24",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-28",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_original_ai_note_ban_sentences_are_preserved_not_deleted::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_original_ai_note_ban_sentences_are_preserved_not_deleted::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_maintained_policy_bans_generic_ai_badge_and_uniform_note::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_maintained_policy_bans_generic_ai_badge_and_uniform_note::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_maintained_policy_bans_generic_ai_badge_and_uniform_note::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_maintained_policy_bans_generic_ai_badge_and_uniform_note::assert-04",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_source_policy_required_attribution_is_recorded_as_a_confirmed_limited_exception::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_source_policy_required_attribution_is_recorded_as_a_confirmed_limited_exception::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_source_policy_required_attribution_is_recorded_as_a_confirmed_limited_exception::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_source_policy_required_attribution_is_recorded_as_a_confirmed_limited_exception::assert-07",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_runtime_attribution_is_already_implemented_and_bl036_only_added_css::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_runtime_attribution_is_already_implemented_and_bl036_only_added_css::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_css_current_values_are_recorded_for_pc_and_390px_both::assert-05",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_css_current_values_are_recorded_for_pc_and_390px_both::assert-06",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_no_contradictory_no_change_claim_near_the_limited_exception::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_no_contradictory_no_change_claim_near_the_limited_exception::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_no_pending_or_draft_current_state_wording_remains_for_the_exception::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_no_pending_or_draft_current_state_wording_remains_for_the_exception::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_no_pending_or_draft_current_state_wording_remains_for_the_exception::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_user_original_text_and_interpretation_are_recorded_separately::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_user_original_text_and_interpretation_are_recorded_separately::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause::assert-05",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause::assert-06",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-04",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-07",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-08",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_bl036_is_recorded_as_complete_without_r04_r13_bl009_contamination::assert-03",
})
UI_SPEC_EXPECTED_D_IDS = frozenset({
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-12",
    "test_ui_spec.py::UiSpecDocumentTest::test_ui_spec_exists_with_version_metadata::assert-17",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-08",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-10",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-11",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-12",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl022_previous_digest_link_is_an_approved_responsive_contract::assert-14",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl020_source_footer_is_plain_user_accepted_and_complete::assert-10",
    "test_ui_spec.py::UiSpecDocumentTest::test_sd016_and_user_adjudication_are_recorded_verbatim::assert-03",
    "test_ui_spec.py::UiSpecDocumentTest::test_sd016_and_user_adjudication_are_recorded_verbatim::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_sd016_and_user_adjudication_are_recorded_verbatim::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-02",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-08",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-09",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-10",
    "test_ui_spec.py::UiSpecDocumentTest::test_bl004_is_complete_with_original_evidence_unchanged::assert-11",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-02",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-04",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-05",
    "test_ui_spec.py::UiSpecDocumentTest::test_status_completes_bl004_bl021_and_bl022::assert-21",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_css_current_values_are_recorded_for_pc_and_390px_both::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_css_current_values_are_recorded_for_pc_and_390px_both::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_css_current_values_are_recorded_for_pc_and_390px_both::assert-04",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_screenshot_filenames_and_evidence_are_recorded::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_screenshot_filenames_and_evidence_are_recorded::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_user_original_text_and_interpretation_are_recorded_separately::assert-01",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause::assert-02",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause::assert-11",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause::assert-12",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_sd016_historical_body_is_preserved_and_notes_partial_supersession::assert-03",
    "test_ui_spec.py::Bl036ArticleAttributionUiSpecTest::test_status_active_work_excludes_and_recently_completed_includes_bl036::assert-04",
})
assert not (UI_SPEC_EXPECTED_A_IDS & UI_SPEC_EXPECTED_C_IDS)
assert not (UI_SPEC_EXPECTED_A_IDS & UI_SPEC_EXPECTED_D_IDS)
assert not (UI_SPEC_EXPECTED_C_IDS & UI_SPEC_EXPECTED_D_IDS)
UI_SPEC_EXPECTED_CATEGORY_COUNTS = {
    "A": len(UI_SPEC_EXPECTED_A_IDS),
    "B": UI_SPEC_EXPECTED_ASSERTION_COUNT
    - len(UI_SPEC_EXPECTED_A_IDS)
    - len(UI_SPEC_EXPECTED_C_IDS)
    - len(UI_SPEC_EXPECTED_D_IDS),
    "C": len(UI_SPEC_EXPECTED_C_IDS),
    "D": len(UI_SPEC_EXPECTED_D_IDS),
}

# Tranche 3d's exact per-ID category membership record for test_status.py,
# built the same way as tranche 3b/3c: A/C/D pinned as hardcoded literal ID
# sets, B checked as the exact remainder of the 98 test_status.py IDs.
STATUS_EXPECTED_A_IDS = frozenset({
})
STATUS_EXPECTED_C_IDS = frozenset({
    "test_status.py::StatusSourceOfTruthTest::test_source_of_truth_row_defers_to_referenced_daily_json::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_source_of_truth_row_points_production_commit_to_git_history::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_as_of_is_document_update_date_not_production_run_date::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_as_of_is_document_update_date_not_production_run_date::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_generator_contract_source_of_truth::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_generator_contract_source_of_truth::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_referenced_daily_json_source_of_truth::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_production_commit_source_of_truth::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_production_commit_source_of_truth::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_states_no_daily_value_duplication::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_treats_past_runs_as_historical_not_latest::assert-01",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_treats_past_runs_as_historical_not_latest::assert-02",
    "test_status.py::StatusSourceOfTruthTest::test_current_versions_paragraph_does_not_reintroduce_the_deleted_row_as_current::assert-01",
    "test_status.py::Sd031DecisionTest::test_sd031_decision_records_source_of_truth_delegation::assert-03",
    "test_status.py::Sd031DecisionTest::test_sd031_decision_records_source_of_truth_delegation::assert-04",
    "test_status.py::Sd031DecisionTest::test_sd031_decision_records_source_of_truth_delegation::assert-05",
    "test_status.py::Bl035ActiveWorkTest::test_recently_completed_bl035_entry_records_required_content::assert-01",
    "test_status.py::Bl035ActiveWorkTest::test_recently_completed_bl035_entry_records_required_content::assert-02",
    "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_row_delegates_to_security_operations_header_not_a_fixed_version_or_status::assert-02",
    "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_row_delegates_to_security_operations_header_not_a_fixed_version_or_status::assert-03",
    "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_row_delegates_to_security_operations_header_not_a_fixed_version_or_status::assert-06",
    "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_row_delegates_to_security_operations_header_not_a_fixed_version_or_status::assert-07",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_no_longer_contains_stale_pending_current_state_wording::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_records_sd033_partial_supersession_as_confirmed::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_records_sd033_partial_supersession_as_confirmed::assert-04",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-09",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_note_does_not_claim_decisions_untouched::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_note_does_not_claim_decisions_untouched::assert-02",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_no_longer_claims_current_state_is_pending_next_production::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_no_longer_claims_current_state_is_pending_next_production::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_distinguishes_independent_scheduled_production_from_bl036_manual_work::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_distinguishes_independent_scheduled_production_from_bl036_manual_work::assert-02",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_distinguishes_independent_scheduled_production_from_bl036_manual_work::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_distinguishes_independent_scheduled_production_from_bl036_manual_work::assert-02",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_no_longer_contains_unqualified_no_production_claim::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_no_longer_contains_unqualified_no_production_claim::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_bl036_scopes_the_no_manual_production_claim_to_bl036_work::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_scopes_the_no_manual_production_claim_to_bl036_work::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_scopes_the_no_manual_production_claim_to_bl036_work::assert-02",
})
STATUS_EXPECTED_D_IDS = frozenset({
    "test_status.py::StatusSourceOfTruthTest::test_current_generator_schema_on_main_is_still_2::assert-01",
    "test_status.py::Sd031DecisionTest::test_sd031_records_date_and_status::assert-01",
    "test_status.py::Sd031DecisionTest::test_sd031_evidence_includes_bl033_commit_and_prs::assert-02",
    "test_status.py::Sd031DecisionTest::test_sd031_evidence_includes_bl033_commit_and_prs::assert-03",
    "test_status.py::Sd031DecisionTest::test_sd031_evidence_includes_bl033_commit_and_prs::assert-04",
    "test_status.py::StatusSecurityOperationsSourceOfTruthTest::test_security_operations_itself_reflects_bl035_final_acceptance::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_as_of_is_20260804::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-01",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-02",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-03",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-04",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-05",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-06",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-07",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-08",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-09",
    "test_status.py::Bl036PostMergeRecordFixTest::test_status_bl036_entry_distinguishes_implementation_and_final_evidence::assert-10",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_records_sd033_partial_supersession_as_confirmed::assert-03",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-02",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-04",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-05",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-06",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-07",
    "test_status.py::Bl036PostMergeRecordFixTest::test_backlog_bl036_distinguishes_accepted_implementation_and_final_files::assert-08",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_bl036_line_records_production_commit_and_pages_run::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_status_bl036_line_records_production_commit_and_pages_run::assert-02",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_records_production_commit_and_pages_run::assert-01",
    "test_status.py::Bl036ProductionEvidenceSyncTest::test_backlog_bl036_records_production_commit_and_pages_run::assert-02",
})
assert not (STATUS_EXPECTED_A_IDS & STATUS_EXPECTED_C_IDS)
assert not (STATUS_EXPECTED_A_IDS & STATUS_EXPECTED_D_IDS)
assert not (STATUS_EXPECTED_C_IDS & STATUS_EXPECTED_D_IDS)
STATUS_EXPECTED_CATEGORY_COUNTS = {
    "A": len(STATUS_EXPECTED_A_IDS),
    "B": STATUS_EXPECTED_ASSERTION_COUNT
    - len(STATUS_EXPECTED_A_IDS)
    - len(STATUS_EXPECTED_C_IDS)
    - len(STATUS_EXPECTED_D_IDS),
    "C": len(STATUS_EXPECTED_C_IDS),
    "D": len(STATUS_EXPECTED_D_IDS),
}

# Tranche 3e's and 3f's per-ID category membership record for
# test_security_requirements.py, built like 3b/3c/3d: A/C/D pinned as
# literal ID sets, B checked as the exact remainder of the 205 IDs.
#
# Category A policy is unchanged: a repeated structural pattern with clear
# shared-helper-consolidation value, NOT merely a recurring exact/fixed
# value re-anchored at different checkpoints. Tranche 3e's four classes
# yielded zero (their 17 fingerprint-duplicate groups are recurring values
# inside otherwise-distinct methods, correctly left B/C/D). Tranche 3f
# yields four of the other kind: the two sd002/sd030 methods are the SAME
# assertions over the SAME extractions, differing only in statement order.
#
# PR #86 round 1 review correction: 12 entries initially misclassified B
# were moved -- 9 to C (raw negative multi-token substrings like "session
# count"/"remain unconfirmed"; a stylistic ID-range embedded in prose,
# "GAP-016-GAP-017"; a raw noun-compound not extracted to a field,
# "所有権確認成功"; a multi-word phrase with a common-noun suffix,
# "Cloudflare Web Analytics dashboard"; a mixed atomic/noun-phrase
# loop-based check) and 3 to D (bare "PR #NN" mentions that are
# substrings of this document's always-fully-linked PR references,
# `[PR #NN](url)` -- matching this manifest's own established precedent
# that PR references are C or D, never B -- and/or part of the same
# historical-acceptance-evidence bundle as a sibling SHA/CI-run-ID
# assertion in the same method). See BACKLOG.md's tranche 3e round 1 fix
# paragraph for the full per-ID reasoning.
SECURITY_REQUIREMENTS_EXPECTED_A_IDS = frozenset({
    # Tranche 3f: the one duplicated-method pair in this file.
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_does_not_mark_sd002_as_implemented_superseded::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_does_not_mark_sd002_as_implemented_superseded::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030::assert-02",
})
SECURITY_REQUIREMENTS_EXPECTED_C_IDS = frozenset({
    # Tranche 3f (Bl031AcceptanceAndBl032RegistrationTest, 33 entries).
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_status_is_completed::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_status_is_completed::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_status_is_completed::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_is_registered_exactly_once::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_is_unique_and_records_approval_deferral_boundary::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_is_unique_and_records_approval_deferral_boundary::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-05",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-06",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-08",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-05",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_completion_condition_6_requires_changing_rich_content_not_preserving_it::assert-06",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_describes_metadata_only_and_limited_feed_analysis_as_policy_requirements::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_describes_metadata_only_and_limited_feed_analysis_as_policy_requirements::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_describes_metadata_only_and_limited_feed_analysis_as_policy_requirements::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_describes_metadata_only_and_limited_feed_analysis_as_policy_requirements::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-05",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-06",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-08",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-09",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-10",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_status_bl030_entry_no_longer_lists_bl031_as_a_follow_up_candidate::assert-11",
    # Tranche 3e (unchanged).
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_version_17_intro_does_not_deny_the_sr044_046_gap016_017_sync::assert-02",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_version_17_intro_does_not_deny_the_sr044_046_gap016_017_sync::assert-03",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_version_17_intro_does_not_deny_the_sr044_046_gap016_017_sync::assert-04",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sr045_no_longer_says_enforcement_remains_deferred_to_bl032::assert-01",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sr045_no_longer_says_enforcement_remains_deferred_to_bl032::assert-02",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_gap017_does_not_call_bl032_merely_registered::assert-01",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_gap017_does_not_call_bl032_merely_registered::assert-02",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-01",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-02",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-03",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-04",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-05",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_sd032_visits_description_has_no_session_language::assert-06",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_has_no_residual_work_after_closeout::assert-01",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_has_no_residual_work_after_closeout::assert-02",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_has_no_residual_work_after_closeout::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl009_remains_the_in_progress_umbrella::assert-01",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_sd032_is_accepted::assert-02",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_security_requirements_version_17_is_approved_and_current_baseline::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_version_16_historical_draft_record_is_preserved::assert-01",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_version_16_historical_draft_record_is_preserved::assert-02",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_dashboard_and_search_console_are_confirmed_by_closeout::assert-01",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_dashboard_and_search_console_are_confirmed_by_closeout::assert-02",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_dashboard_and_search_console_are_confirmed_by_closeout::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_dashboard_and_search_console_are_confirmed_by_closeout::assert-04",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_dashboard_and_search_console_are_confirmed_by_closeout::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl034_is_complete_with_no_residual_work::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-07",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-08",
    "test_security_requirements.py::Bl034CloseoutTest::test_google_verification_txt_value_is_not_present_anywhere::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_google_verification_txt_value_is_not_present_anywhere::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_google_verification_txt_value_is_not_present_anywhere::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl009_is_still_the_in_progress_umbrella_with_full_scope::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl009_is_still_the_in_progress_umbrella_with_full_scope::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_status_recently_completed_records_bl034::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_status_recently_completed_records_bl034::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-08",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-09",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-10",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_and_gap018_confirm_dashboard_and_search_console_not_unconfirmed::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_section_12_records_closeout_without_reapproving_or_version_bumping::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_section_12_records_closeout_without_reapproving_or_version_bumping::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_section_12_records_closeout_without_reapproving_or_version_bumping::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_site_registration_and_snippet_predate_acceptance::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_site_registration_and_snippet_predate_acceptance::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_site_registration_and_snippet_predate_acceptance::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_site_registration_and_snippet_predate_acceptance::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_site_registration_and_snippet_predate_acceptance::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_sr047_distinguishes_dns_provider_unchanged_from_new_google_txt_record::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_bl032_control_mapping_no_longer_calls_documentation_gap_unresolved::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-06",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_status::assert-05",
    "test_security_requirements.py::StatusSecurityRequirementsSourceOfTruthTest::test_row_delegates_to_security_requirements_header_not_a_fixed_version::assert-04",
    "test_security_requirements.py::StatusSecurityRequirementsSourceOfTruthTest::test_row_delegates_to_security_requirements_header_not_a_fixed_version::assert-05",
})
SECURITY_REQUIREMENTS_EXPECTED_D_IDS = frozenset({
    # Tranche 3f (Bl031AcceptanceAndBl032RegistrationTest, 14 entries).
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version::assert-06",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-01",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-04",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-05",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl031_backlog_acceptance_evidence_is_recorded::assert-06",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_checked_at_dates_are_not_bulk_changed::assert-02",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_source_usage_policy_checked_at_dates_are_not_bulk_changed::assert-03",
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_bl032_residual_work_records_operational_observation_as_succeeded::assert-02",
    # Locked as D by BL-038 tranche 2 (BACKLOG.md's classification table and
    # test_fetch.Bl038Tranche2RecordSyncTest); preserved unchanged here.
    "test_security_requirements.py::Bl031AcceptanceAndBl032RegistrationTest::test_sd030_records_that_mode_restrictions_are_not_yet_enforced_in_production::assert-04",
    # Tranche 3e (unchanged).
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_version_17_is_the_current_draft_and_16_is_not_called_this_version::assert-01",
    "test_security_requirements.py::Bl034Round2ReviewCorrectionsTest::test_gap017_does_not_call_bl032_merely_registered::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-02",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-04",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-05",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-06",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_sd032_is_accepted::assert-03",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_sd032_is_accepted::assert-04",
    "test_security_requirements.py::Bl034ImplementationAcceptanceTest::test_security_requirements_version_17_is_approved_and_current_baseline::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_cloudflare_dashboard_and_search_console_are_confirmed::assert-09",
    "test_security_requirements.py::Bl034CloseoutTest::test_measurement_start_date_is_20260803::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_status_recently_completed_records_bl034::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_status_recently_completed_records_bl034::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_status_recently_completed_records_bl034::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_sd032_status_is_still_accepted::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_security_requirements_version_17_approved_is_unchanged_by_closeout::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_intro_no_longer_claims_no_external_confirmations_have_occurred::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_section_12_records_closeout_without_reapproving_or_version_bumping::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_backlog::assert-05",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_status::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_status::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_status::assert-03",
    "test_security_requirements.py::Bl034CloseoutTest::test_pr73_final_acceptance_is_recorded_in_status::assert-04",
    "test_security_requirements.py::Bl034CloseoutTest::test_final_acceptance_record_does_not_touch_out_of_scope_documents::assert-01",
    "test_security_requirements.py::Bl034CloseoutTest::test_final_acceptance_record_does_not_touch_out_of_scope_documents::assert-02",
    "test_security_requirements.py::Bl034CloseoutTest::test_final_acceptance_record_does_not_touch_out_of_scope_documents::assert-03",
    "test_security_requirements.py::StatusSecurityRequirementsSourceOfTruthTest::test_security_requirements_itself_is_unchanged_by_this_fix::assert-01",
})
assert not (SECURITY_REQUIREMENTS_EXPECTED_A_IDS & SECURITY_REQUIREMENTS_EXPECTED_C_IDS)
assert not (SECURITY_REQUIREMENTS_EXPECTED_A_IDS & SECURITY_REQUIREMENTS_EXPECTED_D_IDS)
assert not (SECURITY_REQUIREMENTS_EXPECTED_C_IDS & SECURITY_REQUIREMENTS_EXPECTED_D_IDS)
SECURITY_REQUIREMENTS_EXPECTED_CATEGORY_COUNTS = {
    "A": len(SECURITY_REQUIREMENTS_EXPECTED_A_IDS),
    "B": SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT
    - len(SECURITY_REQUIREMENTS_EXPECTED_A_IDS)
    - len(SECURITY_REQUIREMENTS_EXPECTED_C_IDS)
    - len(SECURITY_REQUIREMENTS_EXPECTED_D_IDS),
    "C": len(SECURITY_REQUIREMENTS_EXPECTED_C_IDS),
    "D": len(SECURITY_REQUIREMENTS_EXPECTED_D_IDS),
}

BASE_EXPECTED_CATEGORY_COUNTS = {
    cat: CUSTOM_DOMAIN_EXPECTED_CATEGORY_COUNTS[cat]
    + UI_SPEC_EXPECTED_CATEGORY_COUNTS[cat]
    + STATUS_EXPECTED_CATEGORY_COUNTS[cat]
    + SECURITY_REQUIREMENTS_EXPECTED_CATEGORY_COUNTS[cat]
    for cat in ("A", "B", "C", "D")
}
# The four files' IDs are disjoint by construction (each id is prefixed
# with its own file name), so the combined exact-membership guard is a
# plain union -- this is what keeps tranche 3b/3c/3d's per-ID record in
# force unweakened after the manifest grew to a fourth file.
BASE_EXPECTED_A_IDS = (
    CUSTOM_DOMAIN_EXPECTED_A_IDS | UI_SPEC_EXPECTED_A_IDS | STATUS_EXPECTED_A_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_A_IDS
)
BASE_EXPECTED_C_IDS = (
    CUSTOM_DOMAIN_EXPECTED_C_IDS | UI_SPEC_EXPECTED_C_IDS | STATUS_EXPECTED_C_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_C_IDS
)
BASE_EXPECTED_D_IDS = (
    CUSTOM_DOMAIN_EXPECTED_D_IDS | UI_SPEC_EXPECTED_D_IDS | STATUS_EXPECTED_D_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_D_IDS
)


# BL-038 tranche 3h: the FIRST additional shard, owning
# test_security_operations.py's first two classes and nothing else. The base
# manifest above stays frozen -- its 585/596/A22 B175 C268 D120 record is
# never re-derived from, merged with, or overwritten by anything below.
SHARD_001_FILENAME = "document_test_classification_001.json"
SHARD_001_PATH = ROOT / SHARD_001_FILENAME
SHARD_001_SOURCE_FILE = "test_security_operations.py"
_SO = SHARD_001_SOURCE_FILE + "::"

# Source order. The file's third class, Bl035DraftSyncTest (34), is
# deliberately excluded: all three would be 170, over the 150 tranche cap.
SHARD_001_EXPECTED_CLASSES = (
    "SecurityOperationsContractTest",
    "Bl031SecurityOperationsReconciliationTest",
)
SHARD_001_UNOWNED_CLASS = "Bl035DraftSyncTest"
SHARD_001_EXPECTED_ASSERTION_COUNT = 136
SHARD_001_EXPECTED_METHOD_COUNT = 24
SHARD_001_EXPECTED_LINE_COUNT = 144

# Hardcoded (class, method, count) in source order; expanding it yields the
# shard's whole ordered id list from literals alone, so a dropped/reordered/
# shrunken method is caught even when manifest and source still agree.
SHARD_001_EXPECTED_METHOD_ORDER = (
    # SecurityOperationsContractTest
    ("SecurityOperationsContractTest", "test_version_10_identity_review_record_and_user_approval", 5),
    ("SecurityOperationsContractTest", "test_requirements_and_decision_references", 1),
    ("SecurityOperationsContractTest", "test_canonical_secret_prohibition_is_unconditional", 6),
    ("SecurityOperationsContractTest", "test_approved_secret_stores_are_not_mistaken_for_evidence", 5),
    ("SecurityOperationsContractTest", "test_only_non_secret_data_can_use_an_approved_artifact_exception", 3),
    ("SecurityOperationsContractTest", "test_rotation_has_immediate_and_controlled_paths", 8),
    ("SecurityOperationsContractTest", "test_nvd_secret_state_has_owner_verification_evidence", 8),
    ("SecurityOperationsContractTest", "test_github_account_compromise_and_published_secret_containment", 7),
    ("SecurityOperationsContractTest", "test_source_suspension_procedure_is_recorded", 16),
    ("SecurityOperationsContractTest", "test_closure_conditions_are_conditional", 4),
    ("SecurityOperationsContractTest", "test_artifact_evidence_priority_and_role_boundaries", 10),
    ("SecurityOperationsContractTest", "test_approved_operational_decisions_and_emergency_boundaries", 3),
    ("SecurityOperationsContractTest", "test_withdrawal_and_correction_policy_is_fixed_without_new_contract", 3),
    ("SecurityOperationsContractTest", "test_artifact_retention_exception_is_recorded_and_reviewed", 2),
    ("SecurityOperationsContractTest", "test_bl024_is_closed_with_merge_and_deployment_evidence", 20),
    ("SecurityOperationsContractTest", "test_no_local_absolute_path_or_credential_value_pattern", 5),
    ("SecurityOperationsContractTest", "test_internal_markdown_links_resolve", 2),
    # Bl031SecurityOperationsReconciliationTest
    ("Bl031SecurityOperationsReconciliationTest", "test_version_11_approval_record_is_preserved_as_history", 1),
    ("Bl031SecurityOperationsReconciliationTest", "test_correction_section_no_longer_lists_translate_cache_as_published_asset", 1),
    ("Bl031SecurityOperationsReconciliationTest", "test_source_suspension_does_not_rewrite_past_published_output", 4),
    ("Bl031SecurityOperationsReconciliationTest", "test_gemini_owner_verification_records_no_confidential_information", 3),
    ("Bl031SecurityOperationsReconciliationTest", "test_verification_step_allows_readonly_official_page_check_not_blanket_ban", 6),
    ("Bl031SecurityOperationsReconciliationTest", "test_section_11_source_suspension_summary_matches_section_7_verification_rule", 5),
    ("Bl031SecurityOperationsReconciliationTest", "test_gemini_owner_verification_is_completed_as_paid_verified", 8),
)

SHARD_001_EXPECTED_C_IDS = frozenset({
    _SO + "SecurityOperationsContractTest::test_version_10_identity_review_record_and_user_approval::assert-05",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-01",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-02",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-03",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-04",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-05",
    _SO + "SecurityOperationsContractTest::test_canonical_secret_prohibition_is_unconditional::assert-06",
    _SO + "SecurityOperationsContractTest::test_approved_secret_stores_are_not_mistaken_for_evidence::assert-01",
    _SO + "SecurityOperationsContractTest::test_approved_secret_stores_are_not_mistaken_for_evidence::assert-03",
    _SO + "SecurityOperationsContractTest::test_approved_secret_stores_are_not_mistaken_for_evidence::assert-04",
    _SO + "SecurityOperationsContractTest::test_approved_secret_stores_are_not_mistaken_for_evidence::assert-05",
    _SO + "SecurityOperationsContractTest::test_only_non_secret_data_can_use_an_approved_artifact_exception::assert-01",
    _SO + "SecurityOperationsContractTest::test_only_non_secret_data_can_use_an_approved_artifact_exception::assert-02",
    _SO + "SecurityOperationsContractTest::test_only_non_secret_data_can_use_an_approved_artifact_exception::assert-03",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-01",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-02",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-03",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-04",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-05",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-06",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-07",
    _SO + "SecurityOperationsContractTest::test_rotation_has_immediate_and_controlled_paths::assert-08",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-01",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-02",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-03",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-04",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-05",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-06",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-07",
    _SO + "SecurityOperationsContractTest::test_nvd_secret_state_has_owner_verification_evidence::assert-08",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-01",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-02",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-03",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-04",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-05",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-06",
    _SO + "SecurityOperationsContractTest::test_github_account_compromise_and_published_secret_containment::assert-07",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-02",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-04",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-07",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-08",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-09",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-10",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-11",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-13",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-14",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-15",
    _SO + "SecurityOperationsContractTest::test_source_suspension_procedure_is_recorded::assert-16",
    _SO + "SecurityOperationsContractTest::test_closure_conditions_are_conditional::assert-01",
    _SO + "SecurityOperationsContractTest::test_closure_conditions_are_conditional::assert-02",
    _SO + "SecurityOperationsContractTest::test_closure_conditions_are_conditional::assert-03",
    _SO + "SecurityOperationsContractTest::test_closure_conditions_are_conditional::assert-04",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-01",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-02",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-03",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-04",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-05",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-06",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-07",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-08",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-09",
    _SO + "SecurityOperationsContractTest::test_artifact_evidence_priority_and_role_boundaries::assert-10",
    _SO + "SecurityOperationsContractTest::test_approved_operational_decisions_and_emergency_boundaries::assert-01",
    _SO + "SecurityOperationsContractTest::test_approved_operational_decisions_and_emergency_boundaries::assert-02",
    _SO + "SecurityOperationsContractTest::test_approved_operational_decisions_and_emergency_boundaries::assert-03",
    _SO + "SecurityOperationsContractTest::test_withdrawal_and_correction_policy_is_fixed_without_new_contract::assert-01",
    _SO + "SecurityOperationsContractTest::test_withdrawal_and_correction_policy_is_fixed_without_new_contract::assert-02",
    _SO + "SecurityOperationsContractTest::test_withdrawal_and_correction_policy_is_fixed_without_new_contract::assert-03",
    _SO + "SecurityOperationsContractTest::test_artifact_retention_exception_is_recorded_and_reviewed::assert-01",
    _SO + "SecurityOperationsContractTest::test_artifact_retention_exception_is_recorded_and_reviewed::assert-02",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-01",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-09",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-10",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-11",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-12",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-13",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_source_suspension_does_not_rewrite_past_published_output::assert-01",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_source_suspension_does_not_rewrite_past_published_output::assert-04",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-01",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-02",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-03",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-04",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-05",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-06",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_section_11_source_suspension_summary_matches_section_7_verification_rule::assert-01",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_section_11_source_suspension_summary_matches_section_7_verification_rule::assert-02",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_section_11_source_suspension_summary_matches_section_7_verification_rule::assert-03",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_section_11_source_suspension_summary_matches_section_7_verification_rule::assert-04",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_section_11_source_suspension_summary_matches_section_7_verification_rule::assert-05",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_gemini_owner_verification_is_completed_as_paid_verified::assert-03",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_gemini_owner_verification_is_completed_as_paid_verified::assert-07",
})

SHARD_001_EXPECTED_D_IDS = frozenset({
    _SO + "SecurityOperationsContractTest::test_version_10_identity_review_record_and_user_approval::assert-03",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-15",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-17",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-18",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-19",
    _SO + "SecurityOperationsContractTest::test_bl024_is_closed_with_merge_and_deployment_evidence::assert-20",
    _SO + "Bl031SecurityOperationsReconciliationTest::test_gemini_owner_verification_is_completed_as_paid_verified::assert-01",
})

# Tranche 3h has NO Category A entry -- pinned explicitly, not left implicit:
# both fingerprint-duplicate groups below were reviewed and rejected as A.
SHARD_001_EXPECTED_A_IDS = frozenset()

SHARD_001_EXPECTED_CATEGORY_COUNTS = {
    "A": len(SHARD_001_EXPECTED_A_IDS),
    "B": SHARD_001_EXPECTED_ASSERTION_COUNT
    - len(SHARD_001_EXPECTED_A_IDS)
    - len(SHARD_001_EXPECTED_C_IDS)
    - len(SHARD_001_EXPECTED_D_IDS),
    "C": len(SHARD_001_EXPECTED_C_IDS),
    "D": len(SHARD_001_EXPECTED_D_IDS),
}

# The two fingerprint-duplicate groups in this scope, each reviewed at
# whole-method / extraction-context level and rejected as Category A.
SHARD_001_FINGERPRINT_DUPLICATE_GROUPS = (
    (
        _SO + "SecurityOperationsContractTest::"
        "test_source_suspension_procedure_is_recorded::assert-13",
        _SO + "Bl031SecurityOperationsReconciliationTest::"
        "test_verification_step_allows_readonly_official_page_check_not_blanket_ban::assert-01",
    ),
    (
        _SO + "SecurityOperationsContractTest::"
        "test_withdrawal_and_correction_policy_is_fixed_without_new_contract::assert-03",
        _SO + "SecurityOperationsContractTest::"
        "test_artifact_retention_exception_is_recorded_and_reviewed::assert-02",
    ),
)

# Current index state. Tranche 3g's "exactly one shard" survives below as
# HISTORY only, asserted NOT to be the current shard count.
EXPECTED_SHARD_ORDER = (MANIFEST_PATH.name, SHARD_001_FILENAME)
EXPECTED_SHARD_COUNT = len(EXPECTED_SHARD_ORDER)
TRANCHE_3G_HISTORICAL_SHARD_COUNT = 1
INDEX_COMBINED_ASSERTION_COUNT = (
    BASE_EXPECTED_ASSERTION_COUNT + SHARD_001_EXPECTED_ASSERTION_COUNT
)
INDEX_COMBINED_CATEGORY_COUNTS = {
    cat: BASE_EXPECTED_CATEGORY_COUNTS[cat] + SHARD_001_EXPECTED_CATEGORY_COUNTS[cat]
    for cat in ("A", "B", "C", "D")
}


EXPECTED_ENTRY_KEY_ORDER = (
    "id",
    "file",
    "class",
    "method",
    "ordinal",
    "assertion_api",
    "fingerprint",
    "targets",
    "category",
    "action",
    "contract_summary",
    "rationale",
)

# Entries whose single AST call site genuinely spans more than one target
# file/path (a `for` loop over distinct targets), keyed by manifest id.
# Tranche 3c added no new multi-target entries: test_ui_spec.py's own
# for-loops (chapter headings, screenshot filenames) all check a single
# document, not distinct target files. Tranche 3d added none either:
# test_status.py's own methods each check exactly one of self.status/
# self.decisions/self.operations/self.backlog per assertion. Tranche 3e
# added exactly one: a `for name, text in (...)` loop over 4 documents.
# Tranche 3f added none: its only loop has a single element, so its three
# assertions each check exactly one document, SOURCE_USAGE_POLICY.md.
EXPECTED_MULTI_TARGETS = {
    "test_custom_domain.py::TicketIdTypoTest::"
    "test_no_bl007_underscore_typo_anywhere_in_tracked_markdown_or_python::assert-01": (
        "README.md",
        "BACKLOG.md",
        "STATUS.md",
        "DECISIONS.md",
        "UI_SPEC.md",
        "fetch.py",
        "daily_json.py",
    ),
    "test_custom_domain.py::CnameSurvivesGenerationTest::"
    "test_cname_survives_repeated_full_archive_regeneration::assert-03": (
        "docs/archive/2026-07-10.html",
        "docs/archive/2026-07-11.html",
        "docs/archive/2026-07-12.html",
    ),
    # Tranche 3e's one genuine multi-target entry: a `for name, text in
    # (...)` loop whose single `self.assertNotIn(...)` call site checks the
    # same banned token across all 4 of BACKLOG.md/STATUS.md/DECISIONS.md/
    # SECURITY_REQUIREMENTS.md.
    "test_security_requirements.py::Bl034CloseoutTest::"
    "test_google_verification_txt_value_is_not_present_anywhere::assert-01": (
        "BACKLOG.md#BL-034",
        "STATUS.md#Active-work",
        "DECISIONS.md#SD-032",
        "SECURITY_REQUIREMENTS.md",
    ),
}

# Round 2 fix (Blocker 6): "short"/"one line"/"no realistic [wrap point]"/
# generic "cname" were the weak length-based reasoning that produced round
# 1's own misclassifications -- removed rather than tightened. This is a
# structural sanity net (nonblank, no placeholder, *some* substantive
# category-appropriate reasoning) -- it cannot verify a rationale's
# classification judgment is correct. Category membership is a
# human-reviewed record, pinned by the *_EXPECTED_A_IDS/C_IDS/D_IDS sets,
# checked by test_exact_category_membership_matches_hardcoded_id_sets.
# -- Tranche 3f round 2: two NARROW structural guards over the tranche 3f
# class's source. Neither improves the per-assertion fingerprint in general
# -- `canonical_fingerprint()` is unchanged and still covers only the
# assertion call node. They close two specific places where that scope is
# too narrow for what the manifest claims, nothing more. Both take a source
# STRING so the same helper runs against a mutated copy (demonstrated, not
# asserted). `test_security_requirements.py` is not modified by either.

_FUNCTION_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)

TRANCHE_3F_CLASS = "Bl031AcceptanceAndBl032RegistrationTest"

# Blind spot 1: this method's `**Version:** 0.1` literal lives in the
# surrounding one-element `for` tuple, NOT in the assertion call, so the
# recorded fingerprint would not move if the tuple were edited to `0.2`.
VERSION_MARKER_METHOD = (
    "test_source_usage_policy_20260731_snapshot_and_security_requirements_current_version"
)
VERSION_MARKER_LITERAL = "**Version:** 0.1"
VERSION_MARKER_DOC_ATTR = "policy"
VERSION_MARKER_BINDINGS = ["doc", "version_marker"]

# Blind spot 2: the four Category A entries rest on whole-METHOD
# duplication, which assertion fingerprints alone cannot see.
CATEGORY_A_METHOD_PAIR = (
    "test_sd030_does_not_mark_sd002_as_implemented_superseded",
    "test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030",
)
CATEGORY_A_EXPECTED_STATEMENT_ROLES = frozenset({
    ("assign", "sd002"),
    ("assign", "sd030"),
    ("assign", "supersedes"),
    ("call", "assertIn", "- **Status:** Accepted / Implemented"),
    ("call", "assertNotIn", "SD-002"),
})


def _find_method(source_text, file_name, class_name, method_name):
    """The named method's AST node; StopIteration if it is gone."""
    tree = ast.parse(source_text, filename=file_name)
    class_node = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == class_name
    )
    return next(
        n for n in class_node.body
        if isinstance(n, _FUNCTION_DEF_TYPES) and n.name == method_name
    )


def _statement_role(stmt):
    """A position-free label saying WHICH contract a statement carries."""
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    ):
        return ("assign", stmt.targets[0].id)
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        func = stmt.value.func
        if isinstance(func, ast.Attribute):
            args = stmt.value.args
            literal = args[0].value if args and isinstance(args[0], ast.Constant) else None
            return ("call", func.attr, literal)
    return ("other", ast.dump(stmt, annotate_fields=True, include_attributes=False))


def _mutate_within_method(source_text, class_name, method_name, old, new):
    """Replace `old` with `new` ONLY inside that method's own source lines,
    so a literal shared with the sibling method is not changed in both."""
    method = _find_method(source_text, "<mutation>", class_name, method_name)
    lines = source_text.splitlines(keepends=True)
    start, end = method.lineno - 1, method.end_lineno
    block = "".join(lines[start:end])
    if old not in block:
        raise AssertionError(f"{old!r} not found inside {method_name}")
    return "".join(lines[:start]) + block.replace(old, new, 1) + "".join(lines[end:])


_PLACEHOLDER_WORDS = ("todo", "fixme", "placeholder", "tbd", "xxx", "n/a")
_CATEGORY_MARKERS = {
    "A": ("duplicat", "helper", "consolidat", "shared", "call site", "identical fingerprint", "repeated"),
    "B": (
        "structural", "atomic", "convention", "no internal wrap", "no wrap point",
        "token", "marker", "single word", "ordering", "position-based",
        "existence", "minimal", "not subject to", "editorial reflow", "config",
        "meaning-preserving edit", "sanity", "postcondition", "standalone",
        "reference", "heading",
    ),
    "C": ("brittle", "reflow", "wrap", "normalize", "prose", "clause", "sentence", "paragraph", "fragment"),
    "D": ("exact", "identifier", "sha", "literal", "evidence", "durable"),
}


class DocumentTestClassificationScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        cls.manifest = json.loads(cls.manifest_text)
        cls.sources = {
            CUSTOM_DOMAIN_SOURCE_FILE: (ROOT / CUSTOM_DOMAIN_SOURCE_FILE).read_text(encoding="utf-8"),
            UI_SPEC_SOURCE_FILE: (ROOT / UI_SPEC_SOURCE_FILE).read_text(encoding="utf-8"),
            STATUS_SOURCE_FILE: (ROOT / STATUS_SOURCE_FILE).read_text(encoding="utf-8"),
            SECURITY_REQUIREMENTS_SOURCE_FILE: (ROOT / SECURITY_REQUIREMENTS_SOURCE_FILE).read_text(encoding="utf-8"),
        }
        cls.live_records_by_file = {
            CUSTOM_DOMAIN_SOURCE_FILE: dti.enumerate_assertions(
                cls.sources[CUSTOM_DOMAIN_SOURCE_FILE], CUSTOM_DOMAIN_SOURCE_FILE,
                list(CUSTOM_DOMAIN_EXPECTED_CLASSES),
            ),
            UI_SPEC_SOURCE_FILE: dti.enumerate_assertions(
                cls.sources[UI_SPEC_SOURCE_FILE], UI_SPEC_SOURCE_FILE,
                list(UI_SPEC_EXPECTED_CLASSES),
            ),
            STATUS_SOURCE_FILE: dti.enumerate_assertions(
                cls.sources[STATUS_SOURCE_FILE], STATUS_SOURCE_FILE,
                list(STATUS_EXPECTED_CLASSES),
            ),
            SECURITY_REQUIREMENTS_SOURCE_FILE: dti.enumerate_assertions(
                cls.sources[SECURITY_REQUIREMENTS_SOURCE_FILE], SECURITY_REQUIREMENTS_SOURCE_FILE,
                list(SECURITY_REQUIREMENTS_EXPECTED_CLASSES),
            ),
        }
        # Concatenation order matches the manifest's own required layout:
        # test_custom_domain.py's 97 entries first (unchanged from tranche
        # 3b), then test_ui_spec.py's 185 entries (unchanged from tranche
        # 3c), then test_status.py's 98 entries (unchanged from tranche 3d),
        # then test_security_requirements.py's 143 entries (tranche 3e), in
        # source order within each file.
        cls.live_records = (
            cls.live_records_by_file[CUSTOM_DOMAIN_SOURCE_FILE]
            + cls.live_records_by_file[UI_SPEC_SOURCE_FILE]
            + cls.live_records_by_file[STATUS_SOURCE_FILE]
            + cls.live_records_by_file[SECURITY_REQUIREMENTS_SOURCE_FILE]
        )

    # -- shared helper, used both directly and against mutated copies in
    # the scope-shrinkage/reordering mutation tests below --
    def _assert_expected_scope(self, manifest):
        scope = manifest["scope"]
        self.assertEqual(len(scope), 4, "scope must list exactly 4 files")
        for entry, (expected_file, expected_classes) in zip(scope, EXPECTED_SCOPE_ORDER):
            self.assertEqual(entry["file"], expected_file)
            self.assertEqual(
                tuple(entry["classes"]),
                expected_classes,
                f"declared scope classes for {expected_file} must exactly equal "
                "the hardcoded literal expected-class tuple (order and membership)",
            )

    def _assert_ids_match_source_order(self, manifest):
        # List (not set) equality: the manifest must list assertions in the
        # same source order document_test_inventory.py enumerates them in,
        # not merely contain the same set of IDs in arbitrary order -- and
        # the two files' blocks must appear in scope order.
        manifest_ids = [a["id"] for a in manifest["assertions"]]
        live_ids = [r.id for r in self.live_records]
        self.assertEqual(manifest_ids, live_ids)

    def test_manifest_exists_and_is_a_valid_json_object(self):
        self.assertTrue(MANIFEST_PATH.is_file())
        self.assertIsInstance(self.manifest, dict)

    def test_schema_version_is_exactly_1(self):
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertIs(type(self.manifest["schema_version"]), int)

    def test_scope_is_exactly_four_files_in_order_with_expected_classes(self):
        self._assert_expected_scope(self.manifest)

    def test_assertion_and_live_inventory_counts_match_expected_totals(self):
        self.assertEqual(len(self.manifest["assertions"]), BASE_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(self.live_records), BASE_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(
            len(self.live_records_by_file[CUSTOM_DOMAIN_SOURCE_FILE]),
            CUSTOM_DOMAIN_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(
            len(self.live_records_by_file[UI_SPEC_SOURCE_FILE]),
            UI_SPEC_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(
            len(self.live_records_by_file[STATUS_SOURCE_FILE]),
            STATUS_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(
            len(self.live_records_by_file[SECURITY_REQUIREMENTS_SOURCE_FILE]),
            SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT,
        )
        manifest_counts_by_file = {}
        for entry in self.manifest["assertions"]:
            manifest_counts_by_file[entry["file"]] = manifest_counts_by_file.get(entry["file"], 0) + 1
        self.assertEqual(
            manifest_counts_by_file,
            {
                CUSTOM_DOMAIN_SOURCE_FILE: CUSTOM_DOMAIN_EXPECTED_ASSERTION_COUNT,
                UI_SPEC_SOURCE_FILE: UI_SPEC_EXPECTED_ASSERTION_COUNT,
                STATUS_SOURCE_FILE: STATUS_EXPECTED_ASSERTION_COUNT,
                SECURITY_REQUIREMENTS_SOURCE_FILE: SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT,
            },
        )

    def test_manifest_ids_match_live_inventory_ids_in_source_order(self):
        self._assert_ids_match_source_order(self.manifest)

    def test_manifest_entries_match_live_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], record.file)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual(entry["method"], record.method)
                # Direct field check -- independent of re-deriving the
                # ordinal from the id string, so a manifest whose "id" and
                # "ordinal" fields were edited out of sync is still caught.
                self.assertEqual(entry["ordinal"], record.ordinal)
                self.assertEqual(
                    int(entry["id"].rsplit("assert-", 1)[1]), record.ordinal
                )
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)

    def test_validate_manifest_reports_no_failures(self):
        failures, summary = dti.validate_manifest(self.manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["unclassified"], 0)
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["fingerprint_mismatch"], 0)

    def test_category_counts_match_corrected_final_tally(self):
        counts_by_file = {
            CUSTOM_DOMAIN_SOURCE_FILE: {"A": 0, "B": 0, "C": 0, "D": 0},
            UI_SPEC_SOURCE_FILE: {"A": 0, "B": 0, "C": 0, "D": 0},
            STATUS_SOURCE_FILE: {"A": 0, "B": 0, "C": 0, "D": 0},
            SECURITY_REQUIREMENTS_SOURCE_FILE: {"A": 0, "B": 0, "C": 0, "D": 0},
        }
        for entry in self.manifest["assertions"]:
            counts_by_file[entry["file"]][entry["category"]] += 1
        self.assertEqual(counts_by_file[CUSTOM_DOMAIN_SOURCE_FILE], CUSTOM_DOMAIN_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(counts_by_file[UI_SPEC_SOURCE_FILE], UI_SPEC_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(counts_by_file[STATUS_SOURCE_FILE], STATUS_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(
            counts_by_file[SECURITY_REQUIREMENTS_SOURCE_FILE], SECURITY_REQUIREMENTS_EXPECTED_CATEGORY_COUNTS
        )
        combined = {
            cat: counts_by_file[CUSTOM_DOMAIN_SOURCE_FILE][cat]
            + counts_by_file[UI_SPEC_SOURCE_FILE][cat]
            + counts_by_file[STATUS_SOURCE_FILE][cat]
            + counts_by_file[SECURITY_REQUIREMENTS_SOURCE_FILE][cat]
            for cat in ("A", "B", "C", "D")
        }
        self.assertEqual(combined, BASE_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(combined.values()), BASE_EXPECTED_ASSERTION_COUNT)

    # Round 2 fix (Blocker 3): category *counts* alone can't catch a B/C (or
    # any two same-count-preserving categories) entry swap. This checks the
    # exact per-ID category membership against hardcoded literal sets for
    # A/C/D (B is checked as the exact remainder), which the classification
    # manifest -- a human-reviewed record, not a derivable computation --
    # requires to be pinned, not merely counted. Tranche 3c preserves
    # tranche 3b's record unweakened by unioning it into the combined sets
    # (the two files' IDs are disjoint by construction).
    def _assert_exact_category_membership(self, manifest):
        by_id = {a["id"]: a["category"] for a in manifest["assertions"]}
        all_ids = frozenset(by_id)
        expected_b_ids = all_ids - BASE_EXPECTED_A_IDS - BASE_EXPECTED_C_IDS - BASE_EXPECTED_D_IDS
        for entry_id, expected_category in (
            [(i, "A") for i in BASE_EXPECTED_A_IDS]
            + [(i, "C") for i in BASE_EXPECTED_C_IDS]
            + [(i, "D") for i in BASE_EXPECTED_D_IDS]
            + [(i, "B") for i in expected_b_ids]
        ):
            self.assertEqual(
                by_id.get(entry_id), expected_category,
                f"{entry_id} expected category {expected_category!r}, "
                f"manifest has {by_id.get(entry_id)!r}",
            )

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        self._assert_exact_category_membership(self.manifest)

    def test_count_preserving_category_swap_mutation_is_detected(self):
        # Swap one B entry and one C entry's categories (and matching
        # actions) -- the aggregate A/B/C/D counts stay identical, so only
        # the exact-membership guard (not test_category_counts_match_
        # corrected_final_tally) can catch this. Exercised for both files.
        expected_c_ids_by_file = {
            CUSTOM_DOMAIN_SOURCE_FILE: CUSTOM_DOMAIN_EXPECTED_C_IDS,
            UI_SPEC_SOURCE_FILE: UI_SPEC_EXPECTED_C_IDS,
            STATUS_SOURCE_FILE: STATUS_EXPECTED_C_IDS,
            SECURITY_REQUIREMENTS_SOURCE_FILE: SECURITY_REQUIREMENTS_EXPECTED_C_IDS,
        }
        for file, c_ids in expected_c_ids_by_file.items():
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                by_id = {a["id"]: a for a in mutated["assertions"]}
                expected_b_ids = (
                    frozenset(by_id) - BASE_EXPECTED_A_IDS - BASE_EXPECTED_C_IDS - BASE_EXPECTED_D_IDS
                )
                b_candidates = [i for i in expected_b_ids if i.startswith(file + "::")]
                b_entry = by_id[b_candidates[0]]
                c_entry = by_id[next(iter(c_ids))]
                b_entry["category"], c_entry["category"] = c_entry["category"], b_entry["category"]
                b_entry["action"], c_entry["action"] = c_entry["action"], b_entry["action"]

                combined = {"A": 0, "B": 0, "C": 0, "D": 0}
                for entry in mutated["assertions"]:
                    combined[entry["category"]] += 1
                self.assertEqual(combined, BASE_EXPECTED_CATEGORY_COUNTS, "swap must be count-preserving")

                with self.assertRaises(AssertionError):
                    self._assert_exact_category_membership(mutated)

    # Explicit preservation check (distinct from the generic swap test
    # above): mutating the category of one of tranche 3b's ORIGINAL 97
    # entries must still be caught by the same combined guard, proving
    # tranche 3c's expansion did not silently dilute tranche 3b's record.
    def test_custom_domain_membership_preservation_mutation_is_detected(self):
        mutated = json.loads(self.manifest_text)
        by_id = {a["id"]: a for a in mutated["assertions"]}
        target_id = next(iter(CUSTOM_DOMAIN_EXPECTED_A_IDS))
        entry = by_id[target_id]
        entry["category"] = "B"
        entry["action"] = dti.CATEGORY_TO_ACTION["B"]
        with self.assertRaises(AssertionError):
            self._assert_exact_category_membership(mutated)

    # Category A is newly non-empty for test_security_requirements.py, so
    # the swap above (B<->C only) would not notice an A entry downgraded to
    # B while a B is promoted to A. Exercise that pair explicitly.
    def test_count_preserving_a_to_b_swap_in_security_requirements_is_detected(self):
        mutated = json.loads(self.manifest_text)
        by_id = {a["id"]: a for a in mutated["assertions"]}
        expected_b_ids = (
            frozenset(by_id) - BASE_EXPECTED_A_IDS - BASE_EXPECTED_C_IDS - BASE_EXPECTED_D_IDS
        )
        prefix = SECURITY_REQUIREMENTS_SOURCE_FILE + "::Bl031AcceptanceAndBl032RegistrationTest::"
        b_entry = by_id[sorted(i for i in expected_b_ids if i.startswith(prefix))[0]]
        a_entry = by_id[sorted(SECURITY_REQUIREMENTS_EXPECTED_A_IDS)[0]]
        b_entry["category"], a_entry["category"] = a_entry["category"], b_entry["category"]
        b_entry["action"], a_entry["action"] = a_entry["action"], b_entry["action"]

        combined = {"A": 0, "B": 0, "C": 0, "D": 0}
        for entry in mutated["assertions"]:
            combined[entry["category"]] += 1
        self.assertEqual(combined, BASE_EXPECTED_CATEGORY_COUNTS, "swap must be count-preserving")
        with self.assertRaises(AssertionError):
            self._assert_exact_category_membership(mutated)

    # The four Category A entries exist because two whole methods duplicate
    # each other. Demonstrate that against the LIVE source, not just in a
    # rationale: the four must cover exactly two methods and two distinct
    # fingerprints, with both methods asserting the same pair.
    def test_security_requirements_category_a_entries_are_a_real_duplicated_method_pair(self):
        a_entries = [
            a for a in self.manifest["assertions"]
            if a["file"] == SECURITY_REQUIREMENTS_SOURCE_FILE and a["category"] == "A"
        ]
        self.assertEqual(len(a_entries), 4)
        self.assertEqual(
            {a["class"] for a in a_entries}, {"Bl031AcceptanceAndBl032RegistrationTest"}
        )
        methods = sorted({a["method"] for a in a_entries})
        self.assertEqual(
            methods,
            [
                "test_sd002_remains_accepted_implemented_and_not_marked_superseded_by_sd030",
                "test_sd030_does_not_mark_sd002_as_implemented_superseded",
            ],
        )
        live_by_id = {r.id: r for r in self.live_records}
        fingerprints_by_method = {}
        for entry in a_entries:
            fingerprints_by_method.setdefault(entry["method"], set()).add(
                live_by_id[entry["id"]].fingerprint
            )
        first, second = (fingerprints_by_method[m] for m in methods)
        self.assertEqual(len(first), 2, "each method must contribute two distinct assertions")
        self.assertEqual(
            first, second,
            "the two methods must assert the identical pair of fingerprints -- that "
            "whole-method duplication is what makes these Category A rather than B",
        )

    # -- Tranche 3f round 2, Blocker 2: the Version-0.1 loop binding --
    def _assert_version_marker_loop_contract(self, source_text):
        """Pin the one-element `for` tuple carrying the `**Version:** 0.1`
        literal the manifest records as an exact Category D contract. The
        recorded fingerprint covers only `assertIn(version_marker, doc)`,
        so without this the tuple could be edited to `0.2` undetected."""
        method = _find_method(
            source_text, SECURITY_REQUIREMENTS_SOURCE_FILE, TRANCHE_3F_CLASS,
            VERSION_MARKER_METHOD,
        )
        loops = [s for s in method.body if isinstance(s, ast.For)]
        self.assertEqual(len(loops), 1, "expected exactly one for-loop in this method")
        loop = loops[0]

        # (a) one-element literal tuple: a second element would silently
        # widen what this single manifest entry describes
        self.assertIsInstance(loop.iter, ast.Tuple)
        self.assertEqual(len(loop.iter.elts), 1, "must stay a single-element tuple")

        # (b) that element is exactly `(self.policy, "**Version:** 0.1")`
        element = loop.iter.elts[0]
        self.assertIsInstance(element, ast.Tuple)
        self.assertEqual(len(element.elts), 2)
        doc_expr, marker_expr = element.elts
        self.assertIsInstance(doc_expr, ast.Attribute)
        self.assertIsInstance(doc_expr.value, ast.Name)
        self.assertEqual((doc_expr.value.id, doc_expr.attr), ("self", VERSION_MARKER_DOC_ATTR))
        self.assertIsInstance(marker_expr, ast.Constant)
        self.assertEqual(
            marker_expr.value, VERSION_MARKER_LITERAL,
            "the loop tuple's literal is assert-01's actual Category D contract",
        )

        # (c) the loop binds those values under the names the assertion uses
        self.assertIsInstance(loop.target, ast.Tuple)
        self.assertTrue(all(isinstance(t, ast.Name) for t in loop.target.elts))
        self.assertEqual([t.id for t in loop.target.elts], VERSION_MARKER_BINDINGS)

        # (d) `self.assertIn(version_marker, doc)` actually consumes that binding
        matches = [
            node for node in ast.walk(loop)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "assertIn"
            and len(node.args) == 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == VERSION_MARKER_BINDINGS[1]
            and isinstance(node.args[1], ast.Name)
            and node.args[1].id == VERSION_MARKER_BINDINGS[0]
        ]
        self.assertEqual(len(matches), 1, "one assertIn must consume the binding")

    def test_version_marker_loop_binding_matches_the_recorded_category_d_contract(self):
        self._assert_version_marker_loop_contract(self.sources[SECURITY_REQUIREMENTS_SOURCE_FILE])

    def test_version_marker_loop_literal_mutation_is_caught_only_by_the_new_guard(self):
        # Editing the loop tuple leaves the fingerprint identical, so only
        # the structural guard fails.
        source = self.sources[SECURITY_REQUIREMENTS_SOURCE_FILE]
        mutated = source.replace('"**Version:** 0.1"),', '"**Version:** 0.2"),')
        self.assertNotEqual(mutated, source)

        def fingerprint_of_assert_01(text):
            records = dti.enumerate_assertions(
                text, SECURITY_REQUIREMENTS_SOURCE_FILE, [TRANCHE_3F_CLASS])
            return next(r.fingerprint for r in records
                        if r.method == VERSION_MARKER_METHOD and r.ordinal == 1)

        # Step 1: prove the gap -- the ordinary fingerprint does not move.
        self.assertEqual(
            fingerprint_of_assert_01(source), fingerprint_of_assert_01(mutated),
            "the recorded fingerprint is blind to the loop tuple's literal",
        )
        # Step 2: prove the new guard catches what the fingerprint missed.
        with self.assertRaises(AssertionError):
            self._assert_version_marker_loop_contract(mutated)

    # -- Tranche 3f round 2, Blocker 3: whole-method duplication --
    def _assert_category_a_methods_are_whole_method_duplicates(self, source_text):
        """Compare both Category A methods' ENTIRE top-level statement sets,
        not just assertion fingerprints. Order may differ (the only
        difference claimed); the multiset of position-free dumps must match,
        so a change to either method's extraction code -- which no
        fingerprint covers -- breaks this."""
        methods = [
            _find_method(source_text, SECURITY_REQUIREMENTS_SOURCE_FILE, TRANCHE_3F_CLASS, n)
            for n in CATEGORY_A_METHOD_PAIR
        ]
        dumps = [
            Counter(ast.dump(s, annotate_fields=True, include_attributes=False) for s in m.body)
            for m in methods
        ]
        self.assertEqual(
            dumps[0], dumps[1],
            "both methods must hold the identical multiset of top-level statements "
            "(extraction included, order free) -- the entire basis for Category A",
        )
        # And they must be the specific statements the manifest describes, so
        # the guard cannot pass on two methods that merely match each other.
        for method, name in zip(methods, CATEGORY_A_METHOD_PAIR):
            with self.subTest(method=name):
                self.assertEqual(len(method.body), 5)
                self.assertEqual(
                    {_statement_role(stmt) for stmt in method.body},
                    CATEGORY_A_EXPECTED_STATEMENT_ROLES,
                )

    def test_category_a_methods_are_whole_method_duplicates_in_live_source(self):
        self._assert_category_a_methods_are_whole_method_duplicates(
            self.sources[SECURITY_REQUIREMENTS_SOURCE_FILE])

    def test_category_a_extraction_change_in_one_method_is_caught_only_by_the_new_guard(self):
        # Change the SD-002 extraction in ONE method: no fingerprint covers
        # that statement, so the fingerprint comparison stays green while the
        # methods have stopped being duplicates.
        source = self.sources[SECURITY_REQUIREMENTS_SOURCE_FILE]
        mutated = _mutate_within_method(
            source, TRANCHE_3F_CLASS, CATEGORY_A_METHOD_PAIR[1],
            '"## SD-002"', '"## SD-003"')
        self.assertNotEqual(mutated, source)

        def pair_fingerprints(text):
            records = dti.enumerate_assertions(
                text, SECURITY_REQUIREMENTS_SOURCE_FILE, [TRANCHE_3F_CLASS])
            return {n: sorted(r.fingerprint for r in records if r.method == n)
                    for n in CATEGORY_A_METHOD_PAIR}

        # Step 1: prove the gap -- both methods' assertion fingerprints are
        # unchanged, and still identical to each other.
        before, after = pair_fingerprints(source), pair_fingerprints(mutated)
        self.assertEqual(before, after, "assertion fingerprints are blind to extraction code")
        self.assertEqual(
            after[CATEGORY_A_METHOD_PAIR[0]], after[CATEGORY_A_METHOD_PAIR[1]],
            "the fingerprint-only comparison still passes on the mutated source",
        )
        # Step 2: prove the new whole-method guard catches it.
        with self.assertRaises(AssertionError):
            self._assert_category_a_methods_are_whole_method_duplicates(mutated)

    def test_action_matches_category_mapping_for_every_entry(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertEqual(
                    entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]]
                )

    # Round 1 fix (Blocker 2): every entry uses `targets` (a list), never
    # the old single-string `target`; genuinely multi-file call sites list
    # every real target path, not a slash-joined/brace-style combined label.
    def test_all_entries_use_targets_list_style_not_target(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                self.assertNotIn("target", entry)
                self.assertIn("targets", entry)
                targets = entry["targets"]
                self.assertIsInstance(targets, list)
                self.assertTrue(targets, "targets must be nonempty")
                self.assertEqual(len(targets), len(set(targets)), "targets must be unique")
                for t in targets:
                    self.assertIsInstance(t, str)
                    self.assertTrue(t.strip())

    def test_known_multi_target_entries_list_every_real_target_path(self):
        by_id = {a["id"]: a for a in self.manifest["assertions"]}
        for entry_id, expected_targets in EXPECTED_MULTI_TARGETS.items():
            with self.subTest(id=entry_id):
                self.assertIn(entry_id, by_id)
                self.assertEqual(tuple(by_id[entry_id]["targets"]), expected_targets)

    def test_non_multi_target_entries_have_exactly_one_target(self):
        multi_target_ids = set(EXPECTED_MULTI_TARGETS)
        for entry in self.manifest["assertions"]:
            if entry["id"] in multi_target_ids:
                continue
            with self.subTest(id=entry["id"]):
                self.assertEqual(len(entry["targets"]), 1)

    # Round 1 fix (Blocker 5): exact-uniqueness across all rationale strings
    # was itself brittle. Replaced with a structural quality check:
    # nonblank, no placeholder filler, and category-appropriate content.
    def test_summaries_and_rationales_are_nonblank_and_category_appropriate(self):
        for entry in self.manifest["assertions"]:
            with self.subTest(id=entry["id"]):
                summary = entry["contract_summary"]
                rationale = entry["rationale"]
                self.assertTrue(summary.strip())
                self.assertTrue(rationale.strip())
                lowered = rationale.lower()
                for placeholder in _PLACEHOLDER_WORDS:
                    self.assertNotIn(placeholder, lowered)
                markers = _CATEGORY_MARKERS[entry["category"]]
                self.assertTrue(
                    any(marker in lowered for marker in markers),
                    f"rationale for category {entry['category']} should mention "
                    f"one of {markers}: {rationale!r}",
                )

    # Round 1 fix (Blocker 4): mutation tests demonstrate the actual gap
    # they claim to close, using the SAME helper the real scope check uses
    # -- rather than just proving unequal tuples fail assertEqual. Tranche
    # 3c adds the whole-file-drop scenario alongside the original
    # single-class-drop scenario, table-driven via subTest.
    def test_scope_shrinkage_mutations_are_caught_by_the_guard(self):
        def drop_ui_spec_class(mutated):
            mutated["scope"][1]["classes"] = [
                c for c in mutated["scope"][1]["classes"] if c != "Bl036ArticleAttributionUiSpecTest"
            ]
            mutated["assertions"] = [
                a for a in mutated["assertions"]
                if not (a["file"] == UI_SPEC_SOURCE_FILE and a["class"] == "Bl036ArticleAttributionUiSpecTest")
            ]

        def drop_ui_spec_file_entirely(mutated):
            mutated["scope"] = [s for s in mutated["scope"] if s["file"] != UI_SPEC_SOURCE_FILE]
            mutated["assertions"] = [a for a in mutated["assertions"] if a["file"] != UI_SPEC_SOURCE_FILE]

        def drop_status_class(mutated):
            status_scope = next(s for s in mutated["scope"] if s["file"] == STATUS_SOURCE_FILE)
            status_scope["classes"] = [
                c for c in status_scope["classes"] if c != "Bl036ProductionEvidenceSyncTest"
            ]
            mutated["assertions"] = [
                a for a in mutated["assertions"]
                if not (a["file"] == STATUS_SOURCE_FILE and a["class"] == "Bl036ProductionEvidenceSyncTest")
            ]

        def drop_status_file_entirely(mutated):
            mutated["scope"] = [s for s in mutated["scope"] if s["file"] != STATUS_SOURCE_FILE]
            mutated["assertions"] = [a for a in mutated["assertions"] if a["file"] != STATUS_SOURCE_FILE]

        def drop_security_requirements_class(mutated):
            sr_scope = next(s for s in mutated["scope"] if s["file"] == SECURITY_REQUIREMENTS_SOURCE_FILE)
            sr_scope["classes"] = [
                c for c in sr_scope["classes"] if c != "StatusSecurityRequirementsSourceOfTruthTest"
            ]
            mutated["assertions"] = [
                a for a in mutated["assertions"]
                if not (
                    a["file"] == SECURITY_REQUIREMENTS_SOURCE_FILE
                    and a["class"] == "StatusSecurityRequirementsSourceOfTruthTest"
                )
            ]

        def drop_tranche3f_class(mutated):
            # Tranche 3f's own class, whose 62 entries are the newest and
            # therefore the easiest to lose silently: the validator alone
            # cannot see the scope shrink back to tranche 3e's four classes.
            sr_scope = next(s for s in mutated["scope"] if s["file"] == SECURITY_REQUIREMENTS_SOURCE_FILE)
            sr_scope["classes"] = [
                c for c in sr_scope["classes"] if c != "Bl031AcceptanceAndBl032RegistrationTest"
            ]
            mutated["assertions"] = [
                a for a in mutated["assertions"]
                if not (
                    a["file"] == SECURITY_REQUIREMENTS_SOURCE_FILE
                    and a["class"] == "Bl031AcceptanceAndBl032RegistrationTest"
                )
            ]

        def drop_security_requirements_file_entirely(mutated):
            mutated["scope"] = [s for s in mutated["scope"] if s["file"] != SECURITY_REQUIREMENTS_SOURCE_FILE]
            mutated["assertions"] = [
                a for a in mutated["assertions"] if a["file"] != SECURITY_REQUIREMENTS_SOURCE_FILE
            ]

        scenarios = {
            "class-shrink-within-ui-spec": drop_ui_spec_class,
            "file-shrink-drop-ui-spec-entirely": drop_ui_spec_file_entirely,
            "class-shrink-within-status": drop_status_class,
            "file-shrink-drop-status-entirely": drop_status_file_entirely,
            "class-shrink-within-security-requirements": drop_security_requirements_class,
            "class-shrink-drop-tranche3f-class": drop_tranche3f_class,
            "file-shrink-drop-security-requirements-entirely": drop_security_requirements_file_entirely,
        }
        for name, mutate in scenarios.items():
            with self.subTest(scenario=name):
                mutated = json.loads(self.manifest_text)
                mutate(mutated)
                # Step 1: prove the gap this guard exists to close -- a
                # manifest that shrank its own declared scope,
                # self-consistently, passes validate_manifest() with zero
                # failures.
                failures, _ = dti.validate_manifest(mutated, root=ROOT)
                self.assertEqual(failures, [])
                # Step 2: prove the structural guard (the same helper the
                # real test above uses) actually catches what the
                # validator missed.
                with self.assertRaises(AssertionError):
                    self._assert_expected_scope(mutated)

    def test_file_order_swap_mutation_is_detected_by_deterministic_scope_order_guard(self):
        # All 6 pairs of the now-4-file scope (itertools.combinations), not
        # just 3 hand-picked pairs -- every adjacent and non-adjacent swap
        # must be individually caught.
        swap_pairs = tuple(itertools.combinations(range(len(SCOPE_FILES)), 2))
        for i, j in swap_pairs:
            with self.subTest(swap=(i, j)):
                mutated = json.loads(self.manifest_text)
                scope = mutated["scope"]
                scope[i], scope[j] = scope[j], scope[i]
                with self.assertRaises(AssertionError):
                    self._assert_expected_scope(mutated)

    def test_assertion_order_swap_mutation_is_detected_by_source_order_guard(self):
        # Swap two adjacent entries within the SAME file's block (for each
        # of the 3 scoped files in turn) so total counts/category tallies/
        # scope are all untouched -- only the source-order list-equality
        # guard can catch this.
        for file in SCOPE_FILES:
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                idx = next(i for i, a in enumerate(mutated["assertions"]) if a["file"] == file)
                mutated["assertions"][idx], mutated["assertions"][idx + 1] = (
                    mutated["assertions"][idx + 1], mutated["assertions"][idx],
                )
                with self.assertRaises(AssertionError):
                    self._assert_ids_match_source_order(mutated)

    def test_assertion_deletion_mutation_is_detected_as_unclassified(self):
        for file in SCOPE_FILES:
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                idx = next(i for i, a in enumerate(mutated["assertions"]) if a["file"] == file)
                del mutated["assertions"][idx]
                failures, _ = dti.validate_manifest(mutated, root=ROOT)
                types = {f.mismatch_type for f in failures}
                self.assertIn("unclassified", types)

    def test_extra_assertion_mutation_is_detected_as_stale_entry(self):
        for file in SCOPE_FILES:
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                idx = next(i for i, a in enumerate(mutated["assertions"]) if a["file"] == file)
                extra = dict(mutated["assertions"][idx])
                extra["id"] = extra["id"].rsplit("assert-", 1)[0] + "assert-999"
                extra["ordinal"] = 999
                mutated["assertions"].append(extra)
                failures, _ = dti.validate_manifest(mutated, root=ROOT)
                types = {f.mismatch_type for f in failures}
                self.assertIn("stale-entry", types)

    def test_fingerprint_mutation_is_detected_as_fingerprint_mismatch(self):
        for file in SCOPE_FILES:
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                idx = next(i for i, a in enumerate(mutated["assertions"]) if a["file"] == file)
                mutated["assertions"][idx]["fingerprint"] = "0" * 64
                failures, _ = dti.validate_manifest(mutated, root=ROOT)
                types = {f.mismatch_type for f in failures}
                self.assertIn("fingerprint-mismatch", types)

    def test_category_action_inconsistency_mutation_is_detected(self):
        for file in SCOPE_FILES:
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                idx = next(i for i, a in enumerate(mutated["assertions"]) if a["file"] == file)
                entry = mutated["assertions"][idx]
                entry["category"] = "B" if entry["category"] != "B" else "D"
                failures, _ = dti.validate_manifest(mutated, root=ROOT)
                types = {f.mismatch_type for f in failures}
                self.assertIn("category-action-mismatch", types)

    # Round 1 fix (Blocker 3): deterministic manifest format -- fixed key
    # order per entry, one compact-JSON line per assertion, final newline.
    def test_manifest_entry_key_order_is_deterministic(self):
        raw = json.loads(self.manifest_text, object_pairs_hook=OrderedDict)
        for entry in raw["assertions"]:
            with self.subTest(id=entry.get("id")):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)

    def test_manifest_assertions_block_is_one_entry_per_line(self):
        lines = self.manifest_text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip() == '"assertions": [')
        end = next(i for i, l in enumerate(lines) if i > start and l.strip() == "]")
        entry_lines = lines[start + 1 : end]
        self.assertEqual(len(entry_lines), BASE_EXPECTED_ASSERTION_COUNT)
        for line in entry_lines:
            stripped = line.strip().rstrip(",")
            parsed = json.loads(stripped)
            self.assertIsInstance(parsed, dict)

    def test_manifest_has_trailing_newline_and_deterministic_reread(self):
        self.assertTrue(self.manifest_text.endswith("\n"))
        reread = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(reread, self.manifest)


class Tranche3hClassificationShardTest(unittest.TestCase):
    """BL-038 tranche 3h: the first ADDITIONAL shard. Deliberately separate
    from DocumentTestClassificationScopeTest, whose literals describe the
    frozen base manifest and must not absorb tranche 3h's values; the two
    records are combined -- never merged -- in ClassificationShardIndexTest."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_001_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text)
        cls.entries = cls.shard["assertions"]
        cls.by_id = {e["id"]: e for e in cls.entries}
        source = (ROOT / SHARD_001_SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(
            source, SHARD_001_SOURCE_FILE, list(SHARD_001_EXPECTED_CLASSES)
        )
        cls.source_classes = [
            n.name for n in ast.parse(source, filename=SHARD_001_SOURCE_FILE).body
            if isinstance(n, ast.ClassDef)
        ]

    def expected_ids_in_source_order(self):
        """The shard's complete id list expanded from hardcoded literals."""
        return [
            f"{SHARD_001_SOURCE_FILE}::{cls_name}::{method}::assert-{ordinal:02d}"
            for cls_name, method, count in SHARD_001_EXPECTED_METHOD_ORDER
            for ordinal in range(1, count + 1)
        ]

    def test_shard_is_scoped_to_exactly_the_two_selected_classes_in_source_order(self):
        self.assertEqual(self.shard["schema_version"], 1)
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(SHARD_001_PATH.name, SHARD_001_FILENAME)
        self.assertEqual(len(self.shard["scope"]), 1)
        scope_entry = self.shard["scope"][0]
        self.assertEqual(scope_entry["file"], SHARD_001_SOURCE_FILE)
        self.assertEqual(tuple(scope_entry["classes"]), SHARD_001_EXPECTED_CLASSES)
        # Declared class order equals the order the classes appear in source.
        self.assertEqual(
            [c for c in self.source_classes if c in SHARD_001_EXPECTED_CLASSES],
            list(SHARD_001_EXPECTED_CLASSES),
        )
        # The file's third class stays unclassified: including it would be
        # 170 assertions, over this tranche's 150-assertion cap.
        self.assertIn(SHARD_001_UNOWNED_CLASS, self.source_classes)
        self.assertNotIn(SHARD_001_UNOWNED_CLASS, scope_entry["classes"])

    def test_shard_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual(len(expected), SHARD_001_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(SHARD_001_EXPECTED_METHOD_ORDER), SHARD_001_EXPECTED_METHOD_COUNT)
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual(len(set(expected)), len(expected))
        # ... and the same list is what the live source actually enumerates.
        self.assertEqual([r.id for r in self.live_records], expected)
        self.assertEqual(len(self.entries), SHARD_001_EXPECTED_ASSERTION_COUNT)

    def test_shard_entries_match_the_live_source_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], SHARD_001_SOURCE_FILE)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual(entry["method"], record.method)
                self.assertEqual(entry["ordinal"], record.ordinal)
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)
        failures, summary = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["inventoried_assertions"], SHARD_001_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(summary["manifest_assertions"], SHARD_001_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(summary["scoped_classes"], len(SHARD_001_EXPECTED_CLASSES))
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        all_ids = frozenset(self.by_id)
        expected_b_ids = (
            all_ids
            - SHARD_001_EXPECTED_A_IDS
            - SHARD_001_EXPECTED_C_IDS
            - SHARD_001_EXPECTED_D_IDS
        )
        # Category A is 0 for tranche 3h -- pinned explicitly, not implied.
        self.assertEqual(SHARD_001_EXPECTED_A_IDS, frozenset())
        self.assertEqual(SHARD_001_EXPECTED_CATEGORY_COUNTS["A"], 0)
        self.assertEqual([e["id"] for e in self.entries if e["category"] == "A"], [])
        for id_, category in (
            [(i, "A") for i in SHARD_001_EXPECTED_A_IDS]
            + [(i, "C") for i in SHARD_001_EXPECTED_C_IDS]
            + [(i, "D") for i in SHARD_001_EXPECTED_D_IDS]
            + [(i, "B") for i in expected_b_ids]
        ):
            with self.subTest(id=id_, category=category):
                self.assertIn(id_, self.by_id)
                self.assertEqual(self.by_id[id_]["category"], category)
                self.assertEqual(self.by_id[id_]["action"], dti.CATEGORY_TO_ACTION[category])
        counts = Counter(e["category"] for e in self.entries)
        self.assertEqual(dict(counts), {k: v for k, v in SHARD_001_EXPECTED_CATEGORY_COUNTS.items() if v})
        for category in ("A", "B", "C", "D"):
            with self.subTest(category=category):
                self.assertEqual(counts[category], SHARD_001_EXPECTED_CATEGORY_COUNTS[category])
        self.assertEqual(sum(counts.values()), SHARD_001_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(expected_b_ids), SHARD_001_EXPECTED_CATEGORY_COUNTS["B"])

    def test_entries_are_well_formed_and_use_the_fixed_key_order(self):
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertNotIn("target", entry)
                self.assertIsInstance(entry["targets"], list)
                self.assertTrue(entry["targets"])
                for target in entry["targets"]:
                    self.assertTrue((ROOT / target).exists(), target)
                for field in ("contract_summary", "rationale"):
                    text = entry[field]
                    self.assertTrue(text.strip())
                    for word in _PLACEHOLDER_WORDS:
                        self.assertNotIn(word, text.lower())
                markers = _CATEGORY_MARKERS[entry["category"]]
                self.assertTrue(
                    any(m in entry["rationale"].lower() for m in markers),
                    f"{entry['id']}: rationale gives no category-{entry['category']} reasoning",
                )

    def test_raw_file_meets_the_shard_format_contract_within_the_line_cap(self):
        failures = dti.validate_shard_file_format(SHARD_001_PATH, self.shard, shard=SHARD_001_FILENAME)
        self.assertEqual([f.format() for f in failures], [])
        lines = self.shard_text.splitlines()
        self.assertEqual(len(lines), SHARD_001_EXPECTED_LINE_COUNT)
        self.assertLessEqual(len(lines), dti.SHARD_LINE_CAP)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)  # cap not raised
        self.assertTrue(self.shard_text.endswith("\n"))
        start = lines.index('  "assertions": [')
        entry_lines = lines[start + 1 : lines.index("  ]", start)]
        self.assertEqual(len(entry_lines), SHARD_001_EXPECTED_ASSERTION_COUNT)
        for offset, line in enumerate(entry_lines):
            with self.subTest(line=start + 2 + offset):
                parsed = json.loads(line.strip().rstrip(","), object_pairs_hook=OrderedDict)
                self.assertEqual(tuple(parsed.keys()), EXPECTED_ENTRY_KEY_ORDER)
        self.assertEqual(json.loads(self.shard_text), self.shard)

    def test_shard_claims_no_id_or_class_already_owned_by_the_base_manifest(self):
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        base_ids = {e["id"] for e in base["assertions"]}
        self.assertEqual(base_ids & frozenset(self.by_id), frozenset())
        base_pairs = {(s["file"], c) for s in base["scope"] for c in s["classes"]}
        shard_pairs = {(s["file"], c) for s in self.shard["scope"] for c in s["classes"]}
        self.assertEqual(base_pairs & shard_pairs, set())
        self.assertNotIn(SHARD_001_SOURCE_FILE, {s["file"] for s in base["scope"]})
        self.assertEqual(len(base_ids), BASE_EXPECTED_ASSERTION_COUNT)

    def test_fingerprint_duplicate_groups_are_not_category_a(self):
        """Every fingerprint collision here was reviewed at whole-method /
        extraction-context level and rejected as a Category A candidate."""
        by_fingerprint = {}
        for entry in self.entries:
            by_fingerprint.setdefault(entry["fingerprint"], []).append(entry["id"])
        groups = sorted(tuple(ids) for ids in by_fingerprint.values() if len(ids) > 1)
        self.assertEqual(groups, sorted(SHARD_001_FINGERPRINT_DUPLICATE_GROUPS))
        for group in groups:
            with self.subTest(group=group):
                for id_ in group:
                    self.assertNotIn(id_, SHARD_001_EXPECTED_A_IDS)
                    self.assertNotEqual(self.by_id[id_]["category"], "A")
                    # The rationale must SAY why the collision is not A.
                    self.assertIn("not a category a candidate", self.by_id[id_]["rationale"].lower())
        # The second group collides only because both call sites are the bare
        # loop call `self.assertIn(contract, compact)`; their enclosing `for`
        # tuples are different, which the assertion fingerprint cannot see.
        spurious = SHARD_001_FINGERPRINT_DUPLICATE_GROUPS[1]
        loops = {
            id_: len(self._loop_literals_for(id_)) for id_ in spurious
        }
        self.assertEqual(sorted(loops.values()), [9, 10])
        self.assertNotEqual(*[frozenset(self._loop_literals_for(i)) for i in spurious])

    def _loop_literals_for(self, entry_id):
        """The string literals of the `for` tuple enclosing an assertion."""
        _file, class_name, method_name, _ordinal = entry_id.split("::")
        source = (ROOT / SHARD_001_SOURCE_FILE).read_text(encoding="utf-8")
        method = _find_method(source, SHARD_001_SOURCE_FILE, class_name, method_name)
        literals = []
        for node in ast.walk(method):
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
                literals.extend(
                    e.value for e in node.iter.elts if isinstance(e, ast.Constant)
                )
        return literals

    def test_scope_shrinkage_mutation_of_the_new_shard_is_detected(self):
        """Demonstrated, not asserted: dropping the second class and its
        entries leaves an internally consistent manifest dti accepts -- only
        the hardcoded literals above catch it."""
        mutated = json.loads(json.dumps(self.shard))
        dropped = SHARD_001_EXPECTED_CLASSES[1]
        mutated["scope"][0]["classes"] = [SHARD_001_EXPECTED_CLASSES[0]]
        mutated["assertions"] = [e for e in mutated["assertions"] if e["class"] != dropped]
        failures, _summary = dti.validate_manifest(mutated, root=ROOT)
        self.assertEqual([f.format() for f in failures], [], "dti alone cannot see the shrinkage")
        self.assertNotEqual(tuple(mutated["scope"][0]["classes"]), SHARD_001_EXPECTED_CLASSES)
        self.assertLess(len(mutated["assertions"]), SHARD_001_EXPECTED_ASSERTION_COUNT)
        with self.assertRaises(AssertionError):
            self.assertEqual(
                tuple(mutated["scope"][0]["classes"]), SHARD_001_EXPECTED_CLASSES
            )


class ClassificationShardIndexTest(unittest.TestCase):
    """BL-038 tranche 3h: the shard-index contract. The index -- not a glob
    -- says which manifests make up the classification and in what order; as
    of tranche 3h, the frozen base manifest then shard 001. Tranche 3g's own
    one-shard state is kept only as history and asserted NOT to be current."""

    def setUp(self):
        self.index_text = INDEX_PATH.read_text(encoding="utf-8")
        self.index = json.loads(self.index_text, object_pairs_hook=OrderedDict)

    def test_index_declares_the_base_manifest_then_shard_001_in_that_order(self):
        self.assertEqual(tuple(self.index.keys()), dti.INDEX_TOP_LEVEL_KEYS)
        self.assertIs(type(self.index["schema_version"]), int)
        self.assertEqual(
            json.loads(self.index_text),
            {"schema_version": 1, "shards": [MANIFEST_PATH.name, SHARD_001_FILENAME]},
        )
        self.assertTrue(self.index_text.endswith("\n"))
        # Order is part of the contract: it fixes combined assertion order.
        self.assertEqual(tuple(self.index["shards"]), EXPECTED_SHARD_ORDER)
        self.assertEqual(self.index["shards"][0], MANIFEST_PATH.name)
        self.assertEqual(self.index["shards"][1], SHARD_001_FILENAME)
        self.assertEqual(len(self.index["shards"]), EXPECTED_SHARD_COUNT)
        self.assertEqual(len(set(self.index["shards"])), EXPECTED_SHARD_COUNT)
        # An unregistered shard file would silently vanish from the check.
        self.assertEqual(dti.discover_shard_filenames(ROOT), sorted(EXPECTED_SHARD_ORDER))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_001_FILENAME))
        self.assertFalse(dti.is_allowed_shard_filename(dti.INDEX_FILENAME))
        # Tranche 3g shipped a one-shard index; that is history, not now.
        self.assertEqual(TRANCHE_3G_HISTORICAL_SHARD_COUNT, 1)
        self.assertNotEqual(len(self.index["shards"]), TRANCHE_3G_HISTORICAL_SHARD_COUNT)

    def test_combined_index_validation_reports_the_two_shard_totals(self):
        failures, combined = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(
            (combined["shard_count"], combined["shard_files"]),
            (EXPECTED_SHARD_COUNT, list(EXPECTED_SHARD_ORDER)),
        )
        self.assertEqual(combined["manifest_assertions"], INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(combined["inventoried_assertions"], INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(INDEX_COMBINED_ASSERTION_COUNT, 585 + 136)
        self.assertEqual(combined["category_counts"], INDEX_COMBINED_CATEGORY_COUNTS)
        self.assertEqual(sum(combined["category_counts"].values()), INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(
            (combined["unclassified"], combined["stale"], combined["fingerprint_mismatch"]), (0, 0, 0)
        )
        # Combined counts are base + tranche 3h, never a re-derived tally.
        for category in ("A", "B", "C", "D"):
            with self.subTest(category=category):
                self.assertEqual(
                    combined["category_counts"][category],
                    BASE_EXPECTED_CATEGORY_COUNTS[category]
                    + SHARD_001_EXPECTED_CATEGORY_COUNTS[category],
                )
        self.assertEqual(
            sorted(combined["scoped_files"]),
            sorted({f for f, _ in EXPECTED_SCOPE_ORDER} | {SHARD_001_SOURCE_FILE}),
        )
        self.assertEqual(combined["file_counts"][SHARD_001_SOURCE_FILE], SHARD_001_EXPECTED_ASSERTION_COUNT)

    def test_combined_assertion_order_is_base_entries_then_shard_001_entries(self):
        load_failures, loaded = dti.load_shard_manifests(list(EXPECTED_SHARD_ORDER), root=ROOT)
        self.assertEqual(load_failures, [])
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))
        base_ids = [e["id"] for e in base["assertions"]]
        shard_ids = [e["id"] for e in shard_001["assertions"]]
        combined_ids = dti.combined_assertion_ids(loaded)
        self.assertEqual(combined_ids, base_ids + shard_ids)
        self.assertEqual(len(combined_ids), INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(len(set(combined_ids)), len(combined_ids))  # no cross-shard duplicate id
        # No cross-shard ownership overlap either.
        owners = {}
        for shard, manifest in loaded:
            for scope_entry in manifest["scope"]:
                for class_name in scope_entry["classes"]:
                    key = (scope_entry["file"], class_name)
                    with self.subTest(pair=key):
                        self.assertNotIn(key, owners)
                    owners[key] = shard
        self.assertEqual(owners[(SHARD_001_SOURCE_FILE, SHARD_001_EXPECTED_CLASSES[0])], SHARD_001_FILENAME)
        self.assertNotIn((SHARD_001_SOURCE_FILE, SHARD_001_UNOWNED_CLASS), owners)

    def test_legacy_single_manifest_path_still_validates_the_base_alone(self):
        """`--manifest` keeps working and keeps reporting the BASE record --
        585 entries, A22/B175/C268/D120 -- untouched by the new shard."""
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        failures, legacy = dti.validate_manifest(manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(legacy["manifest_assertions"], BASE_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(legacy["inventoried_assertions"], BASE_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(legacy["category_counts"], BASE_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(legacy["scoped_files"], sorted(f for f, _ in EXPECTED_SCOPE_ORDER))
        self.assertNotIn(SHARD_001_SOURCE_FILE, legacy["scoped_files"])
        self.assertEqual((legacy["unclassified"], legacy["stale"], legacy["fingerprint_mismatch"]), (0, 0, 0))

    def test_every_indexed_shard_meets_the_shard_format_contract(self):
        # The validator every added shard is held to, run on all of them.
        for shard in self.index["shards"]:
            with self.subTest(shard=shard):
                manifest = json.loads((ROOT / shard).read_text(encoding="utf-8"))
                failures = dti.validate_shard_file_format(ROOT / shard, manifest, shard=shard)
                self.assertEqual([f.format() for f in failures], [])
                self.assertLessEqual(len((ROOT / shard).read_text(encoding="utf-8").splitlines()),
                                     dti.SHARD_LINE_CAP)
        self.assertIn(EXPECTED_ENTRY_KEY_ORDER, dti.ENTRY_KEY_ORDERS)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)

    def test_base_manifest_is_byte_identical_and_unchanged_by_tranche_3h(self):
        raw = MANIFEST_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), BASE_MANIFEST_SHA256)
        text = raw.decode("utf-8")
        # The cap is why sharding exists: it must not be raised to make room.
        self.assertEqual(len(text.splitlines()), BASE_MANIFEST_LINE_COUNT)
        self.assertEqual(BASE_MANIFEST_LINE_CAP - BASE_MANIFEST_LINE_COUNT, 4)
        manifest = json.loads(text)
        self.assertEqual(len(manifest["assertions"]), BASE_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(Counter(e["category"] for e in manifest["assertions"]),
                         Counter(BASE_EXPECTED_CATEGORY_COUNTS))
        self.assertEqual([s["file"] for s in manifest["scope"]], [f for f, _ in EXPECTED_SCOPE_ORDER])
        # Tranche 3h added its 136 entries to a NEW file, not to this one.
        self.assertNotIn(SHARD_001_SOURCE_FILE, text)
        self.assertLess(BASE_EXPECTED_ASSERTION_COUNT, INDEX_COMBINED_ASSERTION_COUNT)


if __name__ == "__main__":
    unittest.main()
