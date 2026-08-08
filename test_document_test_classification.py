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
import document_test_utils as dtu

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

# What shard 001 WAS at tranche 3h merge; history, asserted NOT to be now.
TRANCHE_3H_HISTORICAL_ENTRY_COUNT = SHARD_001_EXPECTED_ASSERTION_COUNT
TRANCHE_3H_HISTORICAL_LINE_COUNT = SHARD_001_EXPECTED_LINE_COUNT
TRANCHE_3H_HISTORICAL_SHA256 = \
    "2d03c748b9136f324d597e9f539ba4738abfdd05e30d0cd69bd51081168442c4"


def _live_section(text, start, end):
    """The same slice `Bl034Round1ReviewCorrectionsTest._section()` takes, used
    to measure a C/D rationale against the live target document."""
    return text.split(start, 1)[1].split(end, 1)[0]


def _subset_content_digest(scope_entry, entries):
    """Canonical, key-order-independent digest of a shard SUBSET's PARSED
    content -- targets/action/contract_summary/rationale included. Raw key
    order stays contracted by EXPECTED_ENTRY_KEY_ORDER elsewhere."""
    payload = {"scope": scope_entry, "assertions": entries}
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# PR #91 round 1 (Blocker 1). Derived from shard 001 AS ACCEPTED at PR #90's
# merge commit 95d97f7318..., NOT regenerated from this branch.
TRANCHE_3H_HISTORICAL_CONTENT_SHA256 = \
    "1f0156b671555c9af25f0943fa06f458679d2020f141a14255794f39401d8489"

# Tranche 3i APPENDED to shard 001: 259 entries / 268 lines fit the cap.
TRANCHE_3I_SOURCE_FILE = SECURITY_REQUIREMENTS_SOURCE_FILE
TRANCHE_3I_CLASS = "Bl031SecurityRequirementsReconciliationTest"
_SRQ = TRANCHE_3I_SOURCE_FILE + "::" + TRANCHE_3I_CLASS + "::"
TRANCHE_3I_EXPECTED_ASSERTION_COUNT = 123
TRANCHE_3I_EXPECTED_METHOD_COUNT = 25

# Hardcoded (method, count) in source order; expands to the whole id list.
TRANCHE_3I_EXPECTED_METHOD_ORDER = (
    ("test_version_and_status_are_16_draft", 3),
    ("test_no_current_architecture_mention_of_removed_translation_path", 5),
    ("test_current_state_sections_1_through_7_have_no_stale_translation_text", 7),
    ("test_historical_sections_may_still_reference_the_removed_translation_path", 2),
    ("test_monomidigest_com_is_recorded_as_the_current_domain", 3),
    ("test_source_usage_policy_is_referenced_as_audit_only", 3),
    ("test_per_source_enforcement_is_implemented_and_no_longer_pending_acceptance", 5),
    ("test_bl031_is_recorded_in_status_recently_completed_work", 4),
    ("test_bl031_gemini_billing_confirmation_removed_from_backlog_residual_work", 6),
    ("test_bl031_backlog_records_paid_verified_owner_confirmation", 5),
    ("test_bl031_status_recently_completed_records_paid_verified", 4),
    ("test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical", 5),
    ("test_5_mode_restructuring_is_consistent_across_requirements_backlog_status", 10),
    ("test_bl031_backlog_no_longer_references_old_4_mode_pending_wording", 2),
    ("test_no_secret_shaped_values_across_bl031_documents", 3),
    ("test_sr_046_is_partially_met_not_met", 4),
    ("test_sr_045_is_met_after_gemini_owner_verification", 7),
    ("test_gap_017_is_completed_owner_verification_with_no_secrets", 7),
    ("test_section_13_gemini_row_is_verified_paid_verified", 3),
    ("test_control_mapping_reflects_sr046_partial_state_and_sr045_owner_verified", 4),
    ("test_sr_045_no_longer_describes_google_terms_recheck_as_pending", 2),
    ("test_trust_boundary_audit_date_follows_per_row_checked_at", 6),
    ("test_intro_clarifies_version_15_is_the_current_approved_baseline", 10),
    ("test_bl_and_sd_ids_referenced_are_unique_in_their_documents", 3),
    ("test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense", 10),
)

TRANCHE_3I_EXPECTED_C_IDS = frozenset({
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-02",
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-03",
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-04",
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-05",
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-06",
    _SRQ + "test_current_state_sections_1_through_7_have_no_stale_translation_text::assert-07",
    _SRQ + "test_historical_sections_may_still_reference_the_removed_translation_path::assert-01",
    _SRQ + "test_historical_sections_may_still_reference_the_removed_translation_path::assert-02",
    _SRQ + "test_monomidigest_com_is_recorded_as_the_current_domain::assert-01",
    _SRQ + "test_monomidigest_com_is_recorded_as_the_current_domain::assert-02",
    _SRQ + "test_source_usage_policy_is_referenced_as_audit_only::assert-03",
    _SRQ + "test_per_source_enforcement_is_implemented_and_no_longer_pending_acceptance::assert-02",
    _SRQ + "test_per_source_enforcement_is_implemented_and_no_longer_pending_acceptance::assert-03",
    _SRQ + "test_bl031_gemini_billing_confirmation_removed_from_backlog_residual_work::assert-01",
    _SRQ + "test_bl031_gemini_billing_confirmation_removed_from_backlog_residual_work::assert-02",
    _SRQ + "test_bl031_status_recently_completed_records_paid_verified::assert-03",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-02",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-03",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-04",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-05",
    _SRQ + "test_bl031_backlog_no_longer_references_old_4_mode_pending_wording::assert-01",
    _SRQ + "test_bl031_backlog_no_longer_references_old_4_mode_pending_wording::assert-02",
    _SRQ + "test_sr_046_is_partially_met_not_met::assert-04",
    _SRQ + "test_gap_017_is_completed_owner_verification_with_no_secrets::assert-04",
    _SRQ + "test_sr_045_no_longer_describes_google_terms_recheck_as_pending::assert-01",
    _SRQ + "test_sr_045_no_longer_describes_google_terms_recheck_as_pending::assert-02",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-01",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-02",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-03",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-04",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-05",
    _SRQ + "test_trust_boundary_audit_date_follows_per_row_checked_at::assert-06",
    _SRQ + "test_intro_clarifies_version_15_is_the_current_approved_baseline::assert-01",
    _SRQ + "test_intro_clarifies_version_15_is_the_current_approved_baseline::assert-04",
    _SRQ + "test_intro_clarifies_version_15_is_the_current_approved_baseline::assert-06",
    _SRQ + "test_intro_clarifies_version_15_is_the_current_approved_baseline::assert-08",
    _SRQ + "test_intro_clarifies_version_15_is_the_current_approved_baseline::assert-10",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-01",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-02",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-03",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-06",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-07",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-08",
    _SRQ + "test_section_11_google_terms_roadmap_item_is_a_completed_record_not_future_tense::assert-09",
})

TRANCHE_3I_EXPECTED_D_IDS = frozenset({
    _SRQ + "test_version_and_status_are_16_draft::assert-01",
    _SRQ + "test_version_and_status_are_16_draft::assert-03",
    _SRQ + "test_bl031_backlog_records_paid_verified_owner_confirmation::assert-02",
    _SRQ + "test_bl031_status_recently_completed_records_paid_verified::assert-02",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-01",
    _SRQ + "test_sr_045_is_met_after_gemini_owner_verification::assert-03",
    _SRQ + "test_gap_017_is_completed_owner_verification_with_no_secrets::assert-02",
    _SRQ + "test_section_13_gemini_row_is_verified_paid_verified::assert-02",
})

# NO Category A here either -- pinned explicitly; all 6 groups rejected as A.
TRANCHE_3I_EXPECTED_A_IDS = frozenset()

TRANCHE_3I_EXPECTED_CATEGORY_COUNTS = {
    "A": len(TRANCHE_3I_EXPECTED_A_IDS), "C": len(TRANCHE_3I_EXPECTED_C_IDS),
    "D": len(TRANCHE_3I_EXPECTED_D_IDS),
    "B": TRANCHE_3I_EXPECTED_ASSERTION_COUNT - len(TRANCHE_3I_EXPECTED_A_IDS)
    - len(TRANCHE_3I_EXPECTED_C_IDS) - len(TRANCHE_3I_EXPECTED_D_IDS),
}

# Each pair asserts the SAME literal against a DIFFERENT extracted document
# or row (BACKLOG BL-031 vs STATUS.md's line; SR-045 row vs GAP-017 row).
TRANCHE_3I_FINGERPRINT_DUPLICATE_GROUPS = tuple(
    tuple(_SRQ + i for i in pair) for pair in (
        ("test_bl031_backlog_records_paid_verified_owner_confirmation::assert-01",
         "test_bl031_status_recently_completed_records_paid_verified::assert-01"),
        ("test_bl031_backlog_records_paid_verified_owner_confirmation::assert-02",
         "test_bl031_status_recently_completed_records_paid_verified::assert-02"),
        ("test_bl031_status_recently_completed_records_paid_verified::assert-04",
         "test_5_mode_restructuring_is_consistent_across_requirements_backlog_status::assert-03"),
        ("test_sr_045_is_met_after_gemini_owner_verification::assert-03",
         "test_gap_017_is_completed_owner_verification_with_no_secrets::assert-02"),
        ("test_sr_045_is_met_after_gemini_owner_verification::assert-04",
         "test_gap_017_is_completed_owner_verification_with_no_secrets::assert-03"),
        ("test_sr_045_is_met_after_gemini_owner_verification::assert-05",
         "test_gap_017_is_completed_owner_verification_with_no_secrets::assert-05"),
    )
)

# Cross-shard collisions with the FROZEN base; all agree with its category.
TRANCHE_3I_CROSS_SHARD_FINGERPRINT_CATEGORIES = {
    _SRQ + "test_version_and_status_are_16_draft::assert-01": "D",
    _SRQ + "test_version_and_status_are_16_draft::assert-02": "B",
    _SRQ + "test_version_and_status_are_16_draft::assert-03": "D",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-01": "D",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-02": "C",
    _SRQ + "test_status_as_of_is_2026_08_04_and_bl030_run_evidence_is_historical::assert-04": "C",
}

# The only multi-target entries: one loop, 3 call sites, 4 documents each.
_BL031_DOCUMENTS = (
    "SOURCE_USAGE_POLICY.md", "SECURITY_REQUIREMENTS.md", "BACKLOG.md", "STATUS.md",
)
TRANCHE_3I_MULTI_TARGETS = {
    _SRQ + f"test_no_secret_shaped_values_across_bl031_documents::assert-0{n}":
    _BL031_DOCUMENTS
    for n in (1, 2, 3)
}

# PR #91 round 1 (Blocker 2). MEASURED: 0 shared fingerprints with 3h's 136.
TRANCHE_3I_VS_TRANCHE_3H_FINGERPRINT_COLLISIONS = frozenset()
TRANCHE_3I_VS_TRANCHE_3H_FINGERPRINT_SET_SIZES = (134, 117)

# Shard 001 CURRENT state, after the tranche 3i append.
SHARD_001_CURRENT_ENTRY_COUNT = \
    TRANCHE_3H_HISTORICAL_ENTRY_COUNT + TRANCHE_3I_EXPECTED_ASSERTION_COUNT
SHARD_001_CURRENT_LINE_COUNT = 268
SHARD_001_CURRENT_SHA256 = \
    "0e1893593594daf44fb52e32ea610f2f7deb572148338faf90f2edfa7949b2cd"
SHARD_001_CURRENT_SCOPE_ORDER = (
    (SHARD_001_SOURCE_FILE, SHARD_001_EXPECTED_CLASSES),
    (TRANCHE_3I_SOURCE_FILE, (TRANCHE_3I_CLASS,)),
)
SHARD_001_CURRENT_CATEGORY_COUNTS = {
    cat: SHARD_001_EXPECTED_CATEGORY_COUNTS[cat] + TRANCHE_3I_EXPECTED_CATEGORY_COUNTS[cat]
    for cat in ("A", "B", "C", "D")
}

# ---------------------------------------------------------------------------
# BL-038 tranche 3j: shard 002, `test_security_operations.py::Bl035DraftSyncTest`.
#
# Why a NEW shard rather than another append to shard 001 -- all three facts
# are measured on this branch, not assumed (see the shard-allocation guards in
# Tranche3jClassificationShard002Test):
#   1. `validate_manifest` rejects a manifest that lists the same file twice
#      (`duplicate-scope-file`), so shard 001 cannot gain a SECOND
#      `test_security_operations.py` scope entry for this class.
#   2. Adding the class to shard 001's EXISTING scope[0] instead would change
#      scope[0], which the tranche 3h historical-content digest
#      TRANCHE_3H_HISTORICAL_CONTENT_SHA256 pins as an accepted contract; that
#      guard is not weakened to make room.
#   3. The 600-line cap is NOT the reason: shard 001 is 268 lines and 34 more
#      entries would still fit. This is a scope-structure necessity, not a
#      capacity one.
# Cross-shard ownership is by (file, class), so a separate shard owning only
# this one class is legal -- that is the growth path the validator documents.
SHARD_002_FILENAME = "document_test_classification_002.json"
SHARD_002_PATH = ROOT / SHARD_002_FILENAME
TRANCHE_3J_SOURCE_FILE = SHARD_001_SOURCE_FILE
TRANCHE_3J_CLASS = SHARD_001_UNOWNED_CLASS
_B35 = TRANCHE_3J_SOURCE_FILE + "::" + TRANCHE_3J_CLASS + "::"
TRANCHE_3J_EXPECTED_ASSERTION_COUNT = 34
TRANCHE_3J_EXPECTED_METHOD_COUNT = 7

# Hardcoded (method, count) in source order; expands to the whole id list.
TRANCHE_3J_EXPECTED_METHOD_ORDER = (
    ("test_version_is_12_approved_as_of_20260803", 3),
    ("test_downgrade_procedure_names_its_source_of_truth_and_sync_targets", 1),
    ("test_downgrade_procedure_distinguishes_metadata_only_and_disabled_legal_review", 6),
    ("test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language", 4),
    ("test_downgrade_procedure_still_protects_past_output_and_requires_review", 6),
    ("test_section_12_links_bl035_and_states_no_production_change", 4),
    ("test_section_12_records_version_12_final_acceptance_via_pr75", 10),
)

TRANCHE_3J_EXPECTED_API_COUNTS = {"assertIn": 33, "assertNotIn": 1}

TRANCHE_3J_EXPECTED_A_IDS = frozenset()
TRANCHE_3J_EXPECTED_C_IDS = frozenset({
    _B35 + "test_downgrade_procedure_distinguishes_metadata_only_and_disabled_legal_review::assert-03",
    _B35 + "test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language::assert-01",
    _B35 + "test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language::assert-02",
    _B35 + "test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language::assert-03",
    _B35 + "test_downgrade_procedure_still_protects_past_output_and_requires_review::assert-03",
    _B35 + "test_downgrade_procedure_still_protects_past_output_and_requires_review::assert-04",
    _B35 + "test_downgrade_procedure_still_protects_past_output_and_requires_review::assert-06",
    _B35 + "test_section_12_links_bl035_and_states_no_production_change::assert-01",
    _B35 + "test_section_12_links_bl035_and_states_no_production_change::assert-04",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-03",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-04",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-05",
    # PR #92 round 1: `Ready-for-review` is this document's own editorial
    # phrasing, not a provider-defined state name -- B -> C.
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-06",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-07",
})
TRANCHE_3J_EXPECTED_D_IDS = frozenset({
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-01",
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-03",
    _B35 + "test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language::assert-04",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-01",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-02",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-08",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-09",
    _B35 + "test_section_12_records_version_12_final_acceptance_via_pr75::assert-10",
})
TRANCHE_3J_EXPECTED_CATEGORY_COUNTS = {
    "A": 0,
    "B": 12,
    "C": len(TRANCHE_3J_EXPECTED_C_IDS),
    "D": len(TRANCHE_3J_EXPECTED_D_IDS),
}

# No two of the 34 share a fingerprint: nothing here is an A candidate on
# repetition grounds, and the emptiness is asserted, not assumed.
TRANCHE_3J_FINGERPRINT_DUPLICATE_GROUPS = ()

# The only cross-shard fingerprint collisions, measured against BOTH the
# frozen base 585 and shard 001's 259. Each maps to the category the existing
# manifests already recorded for that fingerprint -- agreement is required,
# but a fingerprint match alone never promotes an entry to A (PR #85 round 2
# explicitly corrected both of these literals away from A).
TRANCHE_3J_CROSS_SHARD_FINGERPRINT_CATEGORIES = {
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-01": "D",
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-02": "B",
}
TRANCHE_3J_VS_BASE_COLLISION_IDS = {
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-01": (
        STATUS_SOURCE_FILE + "::StatusSecurityOperationsSourceOfTruthTest"
        "::test_security_operations_itself_reflects_bl035_final_acceptance::assert-01"
    ),
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-02": (
        STATUS_SOURCE_FILE + "::StatusSecurityOperationsSourceOfTruthTest"
        "::test_security_operations_itself_reflects_bl035_final_acceptance::assert-02"
    ),
}
TRANCHE_3J_VS_SHARD_001_COLLISION_IDS = {
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-01": (
        _SO + "SecurityOperationsContractTest"
        "::test_version_10_identity_review_record_and_user_approval::assert-03"
    ),
    _B35 + "test_version_is_12_approved_as_of_20260803::assert-02": (
        _SO + "SecurityOperationsContractTest"
        "::test_version_10_identity_review_record_and_user_approval::assert-04"
    ),
}

# Shard 002 AS ACCEPTED AT TRANCHE 3J's MERGE (commit f068270e5e...). These
# are HISTORY: tranche 3k appended to the same file, so the current file has
# different stats. Every one of these is asserted NOT to be current below.
TRANCHE_3J_HISTORICAL_ENTRY_COUNT = TRANCHE_3J_EXPECTED_ASSERTION_COUNT
TRANCHE_3J_HISTORICAL_LINE_COUNT = 42
TRANCHE_3J_HISTORICAL_SHA256 = \
    "3772b37ff4de747a594ec2bef2025e199f9ee967c5dc83a9cae550663c924dbb"
SHARD_002_HISTORICAL_SCOPE_ORDER = (
    (TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
)
# Canonical parsed-content digest of scope[0] + the historical first 34
# entries, DERIVED FROM SHARD 002 AS ACCEPTED at merge commit
# f068270e5ed5c8a453371f0b6d63cde9f0f84d53 -- not regenerated from the
# appended file on this branch. It pins every field the id/category/order
# guards cannot see (targets, action, contract_summary, rationale).
TRANCHE_3J_HISTORICAL_CONTENT_SHA256 = \
    "d4d7f9324f6630e105b695a61f3d649e7779f4e17e47275ebd8cdd9cd31d7295"

# ---------------------------------------------------------------------------
# BL-038 tranche 3k: `test_pr_ci_workflow.py::PullRequestCIWorkflowTest`,
# APPENDED to shard 002 as its second scope entry.
#
# Why shard 002 rather than a new `_003` -- measured, not assumed (see the
# allocation guards in Tranche3kClassificationShard002AppendTest): (1) the
# selected file is in NO existing shard's scope, so a second scope entry
# raises no `duplicate-scope-file`; (2) appending leaves shard 001
# byte-identical, so the 3h digest and the 3i accepted SHA are untouched;
# (3) shard 002's accepted state stays pinnable as a subset digest; (4) the
# 600-line cap does not bind (42 + 1 + 27 = 70); (5) the index stays at three
# shards. A tranche-specific minimal-change choice because more than one
# existing shard was viable -- not a permanent allocator policy.
TRANCHE_3K_SOURCE_FILE = "test_pr_ci_workflow.py"
TRANCHE_3K_CLASS = "PullRequestCIWorkflowTest"
TRANCHE_3K_TARGET_WORKFLOW = ".github/workflows/pr-ci.yml"
_PRC = TRANCHE_3K_SOURCE_FILE + "::" + TRANCHE_3K_CLASS + "::"
TRANCHE_3K_EXPECTED_ASSERTION_COUNT = 27
TRANCHE_3K_EXPECTED_METHOD_COUNT = 7

# Hardcoded (method, count) in source order; expands to the whole id list.
TRANCHE_3K_EXPECTED_METHOD_ORDER = (
    ("test_workflow_file_exists", 1),
    ("test_uses_safe_pull_request_trigger", 3),
    ("test_has_read_only_repository_permissions", 2),
    ("test_checkout_and_python_are_pinned_safely", 7),
    ("test_limits_runtime_and_cancels_superseded_runs", 3),
    ("test_does_not_use_secrets_or_production_commands", 7),
    ("test_runs_full_suite_and_checks_actual_pull_request_diff", 4),
)

TRANCHE_3K_EXPECTED_API_COUNTS = {
    "assertTrue": 1,
    "assertIn": 7,
    "assertNotIn": 9,
    "assertRegex": 7,
    "assertNotRegex": 3,
}

# No A: every Category A entry in this project is backed by an identical
# fingerprint shared across call sites, and this class has none (asserted in
# test_no_two_of_the_27_share_a_fingerprint). Three C shapes, each demonstrated
# by a temporary meaning-preserving mutation of the live workflow: multi-line
# YAML layout locks; a full commit SHA welded to its inert `# vX.Y.Z` comment;
# a quote-style lock (PR #93 round 1, Blocker 1).
TRANCHE_3K_EXPECTED_A_IDS = frozenset()
TRANCHE_3K_EXPECTED_C_IDS = frozenset({
    _PRC + "test_uses_safe_pull_request_trigger::assert-01",
    _PRC + "test_has_read_only_repository_permissions::assert-01",
    _PRC + "test_checkout_and_python_are_pinned_safely::assert-01",
    _PRC + "test_checkout_and_python_are_pinned_safely::assert-04",
    _PRC + "test_checkout_and_python_are_pinned_safely::assert-05",
})
# No D: this class contracts the CURRENT workflow only -- no dates, no PR
# numbers, no CI run ids, and a pinned SHA is current structural contract.
TRANCHE_3K_EXPECTED_D_IDS = frozenset()
TRANCHE_3K_EXPECTED_CATEGORY_COUNTS = {
    "A": 0, "B": 22, "C": len(TRANCHE_3K_EXPECTED_C_IDS), "D": 0,
}

# All 27 fingerprints are distinct and none collides with the frozen base 585,
# shard 001's 259, or shard 002's own accepted tranche 3j 34 -- all asserted.
TRANCHE_3K_FINGERPRINT_DUPLICATE_GROUPS = ()
TRANCHE_3K_VS_BASE_COLLISION_IDS = {}
TRANCHE_3K_VS_SHARD_001_COLLISION_IDS = {}
TRANCHE_3K_VS_TRANCHE_3J_COLLISION_IDS = {}

# Shard 002 as ACCEPTED at PR #93's merge commit
# 764da66947a9b480ee2f074d553111a8e5bb278c: the tranche 3j 34 followed by the
# tranche 3k 27. Tranche 3l appended a THIRD scope entry, so every value here
# is HISTORY -- each one is asserted below NOT to be the current state.
TRANCHE_3K_HISTORICAL_ENTRY_COUNT = (TRANCHE_3J_HISTORICAL_ENTRY_COUNT
                                     + TRANCHE_3K_EXPECTED_ASSERTION_COUNT)
TRANCHE_3K_HISTORICAL_LINE_COUNT = 70
TRANCHE_3K_HISTORICAL_SHA256 = \
    "1aee40fda499ac4308daa24fbd6fe622daab0dabd9390ecdb3014f36c7ae9da1"
TRANCHE_3K_HISTORICAL_SCOPE_ORDER = ((TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
                                     (TRANCHE_3K_SOURCE_FILE, (TRANCHE_3K_CLASS,)))
TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS = {
    cat: TRANCHE_3J_EXPECTED_CATEGORY_COUNTS[cat] + TRANCHE_3K_EXPECTED_CATEGORY_COUNTS[cat]
    for cat in ("A", "B", "C", "D")}
# Parsed-content digest of scope[0:2] + the historical first 61, DERIVED FROM
# SHARD 002 AS ACCEPTED at merge 764da669... -- NOT regenerated here.
TRANCHE_3K_HISTORICAL_CONTENT_SHA256 = \
    "233c98393937c21e7890270c6cd7b8478272e010c4299177344d0b1099164a1e"

# ---------------------------------------------------------------------------
# BL-038 tranche 3l: `test_workflow_action_pinning.py` -- the WHOLE file, its
# two source-order contiguous classes -- APPENDED to shard 002 as scope[2].
# Why shard 002 and not a new `_003` is MEASURED: see the allocation guards.
TRANCHE_3L_SOURCE_FILE = "test_workflow_action_pinning.py"
TRANCHE_3L_CLASSES = ("WorkflowActionPinningTest", "DependabotConfigurationTest")
TRANCHE_3L_TARGET_FETCH_WORKFLOW = ".github/workflows/fetch.yml"
TRANCHE_3L_TARGET_PR_CI_WORKFLOW = ".github/workflows/pr-ci.yml"
TRANCHE_3L_TARGET_DEPENDABOT = ".github/dependabot.yml"
TRANCHE_3L_BOTH_WORKFLOWS = [TRANCHE_3L_TARGET_FETCH_WORKFLOW, TRANCHE_3L_TARGET_PR_CI_WORKFLOW]
_WAP = TRANCHE_3L_SOURCE_FILE + "::" + TRANCHE_3L_CLASSES[0] + "::"
_DPB = TRANCHE_3L_SOURCE_FILE + "::" + TRANCHE_3L_CLASSES[1] + "::"
TRANCHE_3L_EXPECTED_CLASS_COUNT = 2
TRANCHE_3L_EXPECTED_ASSERTION_COUNT = 23
TRANCHE_3L_EXPECTED_METHOD_COUNT = 14

# Hardcoded (class prefix, method, count) in source order across BOTH classes.
TRANCHE_3L_EXPECTED_METHOD_ORDER = ((_WAP, "test_workflow_files_exist", 2),
    (_WAP, "test_checkout_uses_are_pinned_to_forty_char_sha", 3),
    (_WAP, "test_setup_python_uses_are_pinned_to_forty_char_sha", 3),
    (_WAP, "test_checkout_sha_matches_approved_v7_0_1", 1),
    (_WAP, "test_setup_python_sha_matches_approved_v7_0_0", 1),
    (_WAP, "test_no_mutable_major_version_tag_remains", 4),
    (_WAP, "test_no_arbitrary_branch_or_tag_reference_is_allowed", 1),
    (_DPB, "test_dependabot_file_exists", 1), (_DPB, "test_declares_version_2", 1),
    (_DPB, "test_has_exactly_one_update_entry", 1),
    (_DPB, "test_ecosystem_is_github_actions_only", 2),
    (_DPB, "test_directory_is_repository_root", 1), (_DPB, "test_schedule_is_weekly", 1),
    (_DPB, "test_does_not_include_optional_policy_fields", 1), )
TRANCHE_3L_EXPECTED_API_COUNTS = {"assertTrue": 5, "assertEqual": 3, "assertRegex": 7,
                                  "assertIn": 2, "assertNotIn": 4, "assertNotRegex": 2}

# The A pair: the two methods are byte-identical once the single varying action
# identifier is normalised, so ALL SIX of their assertions are one parameterised
# repetition a shared helper would absorb. PR #94 round 1 (Blocker 1) corrected
# the two leading assertTrue calls B -> A: their message literals embed the
# action name, so fingerprints differ -- but that is not a bar to A.
TRANCHE_3L_A_METHOD_PAIR = ("test_checkout_uses_are_pinned_to_forty_char_sha",
                            "test_setup_python_uses_are_pinned_to_forty_char_sha")
TRANCHE_3L_A_VARYING_TOKENS = ("actions/checkout", "actions/setup-python")
TRANCHE_3L_EXPECTED_A_IDS = frozenset(
    f"{_WAP}{method}::assert-{n:02d}" for method in TRANCHE_3L_A_METHOD_PAIR for n in (1, 2, 3))
# Three C shapes: SHA welded to an inert `# vX.Y.Z` comment (2), quote-style
# locks whose plain scalar is the identical string (3), raw absence over
# ordinary English words (1). Their union IS the C set.
TRANCHE_3L_EXPECTED_SHA_COMMENT_C_IDS = frozenset({
    _WAP + "test_checkout_sha_matches_approved_v7_0_1::assert-01",
    _WAP + "test_setup_python_sha_matches_approved_v7_0_0::assert-01"})
TRANCHE_3L_EXPECTED_QUOTE_LOCK_C_IDS = frozenset({
    _DPB + "test_ecosystem_is_github_actions_only::assert-01",
    _DPB + "test_directory_is_repository_root::assert-01",
    _DPB + "test_schedule_is_weekly::assert-01"})
TRANCHE_3L_EXPECTED_PROSE_ABSENCE_C_IDS = frozenset({
    _DPB + "test_does_not_include_optional_policy_fields::assert-01"})
TRANCHE_3L_EXPECTED_C_IDS = (TRANCHE_3L_EXPECTED_SHA_COMMENT_C_IDS
                             | TRANCHE_3L_EXPECTED_QUOTE_LOCK_C_IDS
                             | TRANCHE_3L_EXPECTED_PROSE_ABSENCE_C_IDS)
# No date, PR number or CI run id anywhere: the pinned SHAs are the CURRENT
# contract, not historical evidence, so exactness alone is not Category D.
TRANCHE_3L_EXPECTED_D_IDS = frozenset()
TRANCHE_3L_EXPECTED_CATEGORY_COUNTS = {"A": 6, "B": 11, "C": 6, "D": 0}
# Ordered by fingerprint (assertRegex before assertEqual), ids sorted.
TRANCHE_3L_FINGERPRINT_DUPLICATE_GROUPS = tuple(
    tuple(f"{_WAP}{method}::assert-{n:02d}" for method in TRANCHE_3L_A_METHOD_PAIR)
    for n in (3, 2))
# Both subTest iterables in the Dependabot class, exact and in order: a
# fingerprint covers only `assertNotIn(...)`, not what it loops over.
TRANCHE_3L_PROHIBITED = {"other": ("pip", "npm", "docker", "npm-workspaces"),
    "marker": ("reviewers", "assignees", "labels", "target-branch",
               "open-pull-requests-limit", "registries", "groups", "ignore")}
TRANCHE_3L_VS_BASE_COLLISION_IDS = {}
TRANCHE_3L_VS_SHARD_001_COLLISION_IDS = {}
TRANCHE_3L_VS_TRANCHE_3K_HISTORICAL_COLLISION_IDS = {}

# Shard 002 AS ACCEPTED at PR #94's merge commit 48cc4fdf383030..., the state
# tranche 3l closed out with: 84 entries, 94 lines, scope[0:3], A6/B45/C25/D8.
# Tranche 3m appended a FOURTH scope entry, so every value here is HISTORY and
# is asserted below NOT to be the current state.
TRANCHE_3L_HISTORICAL_ENTRY_COUNT = (TRANCHE_3K_HISTORICAL_ENTRY_COUNT
                                     + TRANCHE_3L_EXPECTED_ASSERTION_COUNT)
TRANCHE_3L_HISTORICAL_LINE_COUNT = 94
TRANCHE_3L_HISTORICAL_SHA256 = \
    "c0f81d1489109e1fe9a6a8dcef497496b7c3b39ad435a84ca06944a43409aaa2"
TRANCHE_3L_HISTORICAL_SCOPE_ORDER = ((TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
    (TRANCHE_3K_SOURCE_FILE, (TRANCHE_3K_CLASS,)), (TRANCHE_3L_SOURCE_FILE, TRANCHE_3L_CLASSES), )
TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS = {
    cat: TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS[cat] + TRANCHE_3L_EXPECTED_CATEGORY_COUNTS[cat]
    for cat in ("A", "B", "C", "D")}
# Parsed-content digest of scope[0:3] plus the historical first 84, DERIVED FROM
# SHARD 002 AS ACCEPTED at merge 48cc4fdf383030... -- NOT regenerated here.
TRANCHE_3L_HISTORICAL_CONTENT_SHA256 = \
    "47fa2d11c1aae9bf298db175ddbd76c8776bad00491ae034e85d4bee441e8391"

# ---------------------------------------------------------------------------
# BL-038 tranche 3m: `test_security_requirements.py::Bl034Round1ReviewCorrectionsTest`
# -- the file's ONLY remaining eligible class, at source-order class index 3 --
# APPENDED to shard 002 as scope[3]. Why not shard 001, which already carries a
# DIFFERENT class of the SAME file: a second same-file scope entry there is
# `duplicate-scope-file` (mutation-proved below), and widening shard 001's
# existing entry instead would have to rewrite a byte-frozen shard whose hash
# anchors the tranche 3h digest. The 600-line cap did not decide it: 268 + 17
# would also have fit.
TRANCHE_3M_SOURCE_FILE = SECURITY_REQUIREMENTS_SOURCE_FILE
TRANCHE_3M_CLASS = "Bl034Round1ReviewCorrectionsTest"
_B34 = TRANCHE_3M_SOURCE_FILE + "::" + TRANCHE_3M_CLASS + "::"
TRANCHE_3M_SOURCE_CLASS_INDEX = 3
TRANCHE_3M_EXPECTED_ASSERTION_COUNT = 17
TRANCHE_3M_EXPECTED_METHOD_COUNT = 7
# The classes of this file OTHER shards own, so the selection is provably the
# only unclassified contiguous run besides the over-cap `SecurityRequirementsTest`.
TRANCHE_3M_OVER_CAP_CLASS = "SecurityRequirementsTest"
TRANCHE_3M_OVER_CAP_ASSERTION_COUNT = 403
TRANCHE_3M_SELECTION_CAP = 150

# Hardcoded (method, count) in source order.
TRANCHE_3M_EXPECTED_METHOD_ORDER = (("test_bl009_is_an_in_progress_umbrella_not_completed", 2),
    ("test_bl034_is_complete_with_the_accepted_implementation_head_recorded", 2),
    ("test_dashboard_and_search_console_confirmation_are_post_merge_only", 2), ("test_gap_018_is_a_policy_decision_not_a_security_gap", 2),
    ("test_bl032_runtime_implementation_is_accepted_and_merged_not_draft", 5), ("test_requirements_document_itself_is_version_17_draft", 2),
    ("test_footer_and_beacon_destinations_are_distinguished_everywhere", 2), )
TRANCHE_3M_EXPECTED_API_COUNTS = {"assertIn": 10, "assertNotIn": 3, "assertRegex": 2, "assertNotRegex": 1, "assertFalse": 1}
TRANCHE_3M_TARGET_BL009 = "BACKLOG.md#BL-009"
TRANCHE_3M_TARGET_BL034 = "BACKLOG.md#BL-034"
TRANCHE_3M_TARGET_GAP_REGISTER = "SECURITY_REQUIREMENTS.md#8-Gap-register"
TRANCHE_3M_TARGET_GAP_016 = "SECURITY_REQUIREMENTS.md#GAP-016"
TRANCHE_3M_TARGET_GAP_018 = "SECURITY_REQUIREMENTS.md#GAP-018"
TRANCHE_3M_TARGET_REQUIREMENTS = "SECURITY_REQUIREMENTS.md"

# No Category A: the seven methods each lock a DIFFERENT one of PR #72 round 1's
# seven corrections, with different extraction scopes, different assertion
# sequences and arities (2/2/2/2/5/2/2) and mixed categories inside a method, so
# no pair is whole-method parameterisable. The one genuine cross-class whole-
# method repetition -- this class's BL-009 method against the shape-identical
# `Bl034ImplementationAcceptanceTest::test_bl009_remains_the_in_progress_umbrella`
# -- was already declined for consolidation by the accepted base manifest, whose
# rationale records that each anchors a different round's snapshot.
TRANCHE_3M_EXPECTED_A_IDS = frozenset()
# Three methods share an AST node-type skeleton (node types cannot distinguish
# `assertIn` from `assertNotIn`), so the skeleton is NOT the A measure here.
TRANCHE_3M_SHARED_SKELETON_METHODS = ["test_bl009_is_an_in_progress_umbrella_not_completed",
    "test_bl034_is_complete_with_the_accepted_implementation_head_recorded", "test_dashboard_and_search_console_confirmation_are_post_merge_only"]
# The BL-009 whole-method twin that is deliberately NOT consolidated: same
# section bounds, same two assertions, in a base-manifest class this tranche
# must not touch.
TRANCHE_3M_BL009_TWIN_METHOD = ("Bl034ImplementationAcceptanceTest", "test_bl009_remains_the_in_progress_umbrella")
# Four C shapes, all reword-brittle: a welded status enum plus parenthetical (1),
# a bold label opening a giant single-line prose item plus a phrase inside that
# same line (2), raw English clauses about BL-032's current state (3), and a
# normalized document-global prose absence check (1).
TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS = frozenset({_B34 + "test_bl009_is_an_in_progress_umbrella_not_completed::assert-01"})
TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS = frozenset({_B34 + "test_dashboard_and_search_console_confirmation_are_post_merge_only::assert-01",
    _B34 + "test_dashboard_and_search_console_confirmation_are_post_merge_only::assert-02"})
TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS = frozenset({_B34 + "test_bl032_runtime_implementation_is_accepted_and_merged_not_draft::assert-03",
    _B34 + "test_bl032_runtime_implementation_is_accepted_and_merged_not_draft::assert-04",
    _B34 + "test_bl032_runtime_implementation_is_accepted_and_merged_not_draft::assert-05"})
TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS = frozenset({_B34 + "test_footer_and_beacon_destinations_are_distinguished_everywhere::assert-01"})
TRANCHE_3M_EXPECTED_C_IDS = (TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS | TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS
                             | TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS | TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS)
# Two D: an exact 40-char accepted implementation head, and the exact Version
# field value this repository already classifies D in six accepted entries.
TRANCHE_3M_EXPECTED_D_IDS = frozenset({_B34 + "test_bl034_is_complete_with_the_accepted_implementation_head_recorded::assert-02",
    _B34 + "test_requirements_document_itself_is_version_17_draft::assert-01"})
TRANCHE_3M_EXPECTED_CATEGORY_COUNTS = {"A": 0, "B": 8, "C": 7, "D": 2}
TRANCHE_3M_ACCEPTED_HEAD_SHA = "6d032e702e1b118bc6da86b981a4189b4a85e15b"
TRANCHE_3M_FINGERPRINT_DUPLICATE_GROUPS = ()
# Cross-shard fingerprint collisions ARE expected here (unlike 3j-3l): six of the
# 17 repeat an assertion already classified elsewhere. Each id maps to the ids it
# collides with AND the category each carries, so a silent reclassification of an
# accepted entry cannot pass unnoticed.
_IMPL = TRANCHE_3M_SOURCE_FILE + "::Bl034ImplementationAcceptanceTest::"
_CLOSE = TRANCHE_3M_SOURCE_FILE + "::Bl034CloseoutTest::"
_ACC = TRANCHE_3M_SOURCE_FILE + "::Bl031AcceptanceAndBl032RegistrationTest::"
_R2 = TRANCHE_3M_SOURCE_FILE + "::Bl034Round2ReviewCorrectionsTest::"
_SOT = TRANCHE_3M_SOURCE_FILE + "::StatusSecurityRequirementsSourceOfTruthTest::"
_BL9 = "test_bl009_is_an_in_progress_umbrella_not_completed::assert-0"
_BL9O = "test_bl009_remains_the_in_progress_umbrella::assert-0"
_BL9C = "test_bl009_is_still_the_in_progress_umbrella_with_full_scope::assert-0"
_V17 = "test_requirements_document_itself_is_version_17_draft::assert-0"
_VAPP = "test_security_requirements_version_17_is_approved_and_current_baseline::assert-0"
_VCLO = "test_security_requirements_version_17_approved_is_unchanged_by_closeout::assert-0"
_VFIX = "test_security_requirements_itself_is_unchanged_by_this_fix::assert-0"
_VSUP = ("test_source_usage_policy_20260731_snapshot_and_security_requirements_" "current_version::assert-0")
TRANCHE_3M_VS_BASE_COLLISIONS = {_B34 + _BL9 + "1": {"test_custom_domain.py::Bl007DocumentationTest::"
        "test_bl009_scope_and_state_are_unchanged::assert-01": "B", _IMPL + _BL9O + "1": "C", _CLOSE + _BL9C + "1": "C"},
    _B34 + _BL9 + "2": {_IMPL + _BL9O + "2": "B", _CLOSE + _BL9C + "2": "B"},
    _B34 + "test_bl034_is_complete_with_the_accepted_implementation_head_recorded::assert-01": {
        _IMPL + "test_bl034_is_complete_with_acceptance_round_evidence_preserved::assert-01": "B",
        _CLOSE + "test_bl034_is_complete_with_no_residual_work::assert-01": "B",
        _CLOSE + "test_pr73_final_acceptance_is_recorded_in_backlog::assert-07": "B"},
    _B34 + "test_dashboard_and_search_console_confirmation_are_post_merge_only::assert-02": {
        _IMPL + "test_bl034_has_no_residual_work_after_closeout::assert-01": "C"},
    _B34 + _V17 + "1": {_ACC + _VSUP + "4": "D", _IMPL + _VAPP + "1": "D", _CLOSE + _VCLO + "1": "D", _SOT + _VFIX + "1": "D",
        _R2 + "test_version_17_is_the_current_draft_and_16_is_not_called_this_version::"
              "assert-01": "D"}, _B34 + _V17 + "2": {_ACC + _VSUP + "5": "B", _IMPL + _VAPP + "2": "B",
        _CLOSE + _VCLO + "2": "B", _SOT + _VFIX + "2": "B"}, }
TRANCHE_3M_VS_SHARD_001_COLLISIONS = {_B34 + _V17 + "1": {_SRQ + "test_version_and_status_are_16_draft::assert-01": "D"},
    _B34 + _V17 + "2": {_SRQ + "test_version_and_status_are_16_draft::assert-02": "B"}}
# Against shard 002's own accepted 84 there is nothing: a different source file.
TRANCHE_3M_VS_TRANCHE_3L_HISTORICAL_COLLISIONS = {}
# The one id whose colliding entries do NOT all agree, and the documented reason.
TRANCHE_3M_DIVERGENT_COLLISION_ID = _B34 + _BL9 + "1"

# -- section/source bindings the per-assertion fingerprints cannot see --------
# PR #95 rounds 1-2 (Blocker 1): the tranche 3m contract covers ONLY the setUpClass
# document bindings the selected 17 actually read. `cls.status` is assigned there but
# no selected assertion touches it, so this tranche fixes nothing about it -- neither
# path nor existence nor absence: retargeting OR deleting it leaves this guard passing.
TRANCHE_3M_USED_DOCUMENT_BINDINGS = {"requirements": "SECURITY_REQUIREMENTS.md", "backlog": "BACKLOG.md"}
# `_section(text, start, end=None)` -- the scoping contract every method rests on.
TRANCHE_3M_SECTION_HELPER_NAME = "_section"
TRANCHE_3M_SECTION_HELPER_BODY = ("after = text.split(start, 1)[1]\n" "return after.split(end, 1)[0] if end else after")
# Method-local section bindings: (method, local name, source attr, start, end).
TRANCHE_3M_SECTION_BINDINGS = (("test_bl009_is_an_in_progress_umbrella_not_completed",
     "bl009", "backlog", "## BL-009", "\n## BL-010"), ("test_bl034_is_complete_with_the_accepted_implementation_head_recorded",
     "bl034", "backlog", "## BL-034", "\n## 完了済み参照"), ("test_dashboard_and_search_console_confirmation_are_post_merge_only",
     "bl034", "backlog", "## BL-034", "\n## 完了済み参照"), ("test_gap_018_is_a_policy_decision_not_a_security_gap", "gaps", "requirements", "## 8. Gap register",
     "## 9. Explicitly non-required controls for the current architecture"),
    ("test_bl032_runtime_implementation_is_accepted_and_merged_not_draft", "gaps", "requirements", "## 8. Gap register",
     "## 9. Explicitly non-required controls for the current architecture"), )
# The GAP-016 row filter: retargeting it to another gap leaves every downstream
# assertion fingerprint identical.
TRANCHE_3M_GAP_016_ROW_BINDING = ("gap016_row", "gaps", "| GAP-016 |")
# The footer stale-phrase bindings, both routed through normalize_markdown_prose.
TRANCHE_3M_STALE_BINDING = ("stale", "dtu.normalize_markdown_prose('first external network destination " "(`static.cloudflareinsights.com`)')")
TRANCHE_3M_NORMALIZED_REQUIREMENTS_BINDING = ("normalized_requirements", "dtu.normalize_markdown_prose(self.requirements)")
TRANCHE_3M_BEACON_ENDPOINT = "cloudflareinsights.com/cdn-cgi/rum"

# Shard 002 CURRENT state: the accepted 84 followed by the tranche 3m 17.
SHARD_002_CURRENT_ENTRY_COUNT = (TRANCHE_3L_HISTORICAL_ENTRY_COUNT + TRANCHE_3M_EXPECTED_ASSERTION_COUNT)
SHARD_002_CURRENT_LINE_COUNT = 112
SHARD_002_CURRENT_SHA256 = \
    "d86d521627dabfed4b4555b8759a50c9a3538a9d89d55c8f2e5d928845e39f46"
SHARD_002_CURRENT_SCOPE_ORDER = ((TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
    (TRANCHE_3K_SOURCE_FILE, (TRANCHE_3K_CLASS,)), (TRANCHE_3L_SOURCE_FILE, TRANCHE_3L_CLASSES), (TRANCHE_3M_SOURCE_FILE, (TRANCHE_3M_CLASS,)), )
SHARD_002_CURRENT_CATEGORY_COUNTS = {cat: TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS[cat]
    + TRANCHE_3M_EXPECTED_CATEGORY_COUNTS[cat] for cat in ("A", "B", "C", "D") }

# Current index state. Tranche 3g's "exactly one shard" and tranche 3i's
# "exactly two shards" survive below as HISTORY only, both asserted NOT to be
# the current shard count.
EXPECTED_SHARD_ORDER = (MANIFEST_PATH.name, SHARD_001_FILENAME, SHARD_002_FILENAME)
EXPECTED_SHARD_COUNT = len(EXPECTED_SHARD_ORDER)
TRANCHE_3G_HISTORICAL_SHARD_COUNT = 1
TRANCHE_3I_HISTORICAL_SHARD_COUNT = 2
INDEX_COMBINED_ASSERTION_COUNT = (
    BASE_EXPECTED_ASSERTION_COUNT
    + SHARD_001_CURRENT_ENTRY_COUNT
    + SHARD_002_CURRENT_ENTRY_COUNT
)
INDEX_COMBINED_CATEGORY_COUNTS = {
    cat: BASE_EXPECTED_CATEGORY_COUNTS[cat]
    + SHARD_001_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_002_CURRENT_CATEGORY_COUNTS[cat]
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
    """BL-038 tranche 3h's OWN subset of shard 001, kept intact after
    tranche 3i appended to the same file. `entries` is deliberately that
    subset only; the current whole-file stats live in the tranche 3i class."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_001_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == SHARD_001_SOURCE_FILE]
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
        # Per-FILE tally here; whole-file totals belong to tranche 3i.
        self.assertEqual(summary["file_counts"][SHARD_001_SOURCE_FILE],
                         SHARD_001_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(self.entries), SHARD_001_EXPECTED_ASSERTION_COUNT)
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

    def test_tranche_3h_parsed_content_still_equals_the_accepted_record(self):
        """PR #91 round 1 (Blocker 1). The id/category/order guards cannot
        see an edit to a historical entry's targets/action/summary/rationale.
        Reconstructing the subset from the CURRENT file must digest to the
        value derived from PR #90's accepted shard -- pinning all 136
        entries' whole content without copying them into this test."""
        self.assertEqual(
            _subset_content_digest(self.shard["scope"][0], self.entries),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )
        # Demonstrated: the digest moves for each blind-spot field.
        for field, value in (
            ("targets", ["README.md"]),
            ("action", "keep"),
            ("contract_summary", "rewritten"),
            ("rationale", "rewritten"),
        ):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(self.entries))
                self.assertNotEqual(mutated[0][field], value)
                mutated[0][field] = value
                self.assertNotEqual(
                    _subset_content_digest(self.shard["scope"][0], mutated),
                    TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
                )
        # A scope edit and a reordering are caught as well.
        self.assertNotEqual(
            _subset_content_digest({"file": "x.py", "classes": []}, self.entries),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )
        self.assertNotEqual(
            _subset_content_digest(self.shard["scope"][0], self.entries[::-1]),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )

    def test_tranche_3h_file_snapshot_is_history_not_the_current_file(self):
        """136 / 144 / SHA 2d03c748 was shard 001 AT TRANCHE 3H MERGE, so
        those numbers are history, asserted NOT to describe the file today."""
        self.assertEqual(TRANCHE_3H_HISTORICAL_ENTRY_COUNT, 136)
        self.assertEqual(TRANCHE_3H_HISTORICAL_LINE_COUNT, 144)
        self.assertEqual(len(self.entries), TRANCHE_3H_HISTORICAL_ENTRY_COUNT)
        current_lines = len(self.shard_text.splitlines())
        current_sha = hashlib.sha256(SHARD_001_PATH.read_bytes()).hexdigest()
        self.assertNotEqual(current_lines, TRANCHE_3H_HISTORICAL_LINE_COUNT)
        self.assertNotEqual(current_sha, TRANCHE_3H_HISTORICAL_SHA256)
        self.assertNotEqual(len(self.all_entries), TRANCHE_3H_HISTORICAL_ENTRY_COUNT)
        self.assertEqual(
            [e["id"] for e in self.all_entries[:TRANCHE_3H_HISTORICAL_ENTRY_COUNT]],
            self.expected_ids_in_source_order(),
        )
        self.assertEqual(
            dict(Counter(e["category"] for e in self.entries)),
            {k: v for k, v in SHARD_001_EXPECTED_CATEGORY_COUNTS.items() if v},
        )

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
        self.assertLess(
            len([e for e in mutated["assertions"] if e["file"] == SHARD_001_SOURCE_FILE]),
            SHARD_001_EXPECTED_ASSERTION_COUNT,
        )
        with self.assertRaises(AssertionError):
            self.assertEqual(
                tuple(mutated["scope"][0]["classes"]), SHARD_001_EXPECTED_CLASSES
            )


class Tranche3iClassificationShardAppendTest(unittest.TestCase):
    """BL-038 tranche 3i: 123 new entries APPENDED to shard 001 (measured to
    fit, so no `_002` shard and no index change). Guards the tranche 3i
    subset and the file's resulting CURRENT whole-file state."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_001_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == TRANCHE_3I_SOURCE_FILE]
        cls.by_id = {e["id"]: e for e in cls.entries}
        source = (ROOT / TRANCHE_3I_SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(
            source, TRANCHE_3I_SOURCE_FILE, [TRANCHE_3I_CLASS]
        )
        cls.source_classes = [
            n.name for n in ast.parse(source, filename=TRANCHE_3I_SOURCE_FILE).body
            if isinstance(n, ast.ClassDef)
        ]

    def expected_ids_in_source_order(self):
        return [
            f"{_SRQ}{method}::assert-{ordinal:02d}"
            for method, count in TRANCHE_3I_EXPECTED_METHOD_ORDER
            for ordinal in range(1, count + 1)
        ]

    def test_scope_appends_the_selected_class_without_touching_tranche_3h(self):
        scope = self.shard["scope"]
        self.assertEqual(
            tuple((s["file"], tuple(s["classes"])) for s in scope),
            SHARD_001_CURRENT_SCOPE_ORDER,
        )
        # Second class in source order; the base owns 5 later ones.
        self.assertEqual(self.source_classes[1], TRANCHE_3I_CLASS)
        base_scope = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["scope"]
        base_classes = {
            c for s in base_scope if s["file"] == TRANCHE_3I_SOURCE_FILE for c in s["classes"]
        }
        self.assertNotIn(TRANCHE_3I_CLASS, base_classes)
        for neighbour in ("SecurityRequirementsTest", "Bl034Round1ReviewCorrectionsTest"):
            with self.subTest(neighbour=neighbour):
                self.assertIn(neighbour, self.source_classes)
                self.assertNotIn(neighbour, base_classes)
                self.assertNotIn(neighbour, scope[1]["classes"])

    def test_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual(len(expected), TRANCHE_3I_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(TRANCHE_3I_EXPECTED_METHOD_ORDER), TRANCHE_3I_EXPECTED_METHOD_COUNT)
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertEqual([r.id for r in self.live_records], expected)
        # Appended AFTER the tranche 3h block, never interleaved with it.
        self.assertEqual(
            [e["id"] for e in self.all_entries[TRANCHE_3H_HISTORICAL_ENTRY_COUNT:]], expected
        )

    def test_entries_match_the_live_source_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], TRANCHE_3I_SOURCE_FILE)
                self.assertEqual(entry["class"], TRANCHE_3I_CLASS)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual((entry["method"], entry["ordinal"]), (record.method, record.ordinal))
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)
        self.assertEqual(
            dict(Counter(e["assertion_api"] for e in self.entries)),
            {"assertIn": 77, "assertNotIn": 33, "assertNotRegex": 5,
             "assertEqual": 3, "assertRegex": 3, "assertFalse": 2},
        )

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        all_ids = frozenset(self.by_id)
        expected_b_ids = (
            all_ids
            - TRANCHE_3I_EXPECTED_A_IDS
            - TRANCHE_3I_EXPECTED_C_IDS
            - TRANCHE_3I_EXPECTED_D_IDS
        )
        self.assertEqual(TRANCHE_3I_EXPECTED_A_IDS, frozenset())
        self.assertEqual(TRANCHE_3I_EXPECTED_CATEGORY_COUNTS["A"], 0)
        self.assertEqual([e["id"] for e in self.entries if e["category"] == "A"], [])
        for id_, category in (
            [(i, "C") for i in TRANCHE_3I_EXPECTED_C_IDS]
            + [(i, "D") for i in TRANCHE_3I_EXPECTED_D_IDS]
            + [(i, "B") for i in expected_b_ids]
        ):
            with self.subTest(id=id_, category=category):
                self.assertIn(id_, self.by_id)
                self.assertEqual(self.by_id[id_]["category"], category)
                self.assertEqual(self.by_id[id_]["action"], dti.CATEGORY_TO_ACTION[category])
        counts = Counter(e["category"] for e in self.entries)
        self.assertEqual(dict(counts), {k: v for k, v in TRANCHE_3I_EXPECTED_CATEGORY_COUNTS.items() if v})
        self.assertEqual(
            (counts["A"], counts["B"], counts["C"], counts["D"]), (0, 71, 44, 8)
        )
        self.assertEqual(sum(counts.values()), TRANCHE_3I_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(expected_b_ids), TRANCHE_3I_EXPECTED_CATEGORY_COUNTS["B"])

    def test_entries_are_well_formed_and_use_the_fixed_key_order(self):
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertNotIn("target", entry)
                self.assertTrue(entry["targets"])
                self.assertEqual(len(set(entry["targets"])), len(entry["targets"]))
                for target in entry["targets"]:
                    # Targets may carry a `#section` anchor; the file must exist.
                    self.assertTrue((ROOT / target.split("#", 1)[0]).exists(), target)
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
        multi = {e["id"]: tuple(e["targets"]) for e in self.entries if len(e["targets"]) > 1}
        self.assertEqual(multi, TRANCHE_3I_MULTI_TARGETS)

    def test_fingerprint_duplicate_groups_are_not_category_a(self):
        by_fingerprint = {}
        for entry in self.entries:
            by_fingerprint.setdefault(entry["fingerprint"], []).append(entry["id"])
        groups = sorted(tuple(ids) for ids in by_fingerprint.values() if len(ids) > 1)
        self.assertEqual(groups, sorted(TRANCHE_3I_FINGERPRINT_DUPLICATE_GROUPS))
        for group in groups:
            with self.subTest(group=group):
                for id_ in group:
                    self.assertNotIn(id_, TRANCHE_3I_EXPECTED_A_IDS)
                    self.assertNotEqual(self.by_id[id_]["category"], "A")
                # Groups agree internally: no hidden category conflict.
                self.assertEqual(len({self.by_id[i]["category"] for i in group}), 1)

    def test_no_fingerprint_collision_with_the_tranche_3h_subset(self):
        """PR #91 round 1 (Blocker 2). The duplicate review's third leg --
        tranche 3i against tranche 3h -- measured at 0 collisions, so no
        cross-tranche group needs an A call and no 3h category is touched."""
        historical = {
            e["fingerprint"] for e in self.all_entries if e["file"] == SHARD_001_SOURCE_FILE
        }
        mine = {e["fingerprint"] for e in self.entries}
        self.assertEqual(historical & mine, TRANCHE_3I_VS_TRANCHE_3H_FINGERPRINT_COLLISIONS)
        self.assertEqual(TRANCHE_3I_VS_TRANCHE_3H_FINGERPRINT_COLLISIONS, frozenset())
        # Not vacuous: both sides are populated, at their measured sizes.
        self.assertEqual((len(historical), len(mine)),
                         TRANCHE_3I_VS_TRANCHE_3H_FINGERPRINT_SET_SIZES)
        # Nearest miss, proving the 0 is real: both scopes assert the same
        # `AIza...` regex; only the subject expression differs.
        by_id = {e["id"]: e for e in self.all_entries}
        old_id = (
            SHARD_001_SOURCE_FILE + "::Bl031SecurityOperationsReconciliationTest::"
            "test_gemini_owner_verification_is_completed_as_paid_verified::assert-08"
        )
        new_id = _SRQ + "test_bl031_backlog_records_paid_verified_owner_confirmation::assert-05"
        self.assertEqual(by_id[old_id]["assertion_api"], by_id[new_id]["assertion_api"])
        self.assertEqual(by_id[old_id]["assertion_api"], "assertNotRegex")
        self.assertNotEqual(by_id[old_id]["fingerprint"], by_id[new_id]["fingerprint"])

    def test_cross_shard_fingerprint_collisions_agree_with_the_base_manifest(self):
        """Same-fingerprint entries already classified in the FROZEN base
        manifest keep that classification here; none is rewritten."""
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]
        base_by_fingerprint = {}
        for entry in base:
            base_by_fingerprint.setdefault(entry["fingerprint"], set()).add(entry["category"])
        collisions = {
            e["id"]: e["category"] for e in self.entries if e["fingerprint"] in base_by_fingerprint
        }
        self.assertEqual(collisions, TRANCHE_3I_CROSS_SHARD_FINGERPRINT_CATEGORIES)
        for entry in self.entries:
            base_categories = base_by_fingerprint.get(entry["fingerprint"])
            if base_categories:
                with self.subTest(id=entry["id"]):
                    self.assertEqual(base_categories, {entry["category"]})

    def test_current_shard_file_meets_the_format_contract_within_the_line_cap(self):
        failures = dti.validate_shard_file_format(SHARD_001_PATH, self.shard, shard=SHARD_001_FILENAME)
        self.assertEqual([f.format() for f in failures], [])
        lines = self.shard_text.splitlines()
        self.assertEqual(len(lines), SHARD_001_CURRENT_LINE_COUNT)
        self.assertLessEqual(len(lines), dti.SHARD_LINE_CAP)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)  # cap not raised
        self.assertEqual(
            hashlib.sha256(SHARD_001_PATH.read_bytes()).hexdigest(), SHARD_001_CURRENT_SHA256
        )
        self.assertTrue(self.shard_text.endswith("\n"))
        start = lines.index('  "assertions": [')
        entry_lines = lines[start + 1 : lines.index("  ]", start)]
        self.assertEqual(len(entry_lines), SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual(len(self.all_entries), SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual(SHARD_001_CURRENT_ENTRY_COUNT, 136 + 123)
        for offset, line in enumerate(entry_lines):
            with self.subTest(line=start + 2 + offset):
                parsed = json.loads(line.strip().rstrip(","), object_pairs_hook=OrderedDict)
                self.assertEqual(tuple(parsed.keys()), EXPECTED_ENTRY_KEY_ORDER)
        self.assertEqual(json.loads(self.shard_text), self.shard)
        self.assertEqual(len({e["id"] for e in self.all_entries}), SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual(
            dict(Counter(e["category"] for e in self.all_entries)),
            {k: v for k, v in SHARD_001_CURRENT_CATEGORY_COUNTS.items() if v},
        )
        failures, summary = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["manifest_assertions"], SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))

    def test_tranche_3i_two_shard_index_is_history_not_the_current_index(self):
        """Tranche 3i deliberately appended rather than adding a `_002` shard,
        so at its merge the index held exactly two shards and no `_002` file
        existed. Tranche 3j added one -- not because shard 001 ran out of room
        (it did not; see the line-cap assertion below) but because a second
        `test_security_operations.py` scope entry is rejected as
        `duplicate-scope-file` and editing scope[0] would break the pinned
        tranche 3h historical digest. This records the 3i state as HISTORY and
        asserts it is no longer current."""
        self.assertEqual(TRANCHE_3I_HISTORICAL_SHARD_COUNT, 2)
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        self.assertEqual(index["shards"], list(EXPECTED_SHARD_ORDER))
        self.assertEqual(len(index["shards"]), EXPECTED_SHARD_COUNT)
        self.assertNotEqual(len(index["shards"]), TRANCHE_3I_HISTORICAL_SHARD_COUNT)
        self.assertEqual(index["shards"][:2], [MANIFEST_PATH.name, SHARD_001_FILENAME])
        self.assertEqual(dti.discover_shard_filenames(ROOT), sorted(EXPECTED_SHARD_ORDER))
        self.assertTrue(SHARD_002_PATH.exists())
        # Shard 001 keeping room is exactly why this is a structural decision
        # rather than a capacity one.
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT, dti.SHARD_LINE_CAP)
        self.assertLess(
            SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
            dti.SHARD_LINE_CAP,
        )

    def test_appending_to_shard_001_does_not_disturb_the_base_manifest(self):
        raw = MANIFEST_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), BASE_MANIFEST_SHA256)
        self.assertEqual(len(raw.decode("utf-8").splitlines()), BASE_MANIFEST_LINE_COUNT)
        self.assertNotIn(TRANCHE_3I_CLASS, raw.decode("utf-8"))


class Tranche3jClassificationShard002Test(unittest.TestCase):
    """BL-038 tranche 3j's OWN subset of shard 002 -- the 34 assertions of
    `test_security_operations.py::Bl035DraftSyncTest` -- kept intact after
    tranche 3k appended a second scope entry to the same file. `entries` is
    deliberately that subset only; the current whole-file stats live in
    Tranche3kClassificationShard002AppendTest. The tranche 3j shard-allocation
    decision (a NEW shard 002 rather than an append to shard 001) is still
    measured here, not asserted by fiat -- see
    test_a_second_scope_entry_for_this_file_is_rejected_as_duplicate and
    test_editing_shard_001_scope_0_would_break_the_pinned_3h_digest."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_002_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text, object_pairs_hook=OrderedDict)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == TRANCHE_3J_SOURCE_FILE]
        cls.by_id = {e["id"]: e for e in cls.entries}
        source = (ROOT / TRANCHE_3J_SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(
            source, TRANCHE_3J_SOURCE_FILE, [TRANCHE_3J_CLASS]
        )
        cls.source_classes = [
            n.name for n in ast.parse(source, filename=TRANCHE_3J_SOURCE_FILE).body
            if isinstance(n, ast.ClassDef)
        ]

    def expected_ids_in_source_order(self):
        return [
            f"{_B35}{method}::assert-{ordinal:02d}"
            for method, count in TRANCHE_3J_EXPECTED_METHOD_ORDER
            for ordinal in range(1, count + 1)
        ]

    # -- scope -------------------------------------------------------------

    def test_shard_002_scope_0_is_still_exactly_the_tranche_3j_class(self):
        scope = self.shard["scope"]
        self.assertEqual(
            (scope[0]["file"], tuple(scope[0]["classes"])),
            SHARD_002_HISTORICAL_SCOPE_ORDER[0],
        )
        # At tranche 3j's merge the shard held exactly this one scope entry.
        # Tranche 3k appended a second: history, asserted NOT to be current.
        self.assertEqual(len(SHARD_002_HISTORICAL_SCOPE_ORDER), 1)
        self.assertNotEqual(len(scope), len(SHARD_002_HISTORICAL_SCOPE_ORDER))
        self.assertEqual(len(scope), len(SHARD_002_CURRENT_SCOPE_ORDER))
        self.assertEqual(scope[0]["file"], TRANCHE_3J_SOURCE_FILE)
        self.assertEqual(scope[0]["classes"], [TRANCHE_3J_CLASS])
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))
        # Third and last class in source order; shard 001 owns the first two.
        self.assertEqual(self.source_classes, list(SHARD_001_EXPECTED_CLASSES) + [TRANCHE_3J_CLASS])
        self.assertEqual(self.source_classes[2], TRANCHE_3J_CLASS)
        self.assertEqual(TRANCHE_3J_CLASS, SHARD_001_UNOWNED_CLASS)
        base_text = MANIFEST_PATH.read_text(encoding="utf-8")
        self.assertNotIn(TRANCHE_3J_CLASS, base_text)
        self.assertNotIn(TRANCHE_3J_CLASS, SHARD_001_PATH.read_text(encoding="utf-8"))

    # -- shard-allocation decision, measured -------------------------------

    def test_a_second_scope_entry_for_this_file_is_rejected_as_duplicate(self):
        """Reason 1 shard 001 could not absorb this class: one manifest may
        not list the same file twice."""
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))
        mutated = json.loads(json.dumps(shard_001))
        mutated["scope"].append(
            {"file": TRANCHE_3J_SOURCE_FILE, "classes": [TRANCHE_3J_CLASS]}
        )
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        self.assertIn("duplicate-scope-file", {f.mismatch_type for f in failures})
        # The unmutated shard 001 is clean, so the failure is the edit's doing.
        clean_failures, _ = dti.validate_manifest(shard_001, root=ROOT)
        self.assertEqual([f.format() for f in clean_failures], [])

    def test_editing_shard_001_scope_0_would_break_the_pinned_3h_digest(self):
        """Reason 2: the alternative -- adding the class to shard 001's
        EXISTING scope[0] -- changes the tranche 3h accepted historical
        contract. The guard is not weakened; the shard is added instead."""
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))
        historical = shard_001["assertions"][:TRANCHE_3H_HISTORICAL_ENTRY_COUNT]
        self.assertEqual(
            _subset_content_digest(shard_001["scope"][0], historical),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )
        mutated_scope = json.loads(json.dumps(shard_001["scope"][0]))
        mutated_scope["classes"] = mutated_scope["classes"] + [TRANCHE_3J_CLASS]
        self.assertNotEqual(
            _subset_content_digest(mutated_scope, historical),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )

    def test_the_line_cap_was_not_the_reason_a_new_shard_was_added(self):
        """Reason 3, stated negatively: shard 001 had room. This is a
        scope-structure decision, not a capacity one."""
        self.assertEqual(SHARD_001_CURRENT_LINE_COUNT, 268)
        self.assertEqual(dti.SHARD_LINE_CAP, 600)
        self.assertLess(
            SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
            dti.SHARD_LINE_CAP,
        )

    def test_shard_001_is_byte_identical_to_its_accepted_tranche_3i_state(self):
        raw = SHARD_001_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SHARD_001_CURRENT_SHA256)
        text = raw.decode("utf-8")
        self.assertEqual(len(text.splitlines()), SHARD_001_CURRENT_LINE_COUNT)
        shard_001 = json.loads(text)
        self.assertEqual(len(shard_001["assertions"]), SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual(SHARD_001_CURRENT_ENTRY_COUNT, 259)
        self.assertEqual(
            tuple((s["file"], tuple(s["classes"])) for s in shard_001["scope"]),
            SHARD_001_CURRENT_SCOPE_ORDER,
        )

    # -- membership --------------------------------------------------------

    def test_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual(len(expected), TRANCHE_3J_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(TRANCHE_3J_EXPECTED_ASSERTION_COUNT, 34)
        self.assertEqual(len(TRANCHE_3J_EXPECTED_METHOD_ORDER), TRANCHE_3J_EXPECTED_METHOD_COUNT)
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertEqual([r.id for r in self.live_records], expected)
        self.assertEqual(
            sum(count for _, count in TRANCHE_3J_EXPECTED_METHOD_ORDER),
            TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
        )
        # Every method named exists on the live class, and no other does.
        _, known = dti.scan_classes(
            (ROOT / TRANCHE_3J_SOURCE_FILE).read_text(encoding="utf-8"),
            TRANCHE_3J_SOURCE_FILE, [TRANCHE_3J_CLASS],
        )
        self.assertEqual(
            sorted(m for m, _ in TRANCHE_3J_EXPECTED_METHOD_ORDER),
            sorted(known[(TRANCHE_3J_SOURCE_FILE, TRANCHE_3J_CLASS)]),
        )

    def test_entries_match_the_live_source_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual(entry["file"], TRANCHE_3J_SOURCE_FILE)
                self.assertEqual(entry["class"], TRANCHE_3J_CLASS)
                self.assertEqual(entry["class"], record.cls)
                self.assertEqual((entry["method"], entry["ordinal"]), (record.method, record.ordinal))
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)
                self.assertEqual(entry["targets"], ["SECURITY_OPERATIONS.md"])

    def test_api_breakdown_matches_the_measured_live_source(self):
        self.assertEqual(
            dict(Counter(e["assertion_api"] for e in self.entries)),
            TRANCHE_3J_EXPECTED_API_COUNTS,
        )
        self.assertEqual(
            dict(Counter(r.assertion_api for r in self.live_records)),
            TRANCHE_3J_EXPECTED_API_COUNTS,
        )
        self.assertEqual(sum(TRANCHE_3J_EXPECTED_API_COUNTS.values()),
                         TRANCHE_3J_EXPECTED_ASSERTION_COUNT)
        # The single negative assertion is the stale-BL-032-language check.
        negatives = [e["id"] for e in self.entries if e["assertion_api"] == "assertNotIn"]
        self.assertEqual(negatives, [
            _B35 + "test_downgrade_procedure_and_section11_have_no_stale_bl032_deferred_language"
                   "::assert-01",
        ])

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        by_category = {}
        for entry in self.entries:
            by_category.setdefault(entry["category"], set()).add(entry["id"])
        self.assertEqual(by_category.get("A", set()), set(TRANCHE_3J_EXPECTED_A_IDS))
        self.assertEqual(by_category.get("C", set()), set(TRANCHE_3J_EXPECTED_C_IDS))
        self.assertEqual(by_category.get("D", set()), set(TRANCHE_3J_EXPECTED_D_IDS))
        # B is the exact remainder -- never its own hand-listed set.
        expected_b = (
            set(self.expected_ids_in_source_order())
            - set(TRANCHE_3J_EXPECTED_A_IDS)
            - set(TRANCHE_3J_EXPECTED_C_IDS)
            - set(TRANCHE_3J_EXPECTED_D_IDS)
        )
        self.assertEqual(by_category.get("B", set()), expected_b)
        self.assertEqual(
            dict(Counter(e["category"] for e in self.entries)),
            {k: v for k, v in TRANCHE_3J_EXPECTED_CATEGORY_COUNTS.items() if v},
        )
        self.assertEqual(TRANCHE_3J_EXPECTED_CATEGORY_COUNTS,
                         {"A": 0, "B": 12, "C": 14, "D": 8})
        self.assertEqual(sum(TRANCHE_3J_EXPECTED_CATEGORY_COUNTS.values()),
                         TRANCHE_3J_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(TRANCHE_3J_EXPECTED_A_IDS, frozenset())

    def test_entries_are_well_formed_and_use_the_fixed_key_order(self):
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertIn(entry["category"], dti.VALID_CATEGORIES)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
                self.assertTrue(entry["contract_summary"].strip())
                self.assertTrue(entry["rationale"].strip())
                self.assertNotIn("target", entry)
                self.assertEqual(len(entry["targets"]), 1)
                lowered = (entry["contract_summary"] + entry["rationale"]).lower()
                for placeholder in _PLACEHOLDER_WORDS:
                    self.assertNotIn(placeholder, lowered)

    # -- fingerprint review ------------------------------------------------

    def test_no_two_of_the_34_share_a_fingerprint(self):
        counts = Counter(e["fingerprint"] for e in self.entries)
        groups = tuple(
            tuple(sorted(e["id"] for e in self.entries if e["fingerprint"] == fingerprint))
            for fingerprint, n in sorted(counts.items()) if n > 1
        )
        self.assertEqual(groups, TRANCHE_3J_FINGERPRINT_DUPLICATE_GROUPS)
        self.assertEqual(groups, ())
        self.assertEqual(len(counts), TRANCHE_3J_EXPECTED_ASSERTION_COUNT)  # not vacuous

    def test_cross_shard_collisions_agree_with_the_base_and_shard_001(self):
        """Measured against BOTH already-accepted manifests. A fingerprint
        match confirms agreement; it never promotes an entry to A."""
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))["assertions"]
        mine_by_fingerprint = {e["fingerprint"]: e for e in self.entries}

        for label, existing, expected_map in (
            ("base", base, TRANCHE_3J_VS_BASE_COLLISION_IDS),
            ("shard_001", shard_001, TRANCHE_3J_VS_SHARD_001_COLLISION_IDS),
        ):
            with self.subTest(against=label):
                hits = {}
                for entry in existing:
                    mine = mine_by_fingerprint.get(entry["fingerprint"])
                    if mine is not None:
                        hits.setdefault(mine["id"], set()).add(entry["id"])
                        # Category agreement is required, both directions.
                        self.assertEqual(mine["category"], entry["category"])
                self.assertEqual({k: sorted(v) for k, v in hits.items()},
                                 {k: [v] for k, v in expected_map.items()})
                self.assertEqual(len(hits), 2)
                for id_ in hits:
                    self.assertEqual(
                        self.by_id[id_]["category"],
                        TRANCHE_3J_CROSS_SHARD_FINGERPRINT_CATEGORIES[id_],
                    )
                    self.assertNotEqual(self.by_id[id_]["category"], "A")
                    self.assertNotIn(id_, TRANCHE_3J_EXPECTED_A_IDS)
        # The two colliding literals are the header Version/Status fields:
        # exact-value evidence (D) and a fixed-vocabulary field (B).
        self.assertEqual(
            set(TRANCHE_3J_CROSS_SHARD_FINGERPRINT_CATEGORIES.values()), {"B", "D"}
        )
        self.assertEqual(
            sorted(TRANCHE_3J_VS_BASE_COLLISION_IDS),
            sorted(TRANCHE_3J_VS_SHARD_001_COLLISION_IDS),
        )
        # The other 32 collide with nothing already classified.
        existing_fingerprints = {e["fingerprint"] for e in base} | {
            e["fingerprint"] for e in shard_001
        }
        fresh = [e["id"] for e in self.entries if e["fingerprint"] not in existing_fingerprints]
        self.assertEqual(len(fresh), TRANCHE_3J_EXPECTED_ASSERTION_COUNT - 2)

    # -- accepted tranche 3j state, preserved as history --------------------

    def test_tranche_3j_parsed_content_still_equals_the_accepted_record(self):
        """The id/category/order guards above cannot see an edit to a
        historical entry's targets/action/summary/rationale. Reconstructing
        scope[0] + the first 34 entries from the CURRENT file must digest to
        the value derived from shard 002 AS ACCEPTED at merge commit
        f068270e5e... -- not regenerated from the file this branch edited."""
        self.assertEqual(
            _subset_content_digest(self.shard["scope"][0], self.entries),
            TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
        )
        # The historical 34 really are the FIRST 34, in their accepted order.
        self.assertEqual(
            self.entries, self.all_entries[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]
        )
        # Demonstrated: the digest moves for each blind-spot field, for a
        # scope edit, for a reordering, and for the append itself -- so the
        # subset guard is not vacuous.
        for field, value in (("targets", ["README.md"]), ("action", "keep"),
                             ("contract_summary", "x"), ("rationale", "x")):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(self.entries))
                self.assertNotEqual(mutated[0][field], value)
                mutated[0][field] = value
                self.assertNotEqual(
                    _subset_content_digest(self.shard["scope"][0], mutated),
                    TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
                )
        for scope, entries in (({"file": "x.py", "classes": []}, self.entries),
                               (self.shard["scope"][0], self.entries[::-1]),
                               (self.shard["scope"][0], self.all_entries)):
            self.assertNotEqual(
                _subset_content_digest(scope, entries),
                TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
            )

    def test_tranche_3j_file_snapshot_is_history_not_the_current_file(self):
        """34 / 42 / SHA 3772b37f was shard 002 AT TRANCHE 3J's MERGE, so those
        numbers are history, asserted NOT to describe the file today."""
        self.assertEqual(TRANCHE_3J_HISTORICAL_ENTRY_COUNT, 34)
        self.assertEqual(TRANCHE_3J_HISTORICAL_LINE_COUNT, 42)
        self.assertEqual(len(self.entries), TRANCHE_3J_HISTORICAL_ENTRY_COUNT)
        current_lines = len(self.shard_text.splitlines())
        current_sha = hashlib.sha256(SHARD_002_PATH.read_bytes()).hexdigest()
        self.assertNotEqual(current_lines, TRANCHE_3J_HISTORICAL_LINE_COUNT)
        self.assertNotEqual(current_sha, TRANCHE_3J_HISTORICAL_SHA256)
        self.assertNotEqual(len(self.all_entries), TRANCHE_3J_HISTORICAL_ENTRY_COUNT)
        self.assertEqual(current_sha, SHARD_002_CURRENT_SHA256)
        self.assertEqual(
            dict(Counter(e["category"] for e in self.entries)),
            {k: v for k, v in TRANCHE_3J_EXPECTED_CATEGORY_COUNTS.items() if v},
        )

    def test_scope_shrinkage_mutation_of_shard_002_is_detected(self):
        """Dropping the class from scope must not silently pass: the entries
        would then belong to no scoped class at all."""
        mutated = json.loads(json.dumps(self.shard))
        mutated["scope"][0]["classes"] = []
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        self.assertNotEqual([f.format() for f in failures], [])

    def test_no_category_c_source_conversion_happened_in_this_tranche(self):
        """Tranche 3j classified only, and tranche 3k did not convert its C
        entries either: every C entry in the 3j subset is still parked with
        the refactor_later action and the live source is untouched."""
        for entry in self.entries:
            if entry["category"] == "C":
                with self.subTest(id=entry["id"]):
                    self.assertEqual(entry["action"], "refactor_later")
        self.assertEqual(
            sum(1 for e in self.entries if e["action"] == "refactor_later"),
            TRANCHE_3J_EXPECTED_CATEGORY_COUNTS["C"],
        )


class Tranche3kClassificationShard002AppendTest(unittest.TestCase):
    """BL-038 tranche 3k: the 27 assertions of
    `test_pr_ci_workflow.py::PullRequestCIWorkflowTest`, APPENDED to shard 002
    rather than opening a `_003`. Kept intact after tranche 3l appended a
    THIRD scope entry to the same file: this class now pins tranche 3k's own
    27 plus the shard-002 state ACCEPTED at PR #93's merge -- 61 entries, 70
    lines, SHA `1aee40fd...` -- as HISTORY. The CURRENT whole-file contract
    lives in Tranche3lClassificationShard002AppendTest; the accepted tranche
    3j subset stays pinned in Tranche3jClassificationShard002Test."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_002_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text, object_pairs_hook=OrderedDict)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == TRANCHE_3K_SOURCE_FILE]
        cls.by_id = {e["id"]: e for e in cls.entries}
        source = (ROOT / TRANCHE_3K_SOURCE_FILE).read_text(encoding="utf-8")
        cls.live_records = dti.enumerate_assertions(source, TRANCHE_3K_SOURCE_FILE,
                                                    [TRANCHE_3K_CLASS])
        cls.source_classes = [n.name for n in ast.parse(source).body
                              if isinstance(n, ast.ClassDef)]

    def expected_ids_in_source_order(self):
        return [f"{_PRC}{method}::assert-{ordinal:02d}"
                for method, count in TRANCHE_3K_EXPECTED_METHOD_ORDER
                for ordinal in range(1, count + 1)]

    # -- scope -------------------------------------------------------------

    def test_shard_002_scope_is_the_tranche_3j_class_then_the_tranche_3k_one(self):
        scope = self.shard["scope"]
        # The accepted 3k scope is still the first TWO entries, in order; the
        # third is tranche 3l's and is contracted in that tranche's class.
        self.assertEqual(tuple((e["file"], tuple(e["classes"])) for e in scope[:2]),
                         TRANCHE_3K_HISTORICAL_SCOPE_ORDER)
        self.assertEqual(TRANCHE_3K_HISTORICAL_SCOPE_ORDER,
                         SHARD_002_CURRENT_SCOPE_ORDER[:2])
        self.assertNotEqual(TRANCHE_3K_HISTORICAL_SCOPE_ORDER,
                            SHARD_002_CURRENT_SCOPE_ORDER)
        self.assertEqual(scope[1]["file"], TRANCHE_3K_SOURCE_FILE)
        self.assertEqual(scope[1]["classes"], [TRANCHE_3K_CLASS])
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))
        # The class is the WHOLE selected file, owned by nothing before now.
        self.assertEqual(self.source_classes, [TRANCHE_3K_CLASS])
        self.assertNotIn(TRANCHE_3K_SOURCE_FILE, MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(TRANCHE_3K_SOURCE_FILE, SHARD_001_PATH.read_text(encoding="utf-8"))

    # -- shard-allocation decision, measured -------------------------------

    def test_the_append_is_legal_and_leaves_the_older_shards_untouched(self):
        """Reasons 1-2. (1) The selected file appears in no other scope entry,
        so no `duplicate-scope-file` -- unlike tranche 3j, whose class shared a
        file with shard 001's scope[0]; the constraint is still enforced here.
        (2) Choosing shard 002 leaves the OLDER shard byte-identical, so the
        3h historical digest and the 3i accepted SHA survive un-re-derived."""
        files = [e["file"] for e in self.shard["scope"]]
        self.assertEqual(len(files), len(set(files)))
        self.assertEqual(files.count(TRANCHE_3K_SOURCE_FILE), 1)
        failures, _ = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        mutated = json.loads(json.dumps(self.shard))
        mutated["scope"].append({"file": TRANCHE_3K_SOURCE_FILE, "classes": [TRANCHE_3K_CLASS]})
        dup_failures, _ = dti.validate_manifest(mutated, root=ROOT)
        self.assertIn("duplicate-scope-file", {f.mismatch_type for f in dup_failures})

        raw = SHARD_001_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SHARD_001_CURRENT_SHA256)
        text = raw.decode("utf-8")
        self.assertEqual(len(text.splitlines()), SHARD_001_CURRENT_LINE_COUNT)
        shard_001 = json.loads(text)
        self.assertEqual(len(shard_001["assertions"]), SHARD_001_CURRENT_ENTRY_COUNT)
        self.assertEqual(tuple((e["file"], tuple(e["classes"])) for e in shard_001["scope"]),
                         SHARD_001_CURRENT_SCOPE_ORDER)
        self.assertNotIn(TRANCHE_3K_CLASS, text)
        self.assertEqual(
            _subset_content_digest(shard_001["scope"][0],
                                   shard_001["assertions"][:TRANCHE_3H_HISTORICAL_ENTRY_COUNT]),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256,
        )

    def test_the_append_preserves_3j_fits_the_cap_and_adds_no_third_shard(self):
        """Reasons 3-5. (3) Shard 002's accepted state stays pinnable: the
        historical 34 keep their ids, categories, order and parsed content,
        and only the 34th raw line's trailing comma changed. (4) The line cap
        does not bind -- shard 001 had room too, which is why the choice
        needed a reason. (5) The index is unchanged and no `_003` exists."""
        historical = self.all_entries[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]
        self.assertEqual(len(historical), 34)
        self.assertTrue(all(e["file"] == TRANCHE_3J_SOURCE_FILE for e in historical))
        self.assertEqual(_subset_content_digest(self.shard["scope"][0], historical),
                         TRANCHE_3J_HISTORICAL_CONTENT_SHA256)
        self.assertEqual(dict(Counter(e["category"] for e in historical)),
                         {k: v for k, v in TRANCHE_3J_EXPECTED_CATEGORY_COUNTS.items() if v})
        self.assertEqual(
            self.all_entries[TRANCHE_3J_HISTORICAL_ENTRY_COUNT:TRANCHE_3K_HISTORICAL_ENTRY_COUNT],
            self.entries,
        )
        self.assertEqual((TRANCHE_3J_HISTORICAL_LINE_COUNT,
                          TRANCHE_3K_HISTORICAL_LINE_COUNT), (42, 70))
        self.assertEqual(dti.SHARD_LINE_CAP, 600)
        self.assertLess(TRANCHE_3K_HISTORICAL_LINE_COUNT, dti.SHARD_LINE_CAP)
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3K_EXPECTED_ASSERTION_COUNT,
                        dti.SHARD_LINE_CAP)
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        self.assertEqual(index["shards"], list(EXPECTED_SHARD_ORDER))
        self.assertEqual((EXPECTED_SHARD_COUNT, dti.discover_shard_filenames(ROOT)),
                         (3, sorted(EXPECTED_SHARD_ORDER)))
        self.assertFalse((ROOT / "document_test_classification_003.json").exists())

    # -- membership --------------------------------------------------------

    def test_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual((len(expected), len(TRANCHE_3K_EXPECTED_METHOD_ORDER)), (27, 7))
        self.assertEqual((TRANCHE_3K_EXPECTED_ASSERTION_COUNT,
                          TRANCHE_3K_EXPECTED_METHOD_COUNT), (27, 7))
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertEqual([r.id for r in self.live_records], expected)
        self.assertEqual(sum(c for _, c in TRANCHE_3K_EXPECTED_METHOD_ORDER),
                         TRANCHE_3K_EXPECTED_ASSERTION_COUNT)
        # Every method named exists on the live class, and no other does.
        _, known = dti.scan_classes((ROOT / TRANCHE_3K_SOURCE_FILE).read_text(encoding="utf-8"),
                                    TRANCHE_3K_SOURCE_FILE, [TRANCHE_3K_CLASS])
        self.assertEqual(sorted(m for m, _ in TRANCHE_3K_EXPECTED_METHOD_ORDER),
                         sorted(known[(TRANCHE_3K_SOURCE_FILE, TRANCHE_3K_CLASS)]))

    def test_entries_match_the_live_source_inventory_fields(self):
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                record = live_by_id[entry["id"]]
                self.assertEqual((entry["file"], entry["class"]),
                                 (TRANCHE_3K_SOURCE_FILE, TRANCHE_3K_CLASS))
                self.assertEqual((entry["method"], entry["ordinal"], entry["class"]),
                                 (record.method, record.ordinal, record.cls))
                self.assertEqual(entry["assertion_api"], record.assertion_api)
                self.assertEqual(entry["fingerprint"], record.fingerprint)
                # Every one of the 27 contracts the same single static file.
                self.assertEqual(entry["targets"], [TRANCHE_3K_TARGET_WORKFLOW])
        self.assertTrue((ROOT / TRANCHE_3K_TARGET_WORKFLOW).is_file())

    def test_the_selected_class_is_a_pure_static_workflow_contract_test(self):
        """It reads the workflow as text -- no production import, no mock."""
        source = (ROOT / TRANCHE_3K_SOURCE_FILE).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=TRANCHE_3K_SOURCE_FILE)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported, {"re", "unittest", "pathlib"})
        self.assertNotIn("mock", source.lower())
        # No custom assertion helper: the fingerprints are call-only.
        class_node = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                          and n.name == TRANCHE_3K_CLASS)
        self.assertEqual(dti._helper_defs_for_class(class_node), {})

    def test_api_breakdown_matches_the_measured_live_source(self):
        for measured in (Counter(e["assertion_api"] for e in self.entries),
                         Counter(r.assertion_api for r in self.live_records)):
            self.assertEqual(dict(measured), TRANCHE_3K_EXPECTED_API_COUNTS)
        self.assertEqual(sum(TRANCHE_3K_EXPECTED_API_COUNTS.values()),
                         TRANCHE_3K_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(TRANCHE_3K_EXPECTED_API_COUNTS,
                         {"assertTrue": 1, "assertIn": 7, "assertNotIn": 9,
                          "assertRegex": 7, "assertNotRegex": 3})
        # Negative guards are 12 of the 27: this class mostly asserts ABSENCE.
        self.assertEqual(sum(1 for e in self.entries
                             if e["assertion_api"].startswith("assertNot")), 12)

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        by_category = {}
        for entry in self.entries:
            by_category.setdefault(entry["category"], set()).add(entry["id"])
        self.assertEqual(by_category.get("A", set()), set(TRANCHE_3K_EXPECTED_A_IDS))
        self.assertEqual(by_category.get("C", set()), set(TRANCHE_3K_EXPECTED_C_IDS))
        self.assertEqual(by_category.get("D", set()), set(TRANCHE_3K_EXPECTED_D_IDS))
        # B is the exact remainder -- never its own hand-listed set.
        expected_b = (set(self.expected_ids_in_source_order()) - TRANCHE_3K_EXPECTED_A_IDS
                      - TRANCHE_3K_EXPECTED_C_IDS - TRANCHE_3K_EXPECTED_D_IDS)
        self.assertEqual(by_category.get("B", set()), expected_b)
        self.assertEqual(dict(Counter(e["category"] for e in self.entries)),
                         {k: v for k, v in TRANCHE_3K_EXPECTED_CATEGORY_COUNTS.items() if v})
        self.assertEqual(TRANCHE_3K_EXPECTED_CATEGORY_COUNTS, {"A": 0, "B": 22, "C": 5, "D": 0})
        self.assertEqual((TRANCHE_3K_EXPECTED_A_IDS, TRANCHE_3K_EXPECTED_D_IDS,
                          len(TRANCHE_3K_EXPECTED_C_IDS)), (frozenset(), frozenset(), 5))

    def test_the_five_c_entries_are_layout_locks_sha_comments_and_a_quote_lock(self):
        """Not a keyword tally: each of the five is the exact assertion whose
        raw text a meaning-preserving workflow edit breaks."""
        self.assertEqual(sorted(TRANCHE_3K_EXPECTED_C_IDS), sorted([
            _PRC + "test_checkout_and_python_are_pinned_safely::assert-01",
            _PRC + "test_checkout_and_python_are_pinned_safely::assert-04",
            _PRC + "test_checkout_and_python_are_pinned_safely::assert-05",
            _PRC + "test_has_read_only_repository_permissions::assert-01",
            _PRC + "test_uses_safe_pull_request_trigger::assert-01"]))
        # Two layout locks (the only multi-line regexes), two SHA-plus-inert-
        # comment lines, one quote lock (round 1, Blocker 1).
        source = (ROOT / TRANCHE_3K_SOURCE_FILE).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=TRANCHE_3K_SOURCE_FILE)
        layout_locks = {
            arg.value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "assertRegex" for arg in node.args
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            and "\\n" in arg.value}
        self.assertEqual(len(layout_locks), 2)
        # `'3.12'` is the same string, so the double-quoted rendering here is
        # presentation, not contract (B -> C).
        self.assertEqual(source.count(r'python-version: "3\.12"'), 1)
        sha_comment_lines = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                             and isinstance(n.value, str)
                             and n.value.startswith("uses: actions/")]
        self.assertEqual(len(sha_comment_lines), 2)
        workflow = (ROOT / TRANCHE_3K_TARGET_WORKFLOW).read_text(encoding="utf-8")
        for line in sha_comment_lines:
            with self.subTest(line=line):
                self.assertRegex(line, r"^uses: actions/[a-z-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")
                self.assertIn(line.split(" # ")[0].split("@")[1], workflow)
        # Nor D: a pinned SHA is CURRENT structural contract, not historical
        # evidence. This class carries no D at all.
        self.assertEqual([e["id"] for e in self.entries if e["category"] == "D"], [])
        self.assertEqual({e["category"] for e in self.entries
                          if "full commit SHA" in e["contract_summary"]}, {"C"})

    def test_entries_are_well_formed_and_use_the_fixed_key_order(self):
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertIn(entry["category"], dti.VALID_CATEGORIES)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
                self.assertNotIn("target", entry)
                self.assertEqual(len(entry["targets"]), 1)
                self.assertTrue((ROOT / entry["targets"][0]).exists())
                lowered = (entry["contract_summary"] + entry["rationale"]).lower()
                self.assertTrue(entry["contract_summary"].strip() and entry["rationale"].strip())
                for placeholder in _PLACEHOLDER_WORDS:
                    self.assertNotIn(placeholder, lowered)
                markers = _CATEGORY_MARKERS[entry["category"]]
                self.assertTrue(
                    any(m in entry["rationale"].lower() for m in markers),
                    f"{entry['id']}: rationale gives no category-{entry['category']} reasoning")

    # -- fingerprint review ------------------------------------------------

    def test_no_two_of_the_27_share_a_fingerprint(self):
        counts = Counter(e["fingerprint"] for e in self.entries)
        groups = tuple(
            tuple(sorted(e["id"] for e in self.entries if e["fingerprint"] == fingerprint))
            for fingerprint, n in sorted(counts.items()) if n > 1
        )
        self.assertEqual((groups, TRANCHE_3K_FINGERPRINT_DUPLICATE_GROUPS), ((), ()))
        self.assertEqual(len(counts), TRANCHE_3K_EXPECTED_ASSERTION_COUNT)  # not vacuous
        # No repetition, so no A candidate (never assigned without one).
        self.assertEqual(TRANCHE_3K_EXPECTED_A_IDS, frozenset())

    def test_no_cross_shard_fingerprint_collision_with_anything_classified(self):
        """Measured against ALL three accepted bodies: base 585, shard 001's
        259, and shard 002's own accepted tranche 3j 34."""
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))["assertions"]
        tranche_3j = self.all_entries[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]
        mine_by_fingerprint = {e["fingerprint"]: e for e in self.entries}
        self.assertEqual(len(mine_by_fingerprint), TRANCHE_3K_EXPECTED_ASSERTION_COUNT)
        for label, existing, expected_map in (
            ("base", base, TRANCHE_3K_VS_BASE_COLLISION_IDS),
            ("shard_001", shard_001, TRANCHE_3K_VS_SHARD_001_COLLISION_IDS),
            ("tranche_3j", tranche_3j, TRANCHE_3K_VS_TRANCHE_3J_COLLISION_IDS),
        ):
            with self.subTest(against=label):
                hits = {}
                for entry in existing:
                    if entry["fingerprint"] in mine_by_fingerprint:
                        hits.setdefault(mine_by_fingerprint[entry["fingerprint"]]["id"],
                                        set()).add(entry["id"])
                self.assertEqual({k: sorted(v) for k, v in hits.items()}, expected_map)
                self.assertEqual(hits, {})
                self.assertTrue(existing)  # not vacuous: the corpus is non-empty
        # Positively: all 27 are fresh, so no past classification is changed.
        seen = {e["fingerprint"] for e in base + shard_001 + tranche_3j}
        self.assertEqual(len([e for e in self.entries if e["fingerprint"] not in seen]), 27)

    # -- physical file (shard 002 CURRENT) ---------------------------------

    def test_the_accepted_tranche_3k_shard_002_state_is_pinned_as_history(self):
        """Shard 002 AS ACCEPTED at PR #93's merge commit
        764da66947a9b480ee2f074d553111a8e5bb278c: 61 entries, 70 lines, SHA
        `1aee40fd...`, scope[0:2], A0/B34/C19/D8. Tranche 3l appended 23 more,
        so each of these is asserted to be HISTORY and NOT the current state.
        The parsed-content digest was derived from the accepted file, not
        regenerated here, so it pins targets/action/contract_summary/rationale
        for all 61 -- the fields the id, category and order guards cannot see."""
        historical = self.all_entries[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]
        self.assertEqual(len(historical), 61)
        self.assertEqual(TRANCHE_3K_HISTORICAL_ENTRY_COUNT, 34 + 27)
        self.assertEqual(
            _subset_content_digest(self.shard["scope"][:2], historical),
            TRANCHE_3K_HISTORICAL_CONTENT_SHA256,
        )
        # Exact ids, in the accepted order: 3j's 34 then 3k's 27.
        self.assertEqual(
            [e["id"] for e in historical],
            [e["id"] for e in self.all_entries[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]]
            + self.expected_ids_in_source_order(),
        )
        self.assertEqual(dict(Counter(e["category"] for e in historical)),
                         {k: v for k, v in TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS.items() if v})
        self.assertEqual(TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS,
                         {"A": 0, "B": 34, "C": 19, "D": 8})
        self.assertEqual([e["file"] for e in historical].count(TRANCHE_3L_SOURCE_FILE), 0)
        # Demonstrated non-vacuous: the digest moves if any accepted field does.
        for field, value in (("category", "D"), ("action", "keep"),
                             ("rationale", "x"), ("contract_summary", "x"),
                             ("targets", ["README.md"])):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(historical))
                mutated[-1][field] = value
                self.assertNotEqual(
                    _subset_content_digest(self.shard["scope"][:2], mutated),
                    TRANCHE_3K_HISTORICAL_CONTENT_SHA256,
                )
        # History, not now: every accepted whole-file statistic has moved on.
        self.assertEqual((TRANCHE_3K_HISTORICAL_ENTRY_COUNT,
                          TRANCHE_3K_HISTORICAL_LINE_COUNT,
                          TRANCHE_3K_HISTORICAL_SHA256),
                         (61, 70, "1aee40fda499ac4308daa24fbd6fe622"
                                  "daab0dabd9390ecdb3014f36c7ae9da1"))
        self.assertNotEqual(TRANCHE_3K_HISTORICAL_ENTRY_COUNT, SHARD_002_CURRENT_ENTRY_COUNT)
        self.assertNotEqual(TRANCHE_3K_HISTORICAL_LINE_COUNT, SHARD_002_CURRENT_LINE_COUNT)
        self.assertNotEqual(TRANCHE_3K_HISTORICAL_SHA256, SHARD_002_CURRENT_SHA256)
        self.assertNotEqual(TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS,
                            SHARD_002_CURRENT_CATEGORY_COUNTS)
        self.assertNotEqual(
            hashlib.sha256(SHARD_002_PATH.read_bytes()).hexdigest(),
            TRANCHE_3K_HISTORICAL_SHA256,
        )
        self.assertEqual(len(self.shard_text.splitlines()), SHARD_002_CURRENT_LINE_COUNT)
        # The accepted 3j digest inside it is untouched by both appends.
        self.assertEqual(
            _subset_content_digest(self.shard["scope"][0],
                                   historical[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]),
            TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
        )

    def test_dropping_the_appended_scope_entry_is_detected(self):
        """The appended 27 must not sit in the file with their class removed
        from scope -- they would then belong to no scoped class at all."""
        mutated = json.loads(json.dumps(self.shard))
        del mutated["scope"][1]
        self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])

    def test_no_category_c_source_conversion_happened_in_this_tranche(self):
        """Tranche 3k classifies only: every C entry is parked with the
        refactor_later action and the live source is untouched."""
        for entry in self.entries:
            if entry["category"] == "C":
                with self.subTest(id=entry["id"]):
                    self.assertEqual(entry["action"], "refactor_later")
        self.assertEqual(sum(1 for e in self.entries if e["action"] == "refactor_later"),
                         TRANCHE_3K_EXPECTED_CATEGORY_COUNTS["C"])
        # The live source still holds all 27 assertions, unconverted.
        self.assertEqual(len(self.live_records), 27)


class Tranche3lClassificationShard002AppendTest(unittest.TestCase):
    """BL-038 tranche 3l: the 23 assertions of `test_workflow_action_pinning.py`
    -- its TWO source-order contiguous classes, i.e. the whole file -- APPENDED
    to shard 002 as scope[2] rather than opening a `_003`. Kept intact after
    tranche 3m appended a FOURTH scope entry to the same file: this class now
    pins tranche 3l's own 23 plus the shard-002 state ACCEPTED at PR #94's merge
    -- 84 entries, 94 lines, SHA `c0f81d14...` -- as HISTORY. The CURRENT
    whole-file contract lives in Tranche3mClassificationShard002AppendTest."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_002_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text, object_pairs_hook=OrderedDict)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == TRANCHE_3L_SOURCE_FILE]
        cls.by_id = {e["id"]: e for e in cls.entries}
        cls.source = (ROOT / TRANCHE_3L_SOURCE_FILE).read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=TRANCHE_3L_SOURCE_FILE)
        cls.live_records = dti.enumerate_assertions(cls.source, TRANCHE_3L_SOURCE_FILE,
                                                    list(TRANCHE_3L_CLASSES))
        cls.source_classes = [n.name for n in cls.tree.body if isinstance(n, ast.ClassDef)]

    def expected_ids_in_source_order(self):
        return [f"{prefix}{method}::assert-{ordinal:02d}"
                for prefix, method, count in TRANCHE_3L_EXPECTED_METHOD_ORDER
                for ordinal in range(1, count + 1)]

    def class_node(self, name):
        return next(n for n in self.tree.body
                    if isinstance(n, ast.ClassDef) and n.name == name)

    # -- scope + shard-allocation decision, measured -----------------------

    def test_the_append_is_legal_and_leaves_the_older_shards_untouched(self):
        """Scope[2] is the WHOLE selected file -- both classes, none split.
        Reasons 1-2: no `duplicate-scope-file` (still enforced, as the mutation
        shows), and shard 001 stays byte-identical so the 3h digest and the 3i
        accepted SHA survive un-re-derived."""
        scope = self.shard["scope"]
        # The accepted 3l scope is still the first THREE entries, in order; the
        # fourth is tranche 3m's and is contracted in that tranche's class.
        self.assertEqual(tuple((e["file"], tuple(e["classes"])) for e in scope[:3]),
                         TRANCHE_3L_HISTORICAL_SCOPE_ORDER)
        self.assertEqual(TRANCHE_3L_HISTORICAL_SCOPE_ORDER, SHARD_002_CURRENT_SCOPE_ORDER[:3])
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_SCOPE_ORDER, SHARD_002_CURRENT_SCOPE_ORDER)
        self.assertEqual((len(scope), scope[2]["file"], scope[2]["classes"]),
                         (4, TRANCHE_3L_SOURCE_FILE, list(TRANCHE_3L_CLASSES)))
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))
        self.assertEqual(self.source_classes, list(TRANCHE_3L_CLASSES))
        self.assertEqual(len(TRANCHE_3L_CLASSES), TRANCHE_3L_EXPECTED_CLASS_COUNT)
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, SHARD_001_PATH.read_text(encoding="utf-8"))
        files = [e["file"] for e in scope]
        self.assertEqual((len(files), len(set(files))), (4, 4))
        self.assertEqual(files.count(TRANCHE_3L_SOURCE_FILE), 1)
        self.assertEqual([f.format() for f in dti.validate_manifest(self.shard, root=ROOT)[0]], [])
        mutated = json.loads(json.dumps(self.shard))
        mutated["scope"].append({"file": TRANCHE_3L_SOURCE_FILE, "classes": [TRANCHE_3L_CLASSES[0]]})
        self.assertIn("duplicate-scope-file",
                      {f.mismatch_type for f in dti.validate_manifest(mutated, root=ROOT)[0]})
        raw = SHARD_001_PATH.read_bytes()
        text = raw.decode("utf-8")
        shard_001 = json.loads(text)
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()),
                          len(shard_001["assertions"])),
                         (SHARD_001_CURRENT_SHA256, SHARD_001_CURRENT_LINE_COUNT,
                          SHARD_001_CURRENT_ENTRY_COUNT))
        self.assertFalse([c for c in TRANCHE_3L_CLASSES if c in text])
        self.assertEqual(_subset_content_digest(shard_001["scope"][0],
                                   shard_001["assertions"][:TRANCHE_3H_HISTORICAL_ENTRY_COUNT]),
            TRANCHE_3H_HISTORICAL_CONTENT_SHA256)

    def test_the_append_preserves_the_accepted_61_and_adds_no_third_shard(self):
        """Reasons 3-5: the accepted 61 keep ids, categories, order and parsed
        content; the cap does not bind (shard 001 had room too, so the choice
        needed a measured reason); the index is unchanged."""
        historical = self.all_entries[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]
        self.assertEqual(len(historical), 61)
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, {e["file"] for e in historical})
        self.assertEqual(_subset_content_digest(self.shard["scope"][:2], historical),
                         TRANCHE_3K_HISTORICAL_CONTENT_SHA256)
        # The 23 are appended AFTER all 61 -- never interleaved -- and, after
        # tranche 3m, they end at the accepted-84 boundary rather than at EOF.
        self.assertEqual(
            self.all_entries[TRANCHE_3K_HISTORICAL_ENTRY_COUNT:TRANCHE_3L_HISTORICAL_ENTRY_COUNT],
            self.entries)
        self.assertEqual((TRANCHE_3K_HISTORICAL_LINE_COUNT, TRANCHE_3L_HISTORICAL_LINE_COUNT,
                          dti.SHARD_LINE_CAP), (70, 94, 600))
        self.assertLess(SHARD_002_CURRENT_LINE_COUNT, dti.SHARD_LINE_CAP)
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3L_EXPECTED_ASSERTION_COUNT,
                        dti.SHARD_LINE_CAP)
        self.assertEqual(json.loads(INDEX_PATH.read_text(encoding="utf-8"))["shards"],
                         list(EXPECTED_SHARD_ORDER))
        self.assertEqual((EXPECTED_SHARD_COUNT, dti.discover_shard_filenames(ROOT)),
                         (3, sorted(EXPECTED_SHARD_ORDER)))
        self.assertFalse((ROOT / "document_test_classification_003.json").exists())

    # -- membership --------------------------------------------------------

    def test_ids_and_api_breakdown_match_the_hardcoded_source_order(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual((len(expected), len(TRANCHE_3L_EXPECTED_METHOD_ORDER)), (23, 14))
        self.assertEqual((TRANCHE_3L_EXPECTED_ASSERTION_COUNT,
                          TRANCHE_3L_EXPECTED_METHOD_COUNT), (23, 14))
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual([r.id for r in self.live_records], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertEqual(sum(c for _, _, c in TRANCHE_3L_EXPECTED_METHOD_ORDER),
                         TRANCHE_3L_EXPECTED_ASSERTION_COUNT)
        # First class's ids all precede the second's: contiguous, not interleaved.
        prefixes = [e["id"].rsplit("::", 2)[0] + "::" for e in self.entries]
        self.assertEqual(prefixes, sorted(prefixes, key=[_WAP, _DPB].index))
        self.assertEqual((prefixes.count(_WAP), prefixes.count(_DPB)), (15, 8))
        # Every method named exists on the live classes, and no other does.
        _, known = dti.scan_classes(self.source, TRANCHE_3L_SOURCE_FILE, list(TRANCHE_3L_CLASSES))
        for prefix, class_name in ((_WAP, TRANCHE_3L_CLASSES[0]), (_DPB, TRANCHE_3L_CLASSES[1])):
            with self.subTest(class_name=class_name):
                self.assertEqual(
                    sorted(m for p, m, _ in TRANCHE_3L_EXPECTED_METHOD_ORDER if p == prefix),
                    sorted(known[(TRANCHE_3L_SOURCE_FILE, class_name)]))
        self.assertEqual(sum(len(v) for v in known.values()), TRANCHE_3L_EXPECTED_METHOD_COUNT)
        for measured in (Counter(e["assertion_api"] for e in self.entries),
                         Counter(r.assertion_api for r in self.live_records)):
            self.assertEqual(dict(measured), TRANCHE_3L_EXPECTED_API_COUNTS)
        self.assertEqual(TRANCHE_3L_EXPECTED_API_COUNTS,
                         {"assertTrue": 5, "assertEqual": 3, "assertRegex": 7,
                          "assertIn": 2, "assertNotIn": 4, "assertNotRegex": 2})
        self.assertEqual(sum(TRANCHE_3L_EXPECTED_API_COUNTS.values()), 23)
        # 6 of the 23 assert ABSENCE.
        self.assertEqual(sum(1 for e in self.entries
                             if e["assertion_api"].startswith("assertNot")), 6)
        by_category = {}
        for entry in self.entries:
            by_category.setdefault(entry["category"], set()).add(entry["id"])
        self.assertEqual(by_category.get("A", set()), set(TRANCHE_3L_EXPECTED_A_IDS))
        self.assertEqual(by_category.get("C", set()), set(TRANCHE_3L_EXPECTED_C_IDS))
        self.assertEqual(by_category.get("D", set()), set(TRANCHE_3L_EXPECTED_D_IDS))
        # B is the exact remainder -- never its own hand-listed set.
        self.assertEqual(by_category.get("B", set()), set(expected) - TRANCHE_3L_EXPECTED_A_IDS
                         - TRANCHE_3L_EXPECTED_C_IDS - TRANCHE_3L_EXPECTED_D_IDS)
        self.assertEqual(dict(Counter(e["category"] for e in self.entries)),
                         {k: v for k, v in TRANCHE_3L_EXPECTED_CATEGORY_COUNTS.items() if v})
        self.assertEqual(TRANCHE_3L_EXPECTED_CATEGORY_COUNTS, {"A": 6, "B": 11, "C": 6, "D": 0})
        self.assertEqual((len(TRANCHE_3L_EXPECTED_A_IDS), len(TRANCHE_3L_EXPECTED_C_IDS),
                          TRANCHE_3L_EXPECTED_D_IDS), (6, 6, frozenset()))

    def test_entries_match_the_live_source_and_its_three_static_targets(self):
        """Also pins the SOURCE BINDINGS the manifest rests on (PR #94 round 1,
        Blocker 2): a per-assertion fingerprint covers the assertion node only,
        so a module constant, the setUpClass workflow mapping or a subTest
        iterable can change underneath an unchanged fingerprint."""
        live_by_id = {r.id: r for r in self.live_records}
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                r = live_by_id[entry["id"]]
                self.assertEqual((entry["file"], entry["class"], entry["method"],
                                  entry["ordinal"], entry["assertion_api"], entry["fingerprint"]),
                                 (TRANCHE_3L_SOURCE_FILE, r.cls, r.method, r.ordinal,
                                  r.assertion_api, r.fingerprint))
                self.assertIn(entry["class"], TRANCHE_3L_CLASSES)
                self.assertTrue(all((ROOT / t).is_file() for t in entry["targets"]))
        # Which entry contracts which target is fixed: the Dependabot class
        # never reaches a workflow and vice versa.
        self.assertEqual(dict(Counter(tuple(e["targets"]) for e in self.entries)),
                         {tuple(TRANCHE_3L_BOTH_WORKFLOWS): 13,
                          (TRANCHE_3L_TARGET_FETCH_WORKFLOW,): 1,
                          (TRANCHE_3L_TARGET_PR_CI_WORKFLOW,): 1,
                          (TRANCHE_3L_TARGET_DEPENDABOT,): 8})
        self.assertEqual({e["targets"][0] for e in self.entries
                          if e["class"] == TRANCHE_3L_CLASSES[1]}, {TRANCHE_3L_TARGET_DEPENDABOT})
        self.assertNotIn(TRANCHE_3L_TARGET_DEPENDABOT,
                         {t for e in self.entries if e["class"] == TRANCHE_3L_CLASSES[0]
                          for t in e["targets"]})
        self.assertNotIn("mock", self.source.lower())
        pinning, dependabot = (self.class_node(c) for c in TRANCHE_3L_CLASSES)
        for node in (pinning, dependabot):  # no custom assertion helper
            with self.subTest(class_name=node.name):
                self.assertEqual(dti._helper_defs_for_class(node), {})
        # A. Module constants: assertions fingerprint the NAMES, so the approved
        # SHA and its inert version comment are invisible to them.
        assigns = {t.id: n.value for n in self.tree.body if isinstance(n, ast.Assign)
                   for t in n.targets if isinstance(t, ast.Name)}
        self.assertEqual({k: v.value for k, v in assigns.items() if isinstance(v, ast.Constant)},
                         {"CHECKOUT_SHA": "3d3c42e5aac5ba805825da76410c181273ba90b1",
                          "CHECKOUT_VERSION_COMMENT": "# v7.0.1",
                          "SETUP_PYTHON_SHA": "5fda3b95a4ea91299a34e894583c3862153e4b97",
                          "SETUP_PYTHON_VERSION_COMMENT": "# v7.0.0"})
        self.assertEqual({k: ast.unparse(v) for k, v in assigns.items() if k.endswith("_PATH")},
                         {"FETCH_WORKFLOW_PATH": "ROOT / '.github' / 'workflows' / 'fetch.yml'",
                          "PR_CI_WORKFLOW_PATH": "ROOT / '.github' / 'workflows' / 'pr-ci.yml'"})
        # B. Loop-bound assertions see only `self.workflows.items()`, so this
        # mapping IS the both-workflows half of their declared targets.
        mapping = next(n.value for n in ast.walk(pinning)
                       if isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict))
        self.assertEqual([(k.value, ast.unparse(v).split(".")[0])
                          for k, v in zip(mapping.keys, mapping.values)],
                         [("fetch.yml", "FETCH_WORKFLOW_PATH"),
                          ("pr-ci.yml", "PR_CI_WORKFLOW_PATH")])
        # C. The Dependabot path, and D. both subTest iterables exactly: shrinking
        # either leaves every fingerprint unchanged while silently dropping coverage.
        self.assertEqual([ast.unparse(n.value) for n in dependabot.body
                          if isinstance(n, ast.Assign)
                          and any(getattr(t, "id", None) == "DEPENDABOT_PATH" for t in n.targets)],
                         ["ROOT / '.github' / 'dependabot.yml'"])
        self.assertEqual({n.target.id: ast.literal_eval(n.iter) for n in ast.walk(dependabot)
                          if isinstance(n, ast.For) and isinstance(n.iter, ast.Tuple)},
                         TRANCHE_3L_PROHIBITED)

    # -- Category A: whole-method evidence, not a bare fingerprint tally ----

    def test_the_a_pair_is_two_methods_identical_but_for_the_action_name(self):
        """The measured basis for Category A: the two ENCLOSING METHODS have
        identical AST node-type skeletons and, once the single varying action
        identifier is normalised, byte-identical unparsed sources -- a real
        `_assert_action_pinned_to_full_sha(action)` helper candidate. A shared
        fingerprint is neither necessary nor sufficient."""
        first, second = TRANCHE_3L_A_METHOD_PAIR
        methods = {m.name: m for m in self.class_node(TRANCHE_3L_CLASSES[0]).body
                   if isinstance(m, ast.FunctionDef)}
        a_node, b_node = methods[first], methods[second]
        skeleton = lambda n: [type(x).__name__ for x in ast.walk(n)]
        self.assertEqual(skeleton(a_node), skeleton(b_node))
        self.assertEqual(len(skeleton(a_node)), 86)
        checkout, setup_python = TRANCHE_3L_A_VARYING_TOKENS
        normalise = lambda text, token, method: (
            text.replace(token, "actions/ACTION").replace(method, "test_ACTION"))
        self.assertEqual(normalise(ast.unparse(a_node), checkout, first),
                         normalise(ast.unparse(b_node), setup_python, second))
        # Non-vacuous: not identical before normalisation.
        self.assertNotEqual(ast.unparse(a_node), ast.unparse(b_node))
        counts = Counter(e["fingerprint"] for e in self.entries)
        groups = tuple(tuple(sorted(e["id"] for e in self.entries if e["fingerprint"] == fp))
                       for fp, n in sorted(counts.items()) if n > 1)
        self.assertEqual(groups, TRANCHE_3L_FINGERPRINT_DUPLICATE_GROUPS)
        self.assertEqual((len(groups), len(counts), sorted(counts.values())),
                         (2, 21, [1] * 19 + [2, 2]))
        self.assertEqual(({self.by_id[i]["assertion_api"] for i in groups[0]},
                          {self.by_id[i]["assertion_api"] for i in groups[1]}),
                         ({"assertRegex"}, {"assertEqual"}))
        # PR #94 round 1 (Blocker 1): the duplicate groups are a PROPER SUBSET of A.
        # The two leading assertTrue calls differ in fingerprint only because their
        # message literals embed the action name -- the same helper absorbs them.
        duplicated = {i for g in groups for i in g}
        self.assertLess(duplicated, set(TRANCHE_3L_EXPECTED_A_IDS))
        self.assertEqual(sorted(set(TRANCHE_3L_EXPECTED_A_IDS) - duplicated),
                         sorted(f"{_WAP}{m}::assert-01" for m in TRANCHE_3L_A_METHOD_PAIR))
        self.assertEqual(sorted(TRANCHE_3L_EXPECTED_A_IDS), sorted(e["id"] for e in self.entries
                                if e["method"] in TRANCHE_3L_A_METHOD_PAIR))
        leading = [e for e in self.entries
                   if e["method"] in TRANCHE_3L_A_METHOD_PAIR and e["ordinal"] == 1]
        self.assertEqual((len(leading), {e["category"] for e in leading},
                          len({e["fingerprint"] for e in leading}),
                          {e["assertion_api"] for e in leading}), (2, {"A"}, 2, {"assertTrue"}))
        # A parks the duplication as a maintainability note, not a fix.
        self.assertEqual({e["action"] for e in self.entries if e["category"] == "A"}, {"keep"})

    def test_the_six_c_entries_are_sha_comment_welds_quote_locks_and_prose(self):
        """Not a keyword tally: each is the exact assertion a meaning-preserving
        edit of the live target file breaks."""
        self.assertEqual((len(TRANCHE_3L_EXPECTED_SHA_COMMENT_C_IDS),
                          len(TRANCHE_3L_EXPECTED_QUOTE_LOCK_C_IDS),
                          len(TRANCHE_3L_EXPECTED_PROSE_ABSENCE_C_IDS),
                          len(TRANCHE_3L_EXPECTED_C_IDS)), (2, 3, 1, 6))
        # (a) Two raw lines weld a full commit SHA to an inert `# vX.Y.Z`
        # comment -- the shape accepted as C in tranche 3k.
        welded = [n.value for n in ast.walk(self.tree) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str) and n.value.startswith("# v")]
        self.assertEqual(sorted(welded), ["# v7.0.0", "# v7.0.1"])
        for workflow, comment in itertools.product(TRANCHE_3L_BOTH_WORKFLOWS, welded):
            with self.subTest(workflow=workflow, comment=comment):
                self.assertRegex((ROOT / workflow).read_text(encoding="utf-8"),
                                 r"@[0-9a-f]{40} " + re.escape(comment))
        # (b) Three Dependabot regexes pin DOUBLE QUOTES around values whose
        # unquoted plain scalar is the identical YAML string.
        dependabot = (ROOT / TRANCHE_3L_TARGET_DEPENDABOT).read_text(encoding="utf-8")
        quote_locked = [n.value for n in ast.walk(self.class_node(TRANCHE_3L_CLASSES[1]))
                        if isinstance(n, ast.Constant) and isinstance(n.value, str)
                        and ':\\s*"' in n.value]
        self.assertEqual(len(quote_locked), len(TRANCHE_3L_EXPECTED_QUOTE_LOCK_C_IDS))
        for pattern in quote_locked:
            with self.subTest(pattern=pattern):
                self.assertRegex(dependabot, pattern)
                self.assertNotRegex(dependabot.replace('"', "'"), pattern)
        # (c) One raw absence check over ORDINARY ENGLISH WORDS -- what separates
        # it from the negative raw checks kept at B here and in tranche 3k, all of
        # which use non-prose structural tokens. (Exact tuple pinned above.)
        self.assertFalse([m for m in TRANCHE_3L_PROHIBITED["marker"] if m in dependabot])
        # Not D: no date, PR number or CI run id anywhere, and the pinned SHAs
        # are the CURRENT contract rather than historical evidence.
        self.assertEqual([e["id"] for e in self.entries if e["category"] == "D"], [])
        self.assertNotRegex(self.source, r"20\d\d-\d\d-\d\d")

    def test_no_cross_shard_fingerprint_collision_with_anything_classified(self):
        """Measured against all three accepted bodies: base 585, shard 001's 259,
        and shard 002's own accepted 61 (tranche 3j's 34 + 3k's 27)."""
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))["assertions"]
        accepted_61 = self.all_entries[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]
        mine = {}
        for entry in self.entries:
            mine.setdefault(entry["fingerprint"], []).append(entry["id"])
        self.assertEqual(len(mine), 21)
        for label, existing, expected_map in (("base", base, TRANCHE_3L_VS_BASE_COLLISION_IDS),
            ("shard_001", shard_001, TRANCHE_3L_VS_SHARD_001_COLLISION_IDS),
            ("accepted_61", accepted_61, TRANCHE_3L_VS_TRANCHE_3K_HISTORICAL_COLLISION_IDS), ):
            with self.subTest(against=label):
                hits = {}
                for entry in existing:
                    for my_id in mine.get(entry["fingerprint"], ()):
                        hits.setdefault(my_id, set()).add(entry["id"])
                self.assertEqual({k: sorted(v) for k, v in hits.items()}, expected_map)
                self.assertEqual(hits, {})
                self.assertTrue(existing)  # not vacuous: the corpus is non-empty
        # Positively: every fingerprint is fresh, so no past classification moved.
        seen = {e["fingerprint"] for e in base + shard_001 + accepted_61}
        self.assertEqual(len([e for e in self.entries if e["fingerprint"] not in seen]), 23)

    # -- physical file (shard 002 CURRENT) ---------------------------------

    def test_the_accepted_tranche_3l_shard_002_state_is_pinned_as_history(self):
        """Shard 002 AS ACCEPTED at PR #94's merge commit
        48cc4fdf38303e9693cf870fb2f73a595d4908b2: 84 entries, 94 lines, SHA
        `c0f81d14...`, scope[0:3], A6/B45/C25/D8. Tranche 3m appended 17 more,
        so each is asserted to be HISTORY and NOT the current state. The
        parsed-content digest was derived from the accepted file, not
        regenerated here, so it pins targets/action/contract_summary/rationale
        for all 84 -- the fields the id, category and order guards cannot see."""
        historical = self.all_entries[:TRANCHE_3L_HISTORICAL_ENTRY_COUNT]
        self.assertEqual(len(historical), 84)
        self.assertEqual(TRANCHE_3L_HISTORICAL_ENTRY_COUNT, 34 + 27 + 23)
        self.assertEqual(_subset_content_digest(self.shard["scope"][:3], historical),
                         TRANCHE_3L_HISTORICAL_CONTENT_SHA256)
        # Exact ids, in the accepted order: the 61 then tranche 3l's own 23.
        self.assertEqual([e["id"] for e in historical],
                         [e["id"] for e in self.all_entries[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]]
                         + self.expected_ids_in_source_order())
        self.assertEqual(dict(Counter(e["category"] for e in historical)),
                         {k: v for k, v in TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS.items() if v})
        self.assertEqual(TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS, {"A": 6, "B": 45, "C": 25, "D": 8})
        self.assertEqual([e["file"] for e in historical].count(TRANCHE_3M_SOURCE_FILE), 0)
        # Demonstrated non-vacuous: the digest moves if any accepted field does.
        for field, value in (("category", "D"), ("action", "keep"), ("rationale", "x"),
                             ("contract_summary", "x"), ("targets", ["README.md"])):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(historical))
                mutated[-1][field] = value
                self.assertNotEqual(_subset_content_digest(self.shard["scope"][:3], mutated),
                                    TRANCHE_3L_HISTORICAL_CONTENT_SHA256)
        # History, not now: every accepted whole-file statistic has moved on.
        self.assertEqual((TRANCHE_3L_HISTORICAL_ENTRY_COUNT, TRANCHE_3L_HISTORICAL_LINE_COUNT,
                          TRANCHE_3L_HISTORICAL_SHA256),
                         (84, 94, "c0f81d1489109e1fe9a6a8dcef497496"
                                  "b7c3b39ad435a84ca06944a43409aaa2"))
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_ENTRY_COUNT, SHARD_002_CURRENT_ENTRY_COUNT)
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_LINE_COUNT, SHARD_002_CURRENT_LINE_COUNT)
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_SHA256, SHARD_002_CURRENT_SHA256)
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS,
                            SHARD_002_CURRENT_CATEGORY_COUNTS)
        self.assertNotEqual(hashlib.sha256(SHARD_002_PATH.read_bytes()).hexdigest(),
                            TRANCHE_3L_HISTORICAL_SHA256)
        self.assertEqual(len(self.shard_text.splitlines()), SHARD_002_CURRENT_LINE_COUNT)
        # PR #95 round 1 (Blocker 3): the accepted 84 are preserved by PARSED content,
        # NOT raw bytes -- appending gave the previously-last entry line and scope[2] a
        # trailing comma, so raw-byte identity cannot hold and is never claimed.
        lines = self.shard_text.splitlines()
        entries = [l for l in lines if l.startswith('    {"id"')]
        scopes = [l for l in lines if l.startswith('    {"file"')]
        self.assertEqual((len(entries), len(scopes)), (101, 4))
        self.assertTrue(entries[TRANCHE_3L_HISTORICAL_ENTRY_COUNT - 1].endswith("},") and scopes[2].endswith("},"))
        self.assertTrue(entries[-1].endswith("}") and not entries[-1].endswith("},"))
        self.assertNotEqual(TRANCHE_3L_HISTORICAL_SHA256, SHARD_002_CURRENT_SHA256)
        # The accepted 3k and 3j digests inside it are untouched by tranche 3m.
        self.assertEqual(_subset_content_digest(self.shard["scope"][:2],
                             historical[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]),
                         TRANCHE_3K_HISTORICAL_CONTENT_SHA256)
        self.assertEqual(_subset_content_digest(self.shard["scope"][0],
                             historical[:TRANCHE_3J_HISTORICAL_ENTRY_COUNT]),
                         TRANCHE_3J_HISTORICAL_CONTENT_SHA256)

    def test_entries_are_well_formed_and_no_source_conversion_happened(self):
        """Every C entry is parked `refactor_later`; source and targets untouched."""
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertIn(entry["category"], dti.VALID_CATEGORIES)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
                self.assertNotIn("target", entry)
                self.assertTrue(1 <= len(entry["targets"]) <= 2)
                self.assertTrue(entry["contract_summary"].strip() and entry["rationale"].strip())
                lowered = (entry["contract_summary"] + entry["rationale"]).lower()
                self.assertFalse([w for w in _PLACEHOLDER_WORDS if w in lowered])
                self.assertTrue(any(m in entry["rationale"].lower()
                        for m in _CATEGORY_MARKERS[entry["category"]]),
                    f"{entry['id']}: rationale gives no category-{entry['category']} reasoning")
        self.assertEqual(sum(1 for e in self.entries if e["action"] == "refactor_later"),
                         TRANCHE_3L_EXPECTED_CATEGORY_COUNTS["C"])
        self.assertEqual(len(self.live_records), 23)  # source still unconverted
        # The 23 must not sit in the file with their classes dropped from scope.
        for index in range(len(TRANCHE_3L_CLASSES)):
            with self.subTest(dropped=TRANCHE_3L_CLASSES[index]):
                mutated = json.loads(json.dumps(self.shard))
                del mutated["scope"][2]["classes"][index]
                self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])
        mutated = json.loads(json.dumps(self.shard))
        del mutated["scope"][2]
        self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])


class Tranche3mClassificationShard002AppendTest(unittest.TestCase):
    """BL-038 tranche 3m: the 17 assertions of
    `test_security_requirements.py::Bl034Round1ReviewCorrectionsTest`, APPENDED
    to shard 002 as scope[3] rather than opening a `_003` or reopening the
    byte-frozen shard 001 that owns a different class of the same file. Owns
    shard 002's CURRENT whole-file contract; the accepted 84 are pinned as
    history in the 3l class, the accepted 61 in the 3k class."""

    @classmethod
    def setUpClass(cls):
        cls.shard_text = SHARD_002_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.shard_text, object_pairs_hook=OrderedDict)
        cls.all_entries = cls.shard["assertions"]
        cls.entries = [e for e in cls.all_entries if e["file"] == TRANCHE_3M_SOURCE_FILE and e["class"] == TRANCHE_3M_CLASS]
        cls.by_id = {e["id"]: e for e in cls.entries}
        cls.source = (ROOT / TRANCHE_3M_SOURCE_FILE).read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=TRANCHE_3M_SOURCE_FILE)
        cls.live_records = dti.enumerate_assertions(cls.source, TRANCHE_3M_SOURCE_FILE, [TRANCHE_3M_CLASS])
        cls.source_classes = [n.name for n in cls.tree.body if isinstance(n, ast.ClassDef)]
        cls.class_node = next(n for n in cls.tree.body if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3M_CLASS)
        cls.methods = {m.name: m for m in cls.class_node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def expected_ids_in_source_order(self): return [f"{_B34}{method}::assert-{ordinal:02d}"
                for method, count in TRANCHE_3M_EXPECTED_METHOD_ORDER for ordinal in range(1, count + 1)]

    # -- selection: 17 was the only eligible candidate, measured -------------

    def test_the_selected_class_is_the_only_remaining_eligible_candidate(self):
        """Selection unit: one file's source-order contiguous run of UNCLASSIFIED
        classes, capped at 150, no split inside a class. Only two classes here
        are unclassified and they are not adjacent: 403 (over cap) and this 17."""
        owned = set()
        for name in EXPECTED_SHARD_ORDER:
            for scope_entry in json.loads((ROOT / name).read_text(encoding="utf-8"))["scope"]:
                for class_name in scope_entry["classes"]:
                    if scope_entry["file"] == TRANCHE_3M_SOURCE_FILE and name != SHARD_002_FILENAME: owned.add(class_name)
        unclassified = [(i, c) for i, c in enumerate(self.source_classes) if c not in owned and c != TRANCHE_3M_CLASS]
        self.assertEqual(unclassified, [(0, TRANCHE_3M_OVER_CAP_CLASS)])
        self.assertEqual(self.source_classes.index(TRANCHE_3M_CLASS), TRANCHE_3M_SOURCE_CLASS_INDEX)
        # The two candidates are separated by classes other shards already own,
        # so they cannot be joined into one contiguous run.
        self.assertTrue(set(self.source_classes[1:TRANCHE_3M_SOURCE_CLASS_INDEX]) <= owned)
        over_cap = dti.enumerate_assertions(self.source, TRANCHE_3M_SOURCE_FILE, [TRANCHE_3M_OVER_CAP_CLASS])
        self.assertEqual(len(over_cap), TRANCHE_3M_OVER_CAP_ASSERTION_COUNT)
        self.assertGreater(len(over_cap), TRANCHE_3M_SELECTION_CAP)
        self.assertLessEqual(TRANCHE_3M_EXPECTED_ASSERTION_COUNT, TRANCHE_3M_SELECTION_CAP)
        self.assertEqual(len(self.live_records), TRANCHE_3M_EXPECTED_ASSERTION_COUNT)

    def test_the_append_is_legal_and_leaves_the_older_manifests_untouched(self):
        """Scope[3] is the whole selected class. Shard 001 could not take it: a
        second same-file scope entry is `duplicate-scope-file`, and widening its
        entry rewrites a byte-frozen file. The cap did not decide it (268+17 fits)."""
        scope = self.shard["scope"]
        self.assertEqual(tuple((e["file"], tuple(e["classes"])) for e in scope), SHARD_002_CURRENT_SCOPE_ORDER)
        self.assertEqual((len(scope), scope[3]["file"], scope[3]["classes"]), (4, TRANCHE_3M_SOURCE_FILE, [TRANCHE_3M_CLASS]))
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        files = [e["file"] for e in scope]
        self.assertEqual((len(files), len(set(files))), (4, 4))
        self.assertEqual(files.count(TRANCHE_3M_SOURCE_FILE), 1)
        self.assertEqual([f.format() for f in dti.validate_manifest(self.shard, root=ROOT)[0]], [])
        # A second same-file scope entry is rejected in BOTH shards.
        for label, path in (("shard_002", SHARD_002_PATH), ("shard_001", SHARD_001_PATH)):
            with self.subTest(shard=label):
                mutated = json.loads(path.read_text(encoding="utf-8"))
                mutated["scope"].append({"file": TRANCHE_3M_SOURCE_FILE, "classes": [TRANCHE_3M_CLASS]})
                self.assertIn("duplicate-scope-file", {f.mismatch_type for f in dti.validate_manifest(mutated, root=ROOT)[0]})
        # Base manifest and shard 001 are byte-identical to their frozen state.
        for path, sha, line_count, entry_count in ((MANIFEST_PATH, BASE_MANIFEST_SHA256, BASE_MANIFEST_LINE_COUNT, 585),
                (SHARD_001_PATH, SHARD_001_CURRENT_SHA256, SHARD_001_CURRENT_LINE_COUNT, SHARD_001_CURRENT_ENTRY_COUNT)):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                text = raw.decode("utf-8")
                self.assertEqual((hashlib.sha256(raw).hexdigest(), len(text.splitlines()),
                                  len(json.loads(text)["assertions"])), (sha, line_count, entry_count))
                self.assertNotIn(TRANCHE_3M_CLASS, text)
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3M_EXPECTED_ASSERTION_COUNT, dti.SHARD_LINE_CAP)
        # No `_003`, and the index still lists exactly the three shards.
        self.assertFalse((ROOT / "document_test_classification_003.json").exists())
        self.assertEqual(json.loads(INDEX_PATH.read_text(encoding="utf-8"))["shards"], list(EXPECTED_SHARD_ORDER))
        self.assertEqual((EXPECTED_SHARD_COUNT, dti.discover_shard_filenames(ROOT)), (3, sorted(EXPECTED_SHARD_ORDER)))

    def test_no_class_is_owned_by_two_shards_and_the_84_keep_their_place(self):
        ownership = {}
        for name in EXPECTED_SHARD_ORDER:
            for scope_entry in json.loads((ROOT / name).read_text(encoding="utf-8"))["scope"]:
                for class_name in scope_entry["classes"]: ownership.setdefault((scope_entry["file"], class_name), []).append(name)
        self.assertEqual({k: v for k, v in ownership.items() if len(v) > 1}, {})
        self.assertEqual(ownership[(TRANCHE_3M_SOURCE_FILE, TRANCHE_3M_CLASS)], [SHARD_002_FILENAME])
        self.assertEqual(len(ownership), 28)
        # The 17 are appended AFTER all 84 -- never interleaved.
        self.assertEqual(self.all_entries[TRANCHE_3L_HISTORICAL_ENTRY_COUNT:], self.entries)
        self.assertEqual(self.all_entries[:TRANCHE_3L_HISTORICAL_ENTRY_COUNT], [e for e in self.all_entries if e not in self.entries])

    # -- membership ---------------------------------------------------------

    def test_ids_and_api_breakdown_match_the_hardcoded_source_order(self):
        expected = self.expected_ids_in_source_order()
        self.assertEqual((len(expected), len(TRANCHE_3M_EXPECTED_METHOD_ORDER)), (17, 7))
        self.assertEqual((TRANCHE_3M_EXPECTED_ASSERTION_COUNT, TRANCHE_3M_EXPECTED_METHOD_COUNT), (17, 7))
        self.assertEqual([e["id"] for e in self.entries], expected)
        self.assertEqual([r.id for r in self.live_records], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertEqual(sum(c for _, c in TRANCHE_3M_EXPECTED_METHOD_ORDER), TRANCHE_3M_EXPECTED_ASSERTION_COUNT)
        # Per-method arity is uneven (2/2/2/2/5/2/2): part of why no pair of
        # methods is whole-method parameterisable.
        self.assertEqual([c for _, c in TRANCHE_3M_EXPECTED_METHOD_ORDER], [2, 2, 2, 2, 5, 2, 2])
        # Every method named exists on the live class, and no other does.
        _, known = dti.scan_classes(self.source, TRANCHE_3M_SOURCE_FILE, [TRANCHE_3M_CLASS])
        self.assertEqual(sorted(m for m, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER), sorted(known[(TRANCHE_3M_SOURCE_FILE, TRANCHE_3M_CLASS)]))
        self.assertEqual(sum(len(v) for v in known.values()), TRANCHE_3M_EXPECTED_METHOD_COUNT)
        for measured in (Counter(e["assertion_api"] for e in self.entries), Counter(r.assertion_api for r in self.live_records)):
            self.assertEqual(dict(measured), TRANCHE_3M_EXPECTED_API_COUNTS)
        self.assertEqual(TRANCHE_3M_EXPECTED_API_COUNTS, {"assertIn": 10, "assertNotIn": 3, "assertRegex": 2, "assertNotRegex": 1, "assertFalse": 1})
        self.assertEqual(sum(TRANCHE_3M_EXPECTED_API_COUNTS.values()), 17)
        # 5 of the 17 assert ABSENCE: 4 via an `assertNot*` API and one more
        # via `assertFalse(<phrase> in <document>)`, which no `assertNot` name
        # would reveal.
        self.assertEqual(sum(1 for e in self.entries if e["assertion_api"].startswith("assertNot")), 4)
        self.assertEqual([e["id"] for e in self.entries if e["assertion_api"] == "assertFalse"],
                         [_B34 + "test_footer_and_beacon_destinations_are_distinguished_" "everywhere::assert-01"])
        # No custom assertion helper: no composite fingerprint in play.
        self.assertEqual(dti._helper_defs_for_class(self.class_node), {})

    def test_exact_category_membership_and_totals(self):
        by_category = {}
        for entry in self.entries: by_category.setdefault(entry["category"], set()).add(entry["id"])
        expected = set(self.expected_ids_in_source_order())
        self.assertEqual(by_category.get("A", set()), set(TRANCHE_3M_EXPECTED_A_IDS))
        self.assertEqual(by_category.get("C", set()), set(TRANCHE_3M_EXPECTED_C_IDS))
        self.assertEqual(by_category.get("D", set()), set(TRANCHE_3M_EXPECTED_D_IDS))
        # B is the exact remainder -- never its own hand-listed set.
        self.assertEqual(by_category.get("B", set()), expected - TRANCHE_3M_EXPECTED_A_IDS - TRANCHE_3M_EXPECTED_C_IDS - TRANCHE_3M_EXPECTED_D_IDS)
        self.assertEqual(dict(Counter(e["category"] for e in self.entries)), {k: v for k, v in TRANCHE_3M_EXPECTED_CATEGORY_COUNTS.items() if v})
        self.assertEqual(TRANCHE_3M_EXPECTED_CATEGORY_COUNTS, {"A": 0, "B": 8, "C": 7, "D": 2})
        self.assertEqual(sum(TRANCHE_3M_EXPECTED_CATEGORY_COUNTS.values()), 17)
        self.assertEqual((len(TRANCHE_3M_EXPECTED_A_IDS), len(TRANCHE_3M_EXPECTED_C_IDS), len(TRANCHE_3M_EXPECTED_D_IDS)), (0, 7, 2))
        # The four C shapes partition C exactly.
        self.assertEqual(TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS | TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS
                         | TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS | TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS, TRANCHE_3M_EXPECTED_C_IDS)
        self.assertEqual(sum(len(s) for s in (TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS, TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS,
                                              TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS,
                                              TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS)), len(TRANCHE_3M_EXPECTED_C_IDS))
        self.assertTrue(TRANCHE_3M_EXPECTED_C_IDS <= expected)
        self.assertTrue(TRANCHE_3M_EXPECTED_D_IDS <= expected)

    def test_combined_inventory_across_the_three_shards_is_945(self):
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["inventoried_assertions"], 945)
        self.assertEqual({k: summary["category_counts"][k] for k in ("A", "B", "C", "D")}, {"A": 28, "B": 337, "C": 435, "D": 145})
        self.assertEqual(sum(summary["category_counts"][k] for k in ("A", "B", "C", "D")), 945)
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))
        self.assertEqual(945, 928 + TRANCHE_3M_EXPECTED_ASSERTION_COUNT)

    # -- Category A: measured absence, not an unexamined zero ----------------

    def test_category_a_is_empty_because_no_pair_of_methods_parameterises(self):
        """Tranche 3l's A bar: normalising ONE varying token made two methods
        byte-identical. Three methods here share an AST node-type skeleton (node
        types cannot tell `assertIn` from `assertNotIn`), so the skeleton is not
        the measure -- every pair differs in at least TWO literals and carries
        different categories. The one real whole-method twin sits in a base-
        manifest class whose accepted rationale already declined consolidation."""
        self.assertEqual(TRANCHE_3M_EXPECTED_A_IDS, frozenset())
        self.assertEqual([e["id"] for e in self.entries if e["category"] == "A"], [])
        selected = [self.methods[m] for m, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER]
        self.assertEqual(len(selected), 7)
        skeleton = lambda n: tuple(type(x).__name__ for x in ast.walk(n))
        groups = {}
        for method, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER: groups.setdefault(skeleton(self.methods[method]), []).append(method)
        self.assertEqual(sorted(len(v) for v in groups.values()), [1, 1, 1, 1, 3])
        shared, = [v for v in groups.values() if len(v) > 1]
        self.assertEqual(shared, TRANCHE_3M_SHARED_SKELETON_METHODS)
        literals = lambda name: [c.value for c in ast.walk(self.methods[name]) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
        self.assertEqual({len(literals(m)) for m in shared}, {4})
        for first, second in itertools.combinations(shared, 2):
            with self.subTest(pair=(first, second)):
                differing = [a for a, b in zip(literals(first), literals(second)) if a != b]
                # Two or more independent literals vary: not a one-token swap.
                self.assertGreaterEqual(len(differing), 2)
                self.assertNotEqual(ast.unparse(self.methods[first]), ast.unparse(self.methods[second]))
                # And the two methods do not even classify the same way.
                cats = [tuple(e["category"] for e in self.entries if e["method"] == m) for m in (first, second)]
                self.assertNotEqual(*cats)
        # Their unparsed bodies are pairwise distinct across all seven.
        self.assertEqual(len({ast.unparse(n) for n in selected}), 7)
        # The declined cross-class twin really is shape-identical, in a class
        # this tranche does not own and must not modify.
        twin_class, twin_method = TRANCHE_3M_BL009_TWIN_METHOD
        twin_node = next(m for n in self.tree.body if isinstance(n, ast.ClassDef) and n.name == twin_class for m in n.body
                         if isinstance(m, ast.FunctionDef) and m.name == twin_method)
        mine = self.methods["test_bl009_is_an_in_progress_umbrella_not_completed"]
        strip = lambda n: [ast.unparse(s) for s in n.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        self.assertEqual(strip(mine), strip(twin_node))
        self.assertNotEqual(mine.name, twin_node.name)
        base_ids = {e["id"] for e in json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]}
        self.assertTrue({f"{TRANCHE_3M_SOURCE_FILE}::{twin_class}::{twin_method}::assert-01",
                         f"{TRANCHE_3M_SOURCE_FILE}::{twin_class}::{twin_method}::assert-02"} <= base_ids)
        self.assertNotIn(TRANCHE_3M_CLASS, {i.split("::")[1] for i in base_ids})

    # -- Category C / D: the exact edit each one breaks ----------------------

    def test_the_seven_c_entries_are_welds_giant_line_labels_and_prose(self):
        """Not a keyword tally: each C is measured against the live target."""
        backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        requirements = (ROOT / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        bl009 = _live_section(backlog, "## BL-009", "\n## BL-010")
        bl034 = _live_section(backlog, "## BL-034", "\n## 完了済み参照")
        # (a) The welded status enum: the literal IS the whole value of a
        # standalone `- **状態:**` bullet, but it welds the enum to a rewordable
        # parenthetical, which is why the two same-file precedents are C.
        self.assertIn("- **状態:** 進行中（BL-034で閲覧計測基盤を先行）", bl009)
        self.assertEqual(len(TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS), 1)
        # (b) The bold label opens a GIANT single-line list item -- measured --
        # so it is not the standalone one-line field convention kept at B.
        item = next(l for l in bl034.splitlines() if l.strip().startswith("12. **merge後:**"))
        # 197 characters on one line, the scale of the BL-007 label items kept
        # at C (177 and 811), not of the 17-character standalone B marker.
        self.assertEqual(len(item), 197)
        self.assertGreater(len(item), 100)
        self.assertIn("Cloudflare dashboardでの実データ受信確認", item)
        self.assertEqual(len(TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS), 2)
        # (c) Three raw English clauses about BL-032's current state, all inside
        # the GAP-016 row's free prose.
        gap016_row = next(l for l in requirements.splitlines() if l.startswith("| GAP-016 |"))
        self.assertIn("user-accepted and merged", gap016_row)
        for stale in ("Draft, pending user acceptance", "not yet user-accepted"):
            with self.subTest(stale=stale): self.assertNotIn(stale, gap016_row)
        self.assertEqual(len(TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS), 3)
        # (d) The normalized document-global absence check: normalization removes
        # line-wrap brittleness only, so the prose is still reword-brittle.
        stale_phrase = dtu.normalize_markdown_prose("first external network destination (`static.cloudflareinsights.com`)")
        self.assertNotIn(stale_phrase, dtu.normalize_markdown_prose(requirements))
        reworded = stale_phrase.replace("external", "outbound")
        self.assertNotEqual(reworded, stale_phrase)
        self.assertEqual(len(TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS), 1)
        self.assertIn(TRANCHE_3M_BEACON_ENDPOINT, requirements)

    def test_the_two_d_entries_are_historical_exact_evidence(self):
        """A 40-char accepted head and the exact Version value -- both already D in
        accepted entries. `**Status:** Approved` stays B for the same reason."""
        backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        bl034 = _live_section(backlog, "## BL-034", "\n## 完了済み参照")
        self.assertIn(TRANCHE_3M_ACCEPTED_HEAD_SHA, bl034)
        self.assertRegex(TRANCHE_3M_ACCEPTED_HEAD_SHA, r"\A[0-9a-f]{40}\Z")
        requirements = (ROOT / "SECURITY_REQUIREMENTS.md").read_text(encoding="utf-8")
        self.assertIn("**Version:** 1.7", requirements)
        self.assertIn("**Status:** Approved", requirements)
        self.assertEqual({self.by_id[i]["assertion_api"] for i in TRANCHE_3M_EXPECTED_D_IDS}, {"assertIn"})
        status_id = _B34 + "test_requirements_document_itself_is_version_17_draft::assert-02"
        self.assertEqual(self.by_id[status_id]["category"], "B")
        self.assertNotIn(status_id, TRANCHE_3M_EXPECTED_D_IDS)

    # -- fingerprints, duplicates and cross-shard collisions ----------------

    def test_no_two_of_the_seventeen_share_a_fingerprint(self):
        counts = Counter(e["fingerprint"] for e in self.entries)
        groups = tuple(tuple(sorted(e["id"] for e in self.entries if e["fingerprint"] == fp)) for fp, n in sorted(counts.items()) if n > 1)
        self.assertEqual(groups, TRANCHE_3M_FINGERPRINT_DUPLICATE_GROUPS)
        self.assertEqual((len(groups), len(counts)), (0, 17))
        self.assertEqual(sorted(counts.values()), [1] * 17)
        self.assertEqual({e["fingerprint"] for e in self.entries}, {r.fingerprint for r in self.live_records})

    def test_cross_shard_collisions_are_exactly_the_measured_six(self):
        """Six of the 17 repeat an assertion classified elsewhere. Each collision
        is pinned WITH the colliding entry's category, so a silent
        reclassification breaks this test instead of passing quietly."""
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["assertions"]
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))["assertions"]
        accepted_84 = self.all_entries[:TRANCHE_3L_HISTORICAL_ENTRY_COUNT]
        mine = {}
        for entry in self.entries: mine.setdefault(entry["fingerprint"], []).append(entry["id"])
        self.assertEqual(len(mine), 17)
        for label, existing, expected_map in (("base", base, TRANCHE_3M_VS_BASE_COLLISIONS), ("shard_001", shard_001, TRANCHE_3M_VS_SHARD_001_COLLISIONS),
                ("accepted_84", accepted_84, TRANCHE_3M_VS_TRANCHE_3L_HISTORICAL_COLLISIONS)):
            with self.subTest(against=label):
                hits = {}
                for entry in existing:
                    for my_id in mine.get(entry["fingerprint"], ()): hits.setdefault(my_id, {})[entry["id"]] = entry["category"]
                self.assertEqual(hits, expected_map)
                self.assertTrue(existing)  # not vacuous: the corpus is non-empty
        # Eleven of the 17 are genuinely new assertions.
        seen = {e["fingerprint"] for e in base + shard_001 + accepted_84}
        colliding = set(TRANCHE_3M_VS_BASE_COLLISIONS) | set(TRANCHE_3M_VS_SHARD_001_COLLISIONS)
        self.assertEqual(len(colliding), 6)
        self.assertEqual(len([e for e in self.entries if e["fingerprint"] not in seen]), 11)
        self.assertEqual({e["id"] for e in self.entries if e["fingerprint"] in seen}, colliding)

    def test_every_collision_agrees_with_precedent_except_one_documented_split(self):
        """Five of the six ids: every colliding entry already carries the
        category chosen here. The sixth collides with an ALREADY split set (B in
        `test_custom_domain.py`, C twice in this file); this tranche follows the
        two same-file C precedents and changes no accepted entry."""
        divergent = TRANCHE_3M_DIVERGENT_COLLISION_ID
        all_maps = {**TRANCHE_3M_VS_BASE_COLLISIONS}
        for my_id, mapping in TRANCHE_3M_VS_SHARD_001_COLLISIONS.items(): all_maps.setdefault(my_id, {}).update(mapping)
        self.assertEqual(len(all_maps), 6)
        self.assertIn(divergent, all_maps)
        for my_id, mapping in all_maps.items():
            with self.subTest(id=my_id):
                categories = set(mapping.values())
                if my_id == divergent:
                    # Pre-existing split, not introduced here.
                    self.assertEqual(categories, {"B", "C"})
                    self.assertEqual(self.by_id[my_id]["category"], "C")
                    same_file = {i: c for i, c in mapping.items() if i.startswith(TRANCHE_3M_SOURCE_FILE)}
                    self.assertEqual(set(same_file.values()), {"C"})
                    self.assertEqual(len(same_file), 2)
                else:
                    self.assertEqual(len(categories), 1)
                    self.assertEqual(categories, {self.by_id[my_id]["category"]})
        # The accepted bodies really are unchanged by this tranche.
        self.assertEqual(hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(), BASE_MANIFEST_SHA256)
        self.assertEqual(hashlib.sha256(SHARD_001_PATH.read_bytes()).hexdigest(), SHARD_001_CURRENT_SHA256)

    # -- source bindings a per-assertion fingerprint cannot see -------------

    def test_setupclass_document_bindings_are_pinned(self):
        """A. Fingerprints see `self.backlog`/`self.requirements` as bare NAMES;
        which file each reads is invisible to them. PR #95 rounds 1-2 (Blocker 1):
        scoped to the bindings the selected 17 READ. `cls.status` is outside this
        tranche's contract entirely -- neither its path nor its presence is fixed
        here, so retargeting or deleting it must leave this guard passing."""
        setup = next(m for m in self.class_node.body if isinstance(m, ast.FunctionDef) and m.name == "setUpClass")
        bindings = {}
        for node in ast.walk(setup):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
                literals = [c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.endswith(".md")]
                if literals: bindings[node.targets[0].attr] = literals[0]
        # Exactly the READ bindings are pinned to their documents...
        self.assertEqual({k: v for k, v in bindings.items() if k in TRANCHE_3M_USED_DOCUMENT_BINDINGS}, TRANCHE_3M_USED_DOCUMENT_BINDINGS)
        self.assertIn("read_text", ast.unparse(setup))
        # ...and the selected 17 read those two and nothing else.
        used = {n.attr for m, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER for n in ast.walk(self.methods[m])
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self" and n.attr in bindings}
        self.assertEqual(used, set(TRANCHE_3M_USED_DOCUMENT_BINDINGS))
        # `used` is intersected with the bindings actually present, so a setUpClass
        # binding this tranche does not read can be retargeted or removed freely.

    def test_the_section_helper_semantics_are_pinned(self):
        """B. `_section()` sits OUTSIDE every assertion node yet defines the scope
        each is evaluated in. Pinned as its own body, not a whole-file hash."""
        helper = next(m for m in self.class_node.body if isinstance(m, ast.FunctionDef) and m.name == TRANCHE_3M_SECTION_HELPER_NAME)
        self.assertEqual([d.id for d in helper.decorator_list], ["staticmethod"])
        self.assertEqual([a.arg for a in helper.args.args], ["text", "start", "end"])
        self.assertEqual([ast.unparse(d) for d in helper.args.defaults], ["None"])
        self.assertEqual("\n".join(ast.unparse(s) for s in helper.body), TRANCHE_3M_SECTION_HELPER_BODY)
        # Not a custom assertion helper, so it carries no composite fingerprint.
        self.assertNotIn(TRANCHE_3M_SECTION_HELPER_NAME, dti._helper_defs_for_class(self.class_node))

    def test_method_local_section_bindings_are_pinned(self):
        """C. Each `_section()` call's source attribute and both boundary markers:
        a fingerprint sees only the local NAME, never which slice it holds."""
        measured = []
        for method, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER:
            for node in ast.walk(self.methods[method]):
                if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)): continue
                call = node.value
                if not (isinstance(call.func, ast.Attribute) and call.func.attr == TRANCHE_3M_SECTION_HELPER_NAME): continue
                self.assertIsInstance(call.func.value, ast.Name)
                self.assertEqual(call.func.value.id, "self")
                source = call.args[0]
                self.assertIsInstance(source, ast.Attribute)
                self.assertEqual(source.value.id, "self")
                self.assertEqual(call.keywords, [])
                self.assertEqual(len(call.args), 3)
                measured.append((method, node.targets[0].id, source.attr, call.args[1].value, call.args[2].value))
        self.assertEqual(tuple(measured), TRANCHE_3M_SECTION_BINDINGS)
        self.assertEqual(len(measured), 5)
        # The two methods with no `_section()` call read the whole document.
        self.assertEqual({m for m, _ in TRANCHE_3M_EXPECTED_METHOD_ORDER} - {m for m, _, _, _, _ in measured},
                         {"test_requirements_document_itself_is_version_17_draft", "test_footer_and_beacon_destinations_are_distinguished_everywhere"})

    def test_the_gap_016_row_filter_is_pinned(self):
        """D. Retargeting `line.startswith("| GAP-016 |")` to another gap row
        leaves the three downstream assertion fingerprints byte-identical."""
        method = self.methods["test_bl032_runtime_implementation_is_accepted_and_merged_not_draft"]
        assign = next(n for n in ast.walk(method) if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == TRANCHE_3M_GAP_016_ROW_BINDING[0])
        generator = assign.value.args[0]
        self.assertIsInstance(generator, ast.GeneratorExp)
        self.assertEqual(assign.value.func.id, "next")
        comprehension, = generator.generators
        self.assertEqual(ast.unparse(comprehension.iter), f"{TRANCHE_3M_GAP_016_ROW_BINDING[1]}.splitlines()")
        condition, = comprehension.ifs
        self.assertEqual(condition.func.attr, "startswith")
        self.assertEqual([a.value for a in condition.args], [TRANCHE_3M_GAP_016_ROW_BINDING[2]])
        # The three assertions downstream really do read that binding.
        downstream = [n for n in ast.walk(method) if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Attribute) and n.func.attr in ("assertIn", "assertNotIn")
                      and any(getattr(a, "id", None) == TRANCHE_3M_GAP_016_ROW_BINDING[0] for a in n.args)]
        self.assertEqual(len(downstream), 3)

    def test_the_footer_stale_phrase_bindings_are_pinned(self):
        """E. `assertFalse(stale in normalized_requirements)` fingerprints two bare
        NAMES, so both assignments are guarded here instead."""
        method = self.methods["test_footer_and_beacon_destinations_are_distinguished_everywhere"]
        assigns = {n.targets[0].id: ast.unparse(n.value) for n in ast.walk(method) if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)}
        for name, expected in (TRANCHE_3M_STALE_BINDING, TRANCHE_3M_NORMALIZED_REQUIREMENTS_BINDING):
            with self.subTest(name=name): self.assertEqual(assigns[name], expected)
        self.assertEqual(sorted(assigns), sorted([TRANCHE_3M_STALE_BINDING[0], TRANCHE_3M_NORMALIZED_REQUIREMENTS_BINDING[0]]))
        # The comparison really is `stale in normalized_requirements`.
        compare = next(n for n in ast.walk(method) if isinstance(n, ast.Compare))
        self.assertEqual(ast.unparse(compare), f"{TRANCHE_3M_STALE_BINDING[0]} in " f"{TRANCHE_3M_NORMALIZED_REQUIREMENTS_BINDING[0]}")
        self.assertEqual([type(o).__name__ for o in compare.ops], ["In"])

    # -- physical file (shard 002 CURRENT) ---------------------------------

    def test_shard_002_file_meets_the_format_contract_within_the_line_cap(self):
        self.assertEqual([f.format() for f in dti.validate_shard_file_format(SHARD_002_PATH, self.shard, shard=SHARD_002_FILENAME)], [])
        lines = self.shard_text.splitlines()
        self.assertEqual(len(lines), SHARD_002_CURRENT_LINE_COUNT)
        self.assertLessEqual(len(lines), dti.SHARD_LINE_CAP)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)  # cap not raised
        self.assertEqual(hashlib.sha256(SHARD_002_PATH.read_bytes()).hexdigest(), SHARD_002_CURRENT_SHA256)
        self.assertTrue(self.shard_text.endswith("\n"))
        start = lines.index('  "assertions": [')
        entry_lines = lines[start + 1 : lines.index("  ]", start)]
        self.assertEqual((len(entry_lines), len(self.all_entries), SHARD_002_CURRENT_ENTRY_COUNT), (101, 101, 101))
        self.assertEqual(SHARD_002_CURRENT_ENTRY_COUNT, 34 + 27 + 23 + 17)
        for offset, line in enumerate(entry_lines):
            with self.subTest(line=start + 2 + offset): self.assertEqual(tuple(json.loads(line.strip().rstrip(","),
                                                  object_pairs_hook=OrderedDict).keys()), EXPECTED_ENTRY_KEY_ORDER)
        self.assertEqual(json.loads(self.shard_text), self.shard)
        self.assertEqual(len({e["id"] for e in self.all_entries}), SHARD_002_CURRENT_ENTRY_COUNT)
        self.assertEqual(dict(Counter(e["category"] for e in self.all_entries)), {k: v for k, v in SHARD_002_CURRENT_CATEGORY_COUNTS.items() if v})
        self.assertEqual(SHARD_002_CURRENT_CATEGORY_COUNTS, {"A": 6, "B": 53, "C": 32, "D": 10})
        failures, summary = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual((summary["manifest_assertions"], summary["inventoried_assertions"]),
                         (SHARD_002_CURRENT_ENTRY_COUNT, SHARD_002_CURRENT_ENTRY_COUNT))
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))

    def test_entries_are_well_formed_and_no_source_conversion_happened(self):
        """Every C entry is parked `refactor_later`; source and targets untouched."""
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry.keys()), EXPECTED_ENTRY_KEY_ORDER)
                self.assertEqual((entry["file"], entry["class"]), (TRANCHE_3M_SOURCE_FILE, TRANCHE_3M_CLASS))
                self.assertIn(entry["category"], dti.VALID_CATEGORIES)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
                self.assertNotIn("target", entry)
                self.assertEqual(len(entry["targets"]), 1)
                self.assertTrue(entry["contract_summary"].strip() and entry["rationale"].strip())
                lowered = (entry["contract_summary"] + entry["rationale"]).lower()
                self.assertFalse([w for w in _PLACEHOLDER_WORDS if w in lowered])
                self.assertTrue(any(m in entry["rationale"].lower() for m in _CATEGORY_MARKERS[entry["category"]]),
                    f"{entry['id']}: rationale gives no category-{entry['category']} reasoning")
        self.assertEqual(sum(1 for e in self.entries if e["action"] == "refactor_later"), TRANCHE_3M_EXPECTED_CATEGORY_COUNTS["C"])
        self.assertEqual({t for e in self.entries for t in e["targets"]}, {TRANCHE_3M_TARGET_BL009, TRANCHE_3M_TARGET_BL034,
                          TRANCHE_3M_TARGET_GAP_REGISTER, TRANCHE_3M_TARGET_GAP_016, TRANCHE_3M_TARGET_GAP_018, TRANCHE_3M_TARGET_REQUIREMENTS})
        # Backlog-scoped entries never claim a requirements target, or vice versa.
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                document = entry["targets"][0].split("#")[0]
                self.assertIn(document, ("BACKLOG.md", "SECURITY_REQUIREMENTS.md"))
                self.assertTrue((ROOT / document).is_file())
        self.assertEqual(len(self.live_records), 17)  # source still unconverted
        # The 17 must not sit in the file with their class dropped from scope.
        mutated = json.loads(json.dumps(self.shard))
        del mutated["scope"][3]
        self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])
        mutated = json.loads(json.dumps(self.shard))
        del mutated["scope"][3]["classes"][0]
        self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])

class ClassificationShardIndexTest(unittest.TestCase):
    """BL-038 tranche 3h/3i/3j/3k/3l: the shard-index contract. The index --
    not a glob -- fixes which manifests and in what order. Tranche 3l, like 3k,
    appended to shard 002 rather than adding a `_003`, so the index is
    unchanged at three shards. Tranche 3g's one-shard and tranche 3i's
    two-shard states are history only, both asserted NOT to be current."""

    def setUp(self):
        self.index_text = INDEX_PATH.read_text(encoding="utf-8")
        self.index = json.loads(self.index_text, object_pairs_hook=OrderedDict)

    def test_index_declares_base_then_shard_001_then_shard_002_in_that_order(self):
        self.assertEqual(tuple(self.index.keys()), dti.INDEX_TOP_LEVEL_KEYS)
        self.assertIs(type(self.index["schema_version"]), int)
        self.assertEqual(
            json.loads(self.index_text),
            {"schema_version": 1,
             "shards": [MANIFEST_PATH.name, SHARD_001_FILENAME, SHARD_002_FILENAME]},
        )
        self.assertTrue(self.index_text.endswith("\n"))
        # Order is part of the contract: it fixes combined assertion order.
        self.assertEqual(tuple(self.index["shards"]), EXPECTED_SHARD_ORDER)
        self.assertEqual(self.index["shards"][0], MANIFEST_PATH.name)
        self.assertEqual(self.index["shards"][1], SHARD_001_FILENAME)
        self.assertEqual(self.index["shards"][2], SHARD_002_FILENAME)
        self.assertEqual(len(self.index["shards"]), EXPECTED_SHARD_COUNT)
        self.assertEqual(EXPECTED_SHARD_COUNT, 3)
        self.assertEqual(len(set(self.index["shards"])), EXPECTED_SHARD_COUNT)
        # An unregistered shard file would silently vanish from the check.
        self.assertEqual(dti.discover_shard_filenames(ROOT), sorted(EXPECTED_SHARD_ORDER))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_001_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_002_FILENAME))
        self.assertFalse(dti.is_allowed_shard_filename(dti.INDEX_FILENAME))
        # Tranche 3g shipped a one-shard index and 3i a two-shard one; both
        # are history, not now.
        self.assertEqual(TRANCHE_3G_HISTORICAL_SHARD_COUNT, 1)
        self.assertEqual(TRANCHE_3I_HISTORICAL_SHARD_COUNT, 2)
        for historical in (TRANCHE_3G_HISTORICAL_SHARD_COUNT, TRANCHE_3I_HISTORICAL_SHARD_COUNT):
            with self.subTest(historical=historical):
                self.assertNotEqual(len(self.index["shards"]), historical)

    def test_combined_index_validation_reports_the_three_shard_totals(self):
        failures, combined = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(
            (combined["shard_count"], combined["shard_files"]),
            (EXPECTED_SHARD_COUNT, list(EXPECTED_SHARD_ORDER)),
        )
        self.assertEqual(combined["manifest_assertions"], INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(combined["inventoried_assertions"], INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(INDEX_COMBINED_ASSERTION_COUNT, 585 + 136 + 123 + 34 + 27 + 23 + 17)
        self.assertEqual(INDEX_COMBINED_ASSERTION_COUNT, 945)
        # 844 was the tranche 3i combined total, 878 the tranche 3j one, 905 the
        # tranche 3k one and 928 the tranche 3l one; all four are history.
        self.assertEqual(585 + 136 + 123, 844)
        self.assertEqual(585 + 136 + 123 + 34, 878)
        self.assertEqual(585 + 136 + 123 + 34 + 27, 905)
        self.assertEqual(585 + 136 + 123 + 34 + 27 + 23, 928)
        for historical_total in (844, 878, 905, 928):
            with self.subTest(historical_total=historical_total):
                self.assertNotEqual(INDEX_COMBINED_ASSERTION_COUNT, historical_total)
        self.assertEqual(combined["category_counts"], INDEX_COMBINED_CATEGORY_COUNTS)
        self.assertEqual(sum(combined["category_counts"].values()), INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual(
            (combined["unclassified"], combined["stale"], combined["fingerprint_mismatch"]), (0, 0, 0)
        )
        # Combined = base + 3h + 3i + 3j + 3k + 3l + 3m, never a re-derived tally.
        for category in ("A", "B", "C", "D"):
            with self.subTest(category=category):
                self.assertEqual(
                    combined["category_counts"][category],
                    BASE_EXPECTED_CATEGORY_COUNTS[category]
                    + SHARD_001_EXPECTED_CATEGORY_COUNTS[category]
                    + TRANCHE_3I_EXPECTED_CATEGORY_COUNTS[category]
                    + TRANCHE_3J_EXPECTED_CATEGORY_COUNTS[category]
                    + TRANCHE_3K_EXPECTED_CATEGORY_COUNTS[category]
                    + TRANCHE_3L_EXPECTED_CATEGORY_COUNTS[category]
                    + TRANCHE_3M_EXPECTED_CATEGORY_COUNTS[category],
                )
        self.assertEqual(combined["category_counts"], {"A": 28, "B": 337, "C": 435, "D": 145})
        # A22/B284/C403/D135 was the 3i tally, A22/B296/C417/D143 the 3j one,
        # A22/B318/C422/D143 the 3k one and A28/B329/C428/D143 the 3l one; all
        # four are history, not now. Tranche 3m moves B, C and D but not A.
        for historical_counts in (
            {"A": 22, "B": 284, "C": 403, "D": 135},
            {"A": 22, "B": 296, "C": 417, "D": 143},
            {"A": 22, "B": 318, "C": 422, "D": 143},
            {"A": 28, "B": 329, "C": 428, "D": 143},
        ):
            with self.subTest(historical_counts=tuple(sorted(historical_counts.items()))):
                self.assertNotEqual(combined["category_counts"], historical_counts)
        self.assertEqual(
            sorted(combined["scoped_files"]),
            sorted(
                {f for f, _ in EXPECTED_SCOPE_ORDER}
                | {SHARD_001_SOURCE_FILE, TRANCHE_3K_SOURCE_FILE, TRANCHE_3L_SOURCE_FILE}
            ),
        )
        # Tranche 3l's file arrived whole too: both its classes, 23 assertions,
        # in the one shard.
        self.assertEqual(
            combined["file_counts"][TRANCHE_3L_SOURCE_FILE],
            TRANCHE_3L_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(combined["file_counts"][TRANCHE_3L_SOURCE_FILE], 23)
        # The selected file arrived whole in one shard: 27 assertions, one
        # class, no split across shards.
        self.assertEqual(
            combined["file_counts"][TRANCHE_3K_SOURCE_FILE],
            TRANCHE_3K_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(combined["file_counts"][TRANCHE_3K_SOURCE_FILE], 27)
        # 136 was shard 001's whole share of this file until 3j added 34 more
        # of it in shard 002; the combined count is now the sum.
        self.assertEqual(
            combined["file_counts"][SHARD_001_SOURCE_FILE],
            SHARD_001_EXPECTED_ASSERTION_COUNT + TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
        )
        # One source file across THREE shards: the base manifest's share, shard
        # 001's tranche 3i class, and shard 002's tranche 3m class.
        self.assertEqual(
            combined["file_counts"][TRANCHE_3I_SOURCE_FILE],
            SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT + TRANCHE_3I_EXPECTED_ASSERTION_COUNT
            + TRANCHE_3M_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(combined["file_counts"][TRANCHE_3M_SOURCE_FILE], 345)
        # One source file, two shards: 001 owns 136 of it, 002 the other 34.
        self.assertEqual(
            combined["file_counts"][TRANCHE_3J_SOURCE_FILE],
            SHARD_001_EXPECTED_ASSERTION_COUNT + TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
        )
        self.assertEqual(combined["file_counts"][TRANCHE_3J_SOURCE_FILE], 170)

    def test_combined_assertion_order_is_base_then_shard_001_then_shard_002(self):
        load_failures, loaded = dti.load_shard_manifests(list(EXPECTED_SHARD_ORDER), root=ROOT)
        self.assertEqual(load_failures, [])
        base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        shard_001 = json.loads(SHARD_001_PATH.read_text(encoding="utf-8"))
        shard_002 = json.loads(SHARD_002_PATH.read_text(encoding="utf-8"))
        base_ids = [e["id"] for e in base["assertions"]]
        shard_ids = [e["id"] for e in shard_001["assertions"]]
        shard_002_ids = [e["id"] for e in shard_002["assertions"]]
        combined_ids = dti.combined_assertion_ids(loaded)
        self.assertEqual(combined_ids, base_ids + shard_ids + shard_002_ids)
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
        self.assertEqual(owners[(TRANCHE_3I_SOURCE_FILE, TRANCHE_3I_CLASS)], SHARD_001_FILENAME)
        # The tranche 3j class is owned by shard 002 and by nothing else: one
        # source file split BY CLASS across two shards is the growth path.
        self.assertEqual(owners[(TRANCHE_3J_SOURCE_FILE, TRANCHE_3J_CLASS)], SHARD_002_FILENAME)
        self.assertNotIn(TRANCHE_3J_CLASS, shard_001["scope"][0]["classes"])
        self.assertEqual(
            sorted(s for (f, c), s in owners.items() if f == TRANCHE_3J_SOURCE_FILE),
            sorted([SHARD_001_FILENAME] * 2 + [SHARD_002_FILENAME]),
        )
        # Tranche 3k: shard 002 now owns a SECOND file outright, and the
        # appended class is owned by shard 002 and by nothing else.
        self.assertEqual(owners[(TRANCHE_3K_SOURCE_FILE, TRANCHE_3K_CLASS)], SHARD_002_FILENAME)
        self.assertEqual(
            sorted(s for (f, c), s in owners.items() if f == TRANCHE_3K_SOURCE_FILE),
            [SHARD_002_FILENAME],
        )
        # Tranche 3l: shard 002 owns a THIRD file outright -- BOTH its classes,
        # owned by shard 002 and by nothing else.
        for class_name in TRANCHE_3L_CLASSES:
            with self.subTest(class_name=class_name):
                self.assertEqual(owners[(TRANCHE_3L_SOURCE_FILE, class_name)],
                                 SHARD_002_FILENAME)
        self.assertEqual(
            sorted(s for (f, c), s in owners.items() if f == TRANCHE_3L_SOURCE_FILE),
            [SHARD_002_FILENAME] * len(TRANCHE_3L_CLASSES),
        )
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, [e["file"] for e in base["scope"]])
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, [e["file"] for e in shard_001["scope"]])
        self.assertNotIn(TRANCHE_3K_SOURCE_FILE, [e["file"] for e in base["scope"]])
        self.assertNotIn(TRANCHE_3K_SOURCE_FILE, [e["file"] for e in shard_001["scope"]])
        self.assertEqual(
            sorted(f for f, _ in owners if f == TRANCHE_3K_SOURCE_FILE),
            [TRANCHE_3K_SOURCE_FILE],
        )
        self.assertEqual(
            owners[(TRANCHE_3I_SOURCE_FILE, "Bl034CloseoutTest")], MANIFEST_PATH.name
        )

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

    def test_base_manifest_is_byte_identical_and_unchanged_by_tranche_3l(self):
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
        # 3h added 136 to a NEW file, 3i appended 123 there, 3j added 34 to a
        # SECOND new file -- none of it here.
        self.assertNotIn(SHARD_001_SOURCE_FILE, text)
        self.assertNotIn(TRANCHE_3I_CLASS, text)
        self.assertNotIn(TRANCHE_3J_CLASS, text)
        # 3k appended a THIRD source file's only class to shard 002 and 3l a
        # FOURTH file's two classes -- also not here.
        self.assertNotIn(TRANCHE_3K_SOURCE_FILE, text)
        self.assertNotIn(TRANCHE_3K_CLASS, text)
        self.assertNotIn(TRANCHE_3L_SOURCE_FILE, text)
        for class_name in TRANCHE_3L_CLASSES:
            with self.subTest(class_name=class_name):
                self.assertNotIn(class_name, text)
        self.assertLess(BASE_EXPECTED_ASSERTION_COUNT, INDEX_COMBINED_ASSERTION_COUNT)


if __name__ == "__main__":
    unittest.main()
