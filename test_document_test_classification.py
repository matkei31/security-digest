#!/usr/bin/env python3
"""BL-038 tranche 3e: declared-scope/count structural guard for
document_test_classification.json, now spanning test_custom_domain.py
(tranche 3b, 97 entries, unchanged), test_ui_spec.py (tranche 3c, 185
entries, unchanged), test_status.py (tranche 3d, 98 entries, unchanged),
and test_security_requirements.py (tranche 3e, 143 new entries: the
Bl034Round2ReviewCorrectionsTest/Bl034ImplementationAcceptanceTest/
Bl034CloseoutTest/StatusSecurityRequirementsSourceOfTruthTest classes).

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
"""

import itertools
import json
import re
import unittest
from collections import OrderedDict
from pathlib import Path

import document_test_inventory as dti

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "document_test_classification.json"

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
SECURITY_REQUIREMENTS_EXPECTED_ASSERTION_COUNT = 143
COMBINED_EXPECTED_ASSERTION_COUNT = (
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

# Tranche 3e's exact per-ID category membership record for
# test_security_requirements.py, built the same way as tranche 3b/3c/3d:
# A/C/D pinned as hardcoded literal ID sets, B checked as the exact
# remainder of the 143 test_security_requirements.py IDs. Category A
# policy (a repeated structural pattern with clear shared-helper-
# consolidation value, not merely a recurring exact/fixed value) yields
# zero Category A entries, same as test_status.py.
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
})
SECURITY_REQUIREMENTS_EXPECTED_C_IDS = frozenset({
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

COMBINED_EXPECTED_CATEGORY_COUNTS = {
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
COMBINED_EXPECTED_A_IDS = (
    CUSTOM_DOMAIN_EXPECTED_A_IDS | UI_SPEC_EXPECTED_A_IDS | STATUS_EXPECTED_A_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_A_IDS
)
COMBINED_EXPECTED_C_IDS = (
    CUSTOM_DOMAIN_EXPECTED_C_IDS | UI_SPEC_EXPECTED_C_IDS | STATUS_EXPECTED_C_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_C_IDS
)
COMBINED_EXPECTED_D_IDS = (
    CUSTOM_DOMAIN_EXPECTED_D_IDS | UI_SPEC_EXPECTED_D_IDS | STATUS_EXPECTED_D_IDS
    | SECURITY_REQUIREMENTS_EXPECTED_D_IDS
)

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
        self.assertEqual(len(self.manifest["assertions"]), COMBINED_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len(self.live_records), COMBINED_EXPECTED_ASSERTION_COUNT)
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
        self.assertEqual(combined, COMBINED_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(combined.values()), COMBINED_EXPECTED_ASSERTION_COUNT)

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
        expected_b_ids = all_ids - COMBINED_EXPECTED_A_IDS - COMBINED_EXPECTED_C_IDS - COMBINED_EXPECTED_D_IDS
        for entry_id, expected_category in (
            [(i, "A") for i in COMBINED_EXPECTED_A_IDS]
            + [(i, "C") for i in COMBINED_EXPECTED_C_IDS]
            + [(i, "D") for i in COMBINED_EXPECTED_D_IDS]
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
                    frozenset(by_id) - COMBINED_EXPECTED_A_IDS - COMBINED_EXPECTED_C_IDS - COMBINED_EXPECTED_D_IDS
                )
                b_candidates = [i for i in expected_b_ids if i.startswith(file + "::")]
                b_entry = by_id[b_candidates[0]]
                c_entry = by_id[next(iter(c_ids))]
                b_entry["category"], c_entry["category"] = c_entry["category"], b_entry["category"]
                b_entry["action"], c_entry["action"] = c_entry["action"], b_entry["action"]

                combined = {"A": 0, "B": 0, "C": 0, "D": 0}
                for entry in mutated["assertions"]:
                    combined[entry["category"]] += 1
                self.assertEqual(combined, COMBINED_EXPECTED_CATEGORY_COUNTS, "swap must be count-preserving")

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
        self.assertEqual(len(entry_lines), COMBINED_EXPECTED_ASSERTION_COUNT)
        for line in entry_lines:
            stripped = line.strip().rstrip(",")
            parsed = json.loads(stripped)
            self.assertIsInstance(parsed, dict)

    def test_manifest_has_trailing_newline_and_deterministic_reread(self):
        self.assertTrue(self.manifest_text.endswith("\n"))
        reread = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(reread, self.manifest)


if __name__ == "__main__":
    unittest.main()
