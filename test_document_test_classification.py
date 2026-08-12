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
import shutil
import tempfile
import unittest
from collections import Counter, OrderedDict
from pathlib import Path

import document_test_history as dth
import document_test_inventory as dti
import document_test_utils as dtu

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "document_test_classification.json"
INDEX_PATH = ROOT / dti.INDEX_FILENAME
# The manifest as accepted and merged in PR #88 (merge commit 66ef88e5).
# Sharding exists so the 585 classified entries never have to move.
# BL-038 tranche 3t: the accepted-history ledger's own pin, spelled out here as
# well as in `document_test_history.LEDGER_DIGEST`, so editing the ledger and that
# module together still fails.
ACCEPTED_LEDGER_DIGEST = "5ed8d7b27837589ab3571a02a0fbdbd3c94db1f93cfa3fc687227320ef59160d"
BASE_MANIFEST_SHA256 = "640585ca03d7836cbdd66edcc8e2b21df7ea1de946b767ae20fa5c12e0c5f15a"
BASE_MANIFEST_LINE_COUNT = 596
# The accepted contracts_digest of the base manifest's acceptance (tranche 3f), as
# recorded in the immutable history ledger. BL-038 tranche 3v cross-checks the two
# independent copies instead of freezing the accepted id->category map on the tree.
BASE_ACCEPTED_CONTRACTS_DIGEST = \
    "4971c083471d9987488bab2687be533d42ff48ddac1fc7ae9ee6cd8ca1fab2c8"
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
# BL-038 tranche 3t: accepted literals, NOT derived from the CURRENT expected
# counts. A later Category C conversion inside an accepted window legitimately
# moves those, and history must not move with them. Second copy of every value:
# TRANCHE_3T_ACCEPTED_FACTS, and the offline ledger.
TRANCHE_3H_HISTORICAL_ENTRY_COUNT = 136
TRANCHE_3H_HISTORICAL_LINE_COUNT = 144
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
TRANCHE_3J_HISTORICAL_ENTRY_COUNT = 34  # accepted literal; see the 3h note
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
TRANCHE_3K_HISTORICAL_ENTRY_COUNT = 61  # accepted literal; see the 3h note
TRANCHE_3K_HISTORICAL_LINE_COUNT = 70
TRANCHE_3K_HISTORICAL_SHA256 = \
    "1aee40fda499ac4308daa24fbd6fe622daab0dabd9390ecdb3014f36c7ae9da1"
TRANCHE_3K_HISTORICAL_SCOPE_ORDER = ((TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
                                     (TRANCHE_3K_SOURCE_FILE, (TRANCHE_3K_CLASS,)))
TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS = {"A": 0, "B": 34, "C": 19, "D": 8}
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
TRANCHE_3L_HISTORICAL_ENTRY_COUNT = 84  # accepted literal; see the 3h note
TRANCHE_3L_HISTORICAL_LINE_COUNT = 94
TRANCHE_3L_HISTORICAL_SHA256 = \
    "c0f81d1489109e1fe9a6a8dcef497496b7c3b39ad435a84ca06944a43409aaa2"
TRANCHE_3L_HISTORICAL_SCOPE_ORDER = ((TRANCHE_3J_SOURCE_FILE, (TRANCHE_3J_CLASS,)),
    (TRANCHE_3K_SOURCE_FILE, (TRANCHE_3K_CLASS,)), (TRANCHE_3L_SOURCE_FILE, TRANCHE_3L_CLASSES), )
TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS = {"A": 6, "B": 45, "C": 25, "D": 8}
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
SHARD_003_FILENAME = "document_test_classification_003.json"
SHARD_003_PATH = ROOT / SHARD_003_FILENAME
SHARD_003_CURRENT_ENTRY_COUNT = 146
SHARD_003_CURRENT_LINE_COUNT = 154
SHARD_003_CURRENT_CATEGORY_COUNTS = {"A": 0, "B": 70, "C": 54, "D": 22}
SHARD_004_FILENAME = "document_test_classification_004.json"
SHARD_004_PATH = ROOT / SHARD_004_FILENAME
SHARD_004_CURRENT_ENTRY_COUNT = 140
SHARD_004_CURRENT_LINE_COUNT = 148
SHARD_004_CURRENT_CATEGORY_COUNTS = {"A": 2, "B": 80, "C": 50, "D": 8}
SHARD_005_FILENAME = "document_test_classification_005.json"
SHARD_005_PATH = ROOT / SHARD_005_FILENAME
SHARD_005_CURRENT_ENTRY_COUNT = 124
SHARD_005_CURRENT_LINE_COUNT = 130
SHARD_005_CURRENT_CATEGORY_COUNTS = {"A": 0, "B": 49, "C": 42, "D": 33}
SHARD_006_FILENAME = "document_test_classification_006.json"
SHARD_006_PATH = ROOT / SHARD_006_FILENAME
SHARD_006_CURRENT_ENTRY_COUNT = 133
SHARD_006_CURRENT_LINE_COUNT = 141
SHARD_006_CURRENT_CATEGORY_COUNTS = {"A": 0, "B": 60, "C": 37, "D": 36}
SHARD_007_FILENAME = "document_test_classification_007.json"
SHARD_007_PATH = ROOT / SHARD_007_FILENAME
SHARD_007_CURRENT_ENTRY_COUNT = 37
SHARD_007_CURRENT_LINE_COUNT = 45
SHARD_007_CURRENT_CATEGORY_COUNTS = {"A": 0, "B": 16, "C": 20, "D": 1}
EXPECTED_SHARD_ORDER = (MANIFEST_PATH.name, SHARD_001_FILENAME, SHARD_002_FILENAME,
                        SHARD_003_FILENAME, SHARD_004_FILENAME, SHARD_005_FILENAME,
                        SHARD_006_FILENAME, SHARD_007_FILENAME)
EXPECTED_SHARD_COUNT = len(EXPECTED_SHARD_ORDER)
TRANCHE_3G_HISTORICAL_SHARD_COUNT = 1
TRANCHE_3I_HISTORICAL_SHARD_COUNT = 2
# Tranches 3j-3n all shipped a three-shard index; tranche 3o is the first to
# need a fourth, because every one of the three already scopes
# test_security_requirements.py and a second same-file scope entry is
# `duplicate-scope-file`.
TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT = 3
# Historical SNAPSHOTS of the shard set. EXPECTED_SHARD_ORDER is the CURRENT
# index and grows every time a tranche adds a shard; a test that pins what was
# true AT some tranche must anchor on that tranche's snapshot instead, or a
# later legal append will break it. Current cross-shard legality (including
# whether two shards may share a class via disjoint method ranges) is the
# method-level ownership validator's job in document_test_inventory.py, not
# these historical records'.
TRANCHE_3M_HISTORICAL_SHARD_ORDER = (MANIFEST_PATH.name, SHARD_001_FILENAME, SHARD_002_FILENAME)
TRANCHE_3O_HISTORICAL_SHARD_ORDER = TRANCHE_3M_HISTORICAL_SHARD_ORDER + (SHARD_003_FILENAME,)
TRANCHE_3P_HISTORICAL_SHARD_ORDER = TRANCHE_3O_HISTORICAL_SHARD_ORDER + (SHARD_004_FILENAME,)
INDEX_COMBINED_ASSERTION_COUNT = (
    BASE_EXPECTED_ASSERTION_COUNT
    + SHARD_001_CURRENT_ENTRY_COUNT
    + SHARD_002_CURRENT_ENTRY_COUNT
    + SHARD_003_CURRENT_ENTRY_COUNT
    + SHARD_004_CURRENT_ENTRY_COUNT
    + SHARD_005_CURRENT_ENTRY_COUNT
    + SHARD_006_CURRENT_ENTRY_COUNT
    + SHARD_007_CURRENT_ENTRY_COUNT
)
INDEX_COMBINED_CATEGORY_COUNTS = {
    cat: BASE_EXPECTED_CATEGORY_COUNTS[cat]
    + SHARD_001_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_002_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_003_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_004_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_005_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_006_CURRENT_CATEGORY_COUNTS[cat]
    + SHARD_007_CURRENT_CATEGORY_COUNTS[cat]
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
        # BL-038 tranche 3v (C005): the per-file and combined ACCEPTED tallies are a
        # past fact, read from the immutable ledger instead of being required of the
        # current manifest, which a legal Category C conversion may legitimately move.
        dth.assert_accepted(self, ROOT, "3f", entry_count=BASE_EXPECTED_ASSERTION_COUNT,
                            category_counts=BASE_EXPECTED_CATEGORY_COUNTS)
        combined = {
            cat: counts_by_file[CUSTOM_DOMAIN_SOURCE_FILE][cat]
            + counts_by_file[UI_SPEC_SOURCE_FILE][cat]
            + counts_by_file[STATUS_SOURCE_FILE][cat]
            + counts_by_file[SECURITY_REQUIREMENTS_SOURCE_FILE][cat]
            for cat in ("A", "B", "C", "D")
        }
        # Current-side property only: the per-file breakdown adds up to the manifest.
        self.assertEqual(sum(combined.values()), len(self.manifest["assertions"]))

    # Round 2 fix (Blocker 3): category *counts* alone can't catch a B/C (or
    # any two same-count-preserving categories) entry swap. This checks the
    # exact per-ID category membership against hardcoded literal sets for
    # A/C/D (B is checked as the exact remainder), which the classification
    # manifest -- a human-reviewed record, not a derivable computation --
    # requires to be pinned, not merely counted. Tranche 3c preserves
    # tranche 3b's record unweakened by unioning it into the combined sets
    # (the two files' IDs are disjoint by construction).
    def _assert_exact_category_membership(self, manifest, expected_by_id=None):
        """BL-038 tranche 3v (C006-C009): `expected_by_id` is the membership this
        manifest is held to. The mutation guards pass the PRE-mutation membership, so
        a count-preserving swap is still caught without freezing the accepted
        id->category map onto the current tree."""
        by_id = {a["id"]: a["category"] for a in manifest["assertions"]}
        if expected_by_id is None:
            expected_by_id = by_id
        for entry_id, expected_category in sorted(expected_by_id.items()):
            self.assertEqual(
                by_id.get(entry_id), expected_category,
                f"{entry_id} expected category {expected_category!r}, "
                f"manifest has {by_id.get(entry_id)!r}",
            )

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        # BL-038 tranche 3v (C009): the accepted id->category membership is a past
        # fact held by the ledger's contracts_digest and category_counts; requiring
        # the CURRENT manifest to reproduce it is what blocked Category C conversion.
        # Current per-entry category/action correctness stays with the validator.
        dth.assert_accepted(self, ROOT, "3f", contracts_digest=BASE_ACCEPTED_CONTRACTS_DIGEST,
                            category_counts=BASE_EXPECTED_CATEGORY_COUNTS)
        failures, _summary = dti.validate_manifest(self.manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])

    def test_count_preserving_category_swap_mutation_is_detected(self):
        # Swap one B entry and one C entry's categories (and matching
        # actions) -- the aggregate A/B/C/D counts stay identical, so only
        # the exact-membership guard (not test_category_counts_match_
        # corrected_final_tally) can catch this. Exercised for both files.
        # BL-038 tranche 3v (C007): the swap target is drawn from the manifest's OWN
        # current C entries. Indexing an accepted C-id set into the current manifest
        # would KeyError once a conversion renumbers or retires that id.
        for file in (CUSTOM_DOMAIN_SOURCE_FILE, UI_SPEC_SOURCE_FILE, STATUS_SOURCE_FILE,
                     SECURITY_REQUIREMENTS_SOURCE_FILE):
            with self.subTest(file=file):
                mutated = json.loads(self.manifest_text)
                by_id = {a["id"]: a for a in mutated["assertions"]}
                before = {a["id"]: a["category"] for a in mutated["assertions"]}
                b_candidates = sorted(i for i, c in before.items()
                                      if c == "B" and i.startswith(file + "::"))
                c_candidates = sorted(i for i, c in before.items()
                                      if c == "C" and i.startswith(file + "::"))
                self.assertTrue(b_candidates and c_candidates)  # not vacuous
                b_entry = by_id[b_candidates[0]]
                c_entry = by_id[c_candidates[0]]
                b_entry["category"], c_entry["category"] = c_entry["category"], b_entry["category"]
                b_entry["action"], c_entry["action"] = c_entry["action"], b_entry["action"]

                combined = {"A": 0, "B": 0, "C": 0, "D": 0}
                for entry in mutated["assertions"]:
                    combined[entry["category"]] += 1
                self.assertEqual(combined, Counter(before.values()), "swap must be count-preserving")

                with self.assertRaises(AssertionError):
                    self._assert_exact_category_membership(mutated, before)

    # Explicit preservation check (distinct from the generic swap test
    # above): mutating the category of one of tranche 3b's ORIGINAL 97
    # entries must still be caught by the same combined guard, proving
    # tranche 3c's expansion did not silently dilute tranche 3b's record.
    def test_custom_domain_membership_preservation_mutation_is_detected(self):
        mutated = json.loads(self.manifest_text)
        by_id = {a["id"]: a for a in mutated["assertions"]}
        before = {a["id"]: a["category"] for a in mutated["assertions"]}
        target_id = sorted(i for i, c in before.items()
                           if c == "A" and i.startswith(CUSTOM_DOMAIN_SOURCE_FILE + "::"))[0]
        entry = by_id[target_id]
        entry["category"] = "B"
        entry["action"] = dti.CATEGORY_TO_ACTION["B"]
        with self.assertRaises(AssertionError):
            self._assert_exact_category_membership(mutated, before)

    # Category A is newly non-empty for test_security_requirements.py, so
    # the swap above (B<->C only) would not notice an A entry downgraded to
    # B while a B is promoted to A. Exercise that pair explicitly.
    def test_count_preserving_a_to_b_swap_in_security_requirements_is_detected(self):
        mutated = json.loads(self.manifest_text)
        by_id = {a["id"]: a for a in mutated["assertions"]}
        before = {a["id"]: a["category"] for a in mutated["assertions"]}
        prefix = SECURITY_REQUIREMENTS_SOURCE_FILE + "::Bl031AcceptanceAndBl032RegistrationTest::"
        b_entry = by_id[sorted(i for i, c in before.items()
                               if c == "B" and i.startswith(prefix))[0]]
        a_entry = by_id[sorted(i for i, c in before.items() if c == "A"
                               and i.startswith(SECURITY_REQUIREMENTS_SOURCE_FILE + "::"))[0]]
        b_entry["category"], a_entry["category"] = a_entry["category"], b_entry["category"]
        b_entry["action"], a_entry["action"] = a_entry["action"], b_entry["action"]

        combined = {"A": 0, "B": 0, "C": 0, "D": 0}
        for entry in mutated["assertions"]:
            combined[entry["category"]] += 1
        self.assertEqual(combined, Counter(before.values()), "swap must be count-preserving")
        with self.assertRaises(AssertionError):
            self._assert_exact_category_membership(mutated, before)

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
        # BL-038 tranche 3v (C014): the accepted id list, its source order and its count
        # are past facts in the immutable ledger. What stays current is that the shard's
        # ids are exactly what the live source enumerates, in that order, without
        # duplicates -- and that every accepted contract is still accounted for.
        ids = [e["id"] for e in self.entries]
        self.assertEqual(ids, [r.id for r in self.live_records])
        self.assertEqual(len(set(ids)), len(ids))
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3h")

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
        # BL-038 tranche 3v (C011): tranche 3h's accepted id->category membership and
        # category counts are past facts, asserted here from the immutable ledger. The
        # current tree is held to accepted-contract continuity and to category/action
        # consistency, never to a frozen category, so a legal Category C conversion of
        # these assertions is no longer blocked.
        self.assertEqual(SHARD_001_EXPECTED_A_IDS, frozenset())
        self.assertEqual(SHARD_001_EXPECTED_CATEGORY_COUNTS["A"], 0)
        dth.assert_accepted(self, ROOT, "3h", entry_count=SHARD_001_EXPECTED_ASSERTION_COUNT,
                            category_counts=SHARD_001_EXPECTED_CATEGORY_COUNTS)
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])

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
        # BL-038 tranche 3v (C016): the accepted content digest is asserted from the
        # immutable ledger, NOT recomputed from the current shard -- recomputing it is
        # exactly the freeze that blocked structural conversion. What stays here is the
        # digest function's sensitivity, measured against the current file's own value.
        dth.assert_accepted(self, ROOT, "3h", content_digest=TRANCHE_3H_HISTORICAL_CONTENT_SHA256)
        baseline = _subset_content_digest(self.shard["scope"][0], self.entries)
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
                    _subset_content_digest(self.shard["scope"][0], mutated), baseline)
        # A scope edit and a reordering are caught as well.
        self.assertNotEqual(
            _subset_content_digest({"file": "x.py", "classes": []}, self.entries), baseline)
        self.assertNotEqual(
            _subset_content_digest(self.shard["scope"][0], self.entries[::-1]), baseline)

    def test_tranche_3h_file_snapshot_is_history_not_the_current_file(self):
        """136 / 144 / SHA 2d03c748 was shard 001 AT TRANCHE 3H MERGE, so
        those numbers are history, asserted NOT to describe the file today."""
        # BL-038 tranche 3v (C015): the accepted 136 / 144 / SHA 2d03c748 snapshot comes
        # from the immutable ledger. The positional prefix reconstruction
        # (all_entries[:136] == the accepted id order) and the accepted category
        # breakdown of the current window are gone -- both froze the current file.
        dth.assert_accepted(self, ROOT, "3h", sha256=TRANCHE_3H_HISTORICAL_SHA256,
                            line_count=TRANCHE_3H_HISTORICAL_LINE_COUNT,
                            entry_count=TRANCHE_3H_HISTORICAL_ENTRY_COUNT)
        self.assertEqual(TRANCHE_3H_HISTORICAL_ENTRY_COUNT, 136)
        self.assertEqual(TRANCHE_3H_HISTORICAL_LINE_COUNT, 144)
        current_lines = len(self.shard_text.splitlines())
        current_sha = hashlib.sha256(SHARD_001_PATH.read_bytes()).hexdigest()
        self.assertNotEqual(current_lines, TRANCHE_3H_HISTORICAL_LINE_COUNT)
        self.assertNotEqual(current_sha, TRANCHE_3H_HISTORICAL_SHA256)

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
        """BL-038 tranche 3v (C012, H7-A+B). The accepted collision groups, their
        category calls and the measured loop-literal sizes were an accepted-time
        measurement -- a legal Category C conversion changes fingerprints, so requiring
        them of the current corpus blocked conversion and they are gone. What remains is
        the single algorithm fact that made the second group spurious, proven through the
        REAL inventory/fingerprint generator on synthetic source: fingerprint generation
        is blind to the enclosing loop context. No accepted collision set, no category,
        no live corpus id is involved."""
        source = (
            "import unittest\n\n\n"
            "class SyntheticFingerprintTest(unittest.TestCase):\n"
            "    def test_first_call_site(self):\n"
            "        compact = \"x\"\n"
            "        for contract in (\"alpha\", \"beta\", \"gamma\"):\n"
            "            with self.subTest(contract=contract):\n"
            "                self.assertIn(contract, compact)\n\n"
            "    def test_second_call_site(self):\n"
            "        compact = \"x\"\n"
            "        for contract in (\"delta\",):\n"
            "            with self.subTest(contract=contract):\n"
            "                self.assertIn(contract, compact)\n"
        )
        records = dti.enumerate_assertions(
            source, "synthetic_fingerprint.py", ["SyntheticFingerprintTest"])
        self.assertEqual(len(records), 2)
        self.assertEqual({r.assertion_api for r in records}, {"assertIn"})
        # The real generator gives the two call sites ONE fingerprint...
        self.assertEqual(len({r.fingerprint for r in records}), 1)
        self.assertNotEqual(records[0].id, records[1].id)
        # ...while the enclosing `for` tuples in the very same fixture differ, which is
        # why a fingerprint collision never implied a shared contract or category.
        tree = ast.parse(source)
        loops = {}
        for method in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(method):
                if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
                    loops[method.name] = tuple(e.value for e in node.iter.elts)
        self.assertEqual(sorted(loops), ["test_first_call_site", "test_second_call_site"])
        self.assertNotEqual(*loops.values())
        self.assertEqual(sorted(len(v) for v in loops.values()), [1, 3])

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
        # BL-038 tranche 3v (C013): the shrinkage is measured against the shard's OWN
        # current scope rather than the accepted class tuple, so the guard still catches
        # a silent drop without pinning which classes the shard must own today.
        original_classes = tuple(self.shard["scope"][0]["classes"])
        original_count = len([e for e in self.shard["assertions"]
                              if e["file"] == SHARD_001_SOURCE_FILE])
        mutated = json.loads(json.dumps(self.shard))
        dropped = original_classes[1]
        mutated["scope"][0]["classes"] = [original_classes[0]]
        mutated["assertions"] = [e for e in mutated["assertions"] if e["class"] != dropped]
        failures, _summary = dti.validate_manifest(mutated, root=ROOT)
        self.assertEqual([f.format() for f in failures], [], "dti alone cannot see the shrinkage")
        self.assertNotEqual(tuple(mutated["scope"][0]["classes"]), original_classes)
        self.assertLess(
            len([e for e in mutated["assertions"] if e["file"] == SHARD_001_SOURCE_FILE]),
            original_count,
        )
        with self.assertRaises(AssertionError):
            self.assertEqual(tuple(mutated["scope"][0]["classes"]), original_classes)


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
        # BL-038 tranche 3v (C022): the accepted id list, its count and the positional
        # window all_entries[136:] are past facts / positional reconstruction. The block
        # is now located by the shard's own structure, not by a historical count, and
        # accepted-contract continuity replaces the positional pin.
        ids = [e["id"] for e in self.entries]
        self.assertEqual(ids, [r.id for r in self.live_records])
        self.assertEqual(len(set(ids)), len(ids))
        # Appended as a trailing block, never interleaved with what came before.
        self.assertEqual([e["id"] for e in self.all_entries[-len(ids):]], ids)
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3i")

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
        # BL-038 tranche 3v (C020): tranche 3i's accepted membership and category counts
        # are past facts. The ledger's 3i record is the shard-level accepted snapshot
        # (259 entries cumulative), so it is asserted from there; the current tree keeps
        # only category/action consistency and accepted-contract continuity.
        self.assertEqual(TRANCHE_3I_EXPECTED_A_IDS, frozenset())
        self.assertEqual(TRANCHE_3I_EXPECTED_CATEGORY_COUNTS["A"], 0)
        dth.assert_accepted(self, ROOT, "3i", entry_count=SHARD_001_CURRENT_ENTRY_COUNT,
                            category_counts=SHARD_001_CURRENT_CATEGORY_COUNTS)
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])

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

    def test_current_shard_file_meets_the_format_contract_within_the_line_cap(self):
        failures = dti.validate_shard_file_format(SHARD_001_PATH, self.shard, shard=SHARD_001_FILENAME)
        self.assertEqual([f.format() for f in failures], [])
        # BL-038 tranche 3v (C019): shard 001's accepted bytes, line count and entry
        # count are the ledger's tranche 3i record; the current file is held to the
        # format contract and the line cap, not to a byte identity.
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            line_count=SHARD_001_CURRENT_LINE_COUNT, entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        lines = self.shard_text.splitlines()
        self.assertLessEqual(len(lines), dti.SHARD_LINE_CAP)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)  # cap not raised
        self.assertTrue(self.shard_text.endswith("\n"))
        start = lines.index('  "assertions": [')
        entry_lines = lines[start + 1 : lines.index("  ]", start)]
        self.assertEqual(len(entry_lines), len(self.all_entries))
        for offset, line in enumerate(entry_lines):
            with self.subTest(line=start + 2 + offset):
                parsed = json.loads(line.strip().rstrip(","), object_pairs_hook=OrderedDict)
                self.assertEqual(tuple(parsed.keys()), EXPECTED_ENTRY_KEY_ORDER)
        self.assertEqual(json.loads(self.shard_text), self.shard)
        self.assertEqual(len({e["id"] for e in self.all_entries}), len(self.all_entries))
        failures, summary = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["manifest_assertions"], len(self.all_entries))
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
        # BL-038 tranche 3v (C017): the base manifest's accepted bytes and line count are
        # asserted from the immutable ledger; what stays current is that this tranche's
        # class did not leak into the base manifest.
        dth.assert_accepted(self, ROOT, "3f", sha256=BASE_MANIFEST_SHA256, line_count=BASE_MANIFEST_LINE_COUNT)
        raw = MANIFEST_PATH.read_bytes()
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
        # BL-038 tranche 3w round 2: candidate logic works on the LOGICAL window -- dth.live_entries(ROOT) over the indexed manifests -- filtered by the tranche's own
        # file and class, so a legal re-shard cannot empty it. cls.all_entries stays physical and is used only by the current shard-format tests.
        cls.entries = [e for e in dth.live_entries(ROOT) if e["file"] == TRANCHE_3J_SOURCE_FILE
                       and e["class"] == TRANCHE_3J_CLASS]
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
        """BL-038 tranche 3w (C031): accepted scope from the pinned map. Current physical placement is not pinned -- that is dth.owns() and the validator."""
        accepted_scope, _window = dth.accepted_window(ROOT, "3j")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3j"])
        self.assertEqual(len(SHARD_002_HISTORICAL_SCOPE_ORDER), 1)
        self.assertTrue(dth.owns("3j", TRANCHE_3J_SOURCE_FILE, TRANCHE_3J_CLASS, self.entries[0]["method"]))
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))

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
        # BL-038 tranche 3w (C026): the accepted 3h digest comes from the ledger, and the window is located by logical ownership instead of a positional prefix. What is
        # demonstrated here is only that widening the scope moves the digest.
        dth.assert_accepted(self, ROOT, "3h", content_digest=TRANCHE_3H_HISTORICAL_CONTENT_SHA256)
        accepted_scope, window = dth.accepted_window(ROOT, "3h")
        baseline = _subset_content_digest(accepted_scope, window)
        mutated_scope = json.loads(json.dumps(accepted_scope))
        mutated_scope[0]["classes"] = mutated_scope[0]["classes"] + [TRANCHE_3J_CLASS]
        self.assertNotEqual(_subset_content_digest(mutated_scope, window), baseline)

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
        # BL-038 tranche 3w (C030): shard 001's accepted bytes, line count and entry count are the ledger's tranche 3i record. The current file is no longer byte-frozen;
        # its accepted contracts must still be accounted for.
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            line_count=SHARD_001_CURRENT_LINE_COUNT, entry_count=SHARD_001_CURRENT_ENTRY_COUNT)

    # -- membership --------------------------------------------------------

    def test_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        """BL-038 tranche 3w (C028): accepted ids/order/count are past facts; id agreement, uniqueness and method existence are the validator's."""
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3j")

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
        """BL-038 tranche 3w (C024): the accepted API breakdown is a past measurement; manifest-vs-live agreement is the validator's. Only lineage remains here."""
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3j")

    def test_exact_category_membership_matches_hardcoded_id_sets(self):
        # BL-038 tranche 3w (C027): the accepted id->category membership and the accepted counts are past facts, read from the immutable ledger. The current tree keeps
        # category/action consistency only, never a frozen category.
        self.assertEqual(TRANCHE_3J_EXPECTED_A_IDS, frozenset())
        dth.assert_accepted(self, ROOT, "3j", entry_count=TRANCHE_3J_EXPECTED_ASSERTION_COUNT,
                            category_counts=TRANCHE_3J_EXPECTED_CATEGORY_COUNTS)
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])

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

    def test_tranche_3j_parsed_content_still_equals_the_accepted_record(self):
        """The id/category/order guards above cannot see an edit to a
        historical entry's targets/action/summary/rationale. Reconstructing
        scope[0] + the first 34 entries from the CURRENT file must digest to
        the value derived from shard 002 AS ACCEPTED at merge commit
        f068270e5e... -- not regenerated from the file this branch edited."""
        # BL-038 tranche 3w (C033): the accepted digest is asserted from the ledger, not recomputed from the current shard, and the positional "first 34" prefix is
        # replaced by accepted-contract continuity. The sensitivity demonstration below now measures against the current subset's own digest.
        dth.assert_accepted(self, ROOT, "3j", content_digest=TRANCHE_3J_HISTORICAL_CONTENT_SHA256)
        accepted_scope, window = dth.accepted_window(ROOT, "3j")
        baseline = _subset_content_digest(accepted_scope, window)
        # Demonstrated: the digest moves for each blind-spot field, for a
        # scope edit, for a reordering, and for the append itself.
        for field, value in (("targets", ["README.md"]), ("action", "keep"),
                             ("contract_summary", "x"), ("rationale", "x")):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(window))
                self.assertNotEqual(mutated[0][field], value)
                mutated[0][field] = value
                self.assertNotEqual(_subset_content_digest(accepted_scope, mutated), baseline)
        for scope, entries in (([{"file": "x.py", "classes": []}], window),
                               (accepted_scope, window[::-1]),
                               (accepted_scope, window + window)):
            self.assertNotEqual(_subset_content_digest(scope, entries), baseline)

    def test_tranche_3j_file_snapshot_is_history_not_the_current_file(self):
        """34 / 42 / SHA 3772b37f was shard 002 AT TRANCHE 3J's MERGE, so those
        numbers are history, asserted NOT to describe the file today."""
        # BL-038 tranche 3w (C032): the accepted 34 / 42 / SHA 3772b37f snapshot comes from the ledger; the current file is only asserted NOT to be that snapshot.
        dth.assert_accepted(self, ROOT, "3j", sha256=TRANCHE_3J_HISTORICAL_SHA256,
                            line_count=TRANCHE_3J_HISTORICAL_LINE_COUNT,
                            entry_count=TRANCHE_3J_HISTORICAL_ENTRY_COUNT)
        current_lines = len(self.shard_text.splitlines())
        current_sha = hashlib.sha256(SHARD_002_PATH.read_bytes()).hexdigest()
        self.assertNotEqual(current_lines, TRANCHE_3J_HISTORICAL_LINE_COUNT)
        self.assertNotEqual(current_sha, TRANCHE_3J_HISTORICAL_SHA256)

    def test_scope_shrinkage_mutation_of_shard_002_is_detected(self):
        """Dropping the class from scope must not silently pass: the entries
        would then belong to no scoped class at all."""
        mutated = json.loads(json.dumps(self.shard))
        mutated["scope"][0]["classes"] = []
        failures, _ = dti.validate_manifest(mutated, root=ROOT)
        self.assertNotEqual([f.format() for f in failures], [])

    def test_no_category_c_source_conversion_happened_in_this_tranche(self):
        """BL-038 tranche 3w (C029): "still Category C, still refactor_later" is a past fact, not a current contract -- requiring it of the live tree is precisely what
        blocks conversion. The accepted C count is read from the immutable ledger, and current category/action consistency belongs to the validator."""
        record = dth.assert_accepted(self, ROOT, "3j",
                                     category_counts=TRANCHE_3J_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(record["historical"]["category_counts"]["C"], 14)


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
        cls.all_entries = cls.shard["assertions"]  # physical: shard-format tests only
        cls.entries = [e for e in dth.live_entries(ROOT) if e["file"] == TRANCHE_3K_SOURCE_FILE
                       and e["class"] == TRANCHE_3K_CLASS]
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
        """BL-038 tranche 3w (C039): accepted scope from the pinned map; no current physical placement pin."""
        accepted_scope, _window = dth.accepted_window(ROOT, "3k")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3k"])
        self.assertTrue(dth.owns("3k", TRANCHE_3K_SOURCE_FILE, TRANCHE_3K_CLASS, self.entries[0]["method"]))
        self.assertEqual(self.source_classes, [TRANCHE_3K_CLASS])  # whole selected file
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))

    # -- shard-allocation decision, measured -------------------------------

    def test_the_append_is_legal_and_leaves_the_older_shards_untouched(self):
        """BL-038 tranche 3w round 2 (C041): the accepted allocation is history. Which physical shard holds this contract today is not required, and the generic
        duplicate-scope-file rule is the validator's -- neither is re-implemented here. What remains is the accepted state of the older shard, read from the ledger."""
        # BL-038 tranche 3w (C041): the older shard's accepted bytes and the 3h content digest are asserted from the ledger, not re-derived from the current file.
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            line_count=SHARD_001_CURRENT_LINE_COUNT, entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        dth.assert_accepted(self, ROOT, "3h", content_digest=TRANCHE_3H_HISTORICAL_CONTENT_SHA256)
        # Round 1: the class's absence from shard 001 is current physical placement and is
        # left to the validator / logical ownership, not pinned here.

    def test_the_append_preserves_3j_fits_the_cap_and_adds_no_third_shard(self):
        """Reasons 3-5. (3) Shard 002's accepted state stays pinnable: the
        historical 34 keep their ids, categories, order and parsed content,
        and only the 34th raw line's trailing comma changed. (4) The line cap
        does not bind -- shard 001 had room too, which is why the choice
        needed a reason. (5) The index is unchanged and no `_003` exists."""
        # BL-038 tranche 3w (C042): 3j's accepted digest and counts come from the ledger; the positional [:34] and [34:61] reconstructions are gone.
        dth.assert_accepted(self, ROOT, "3j", content_digest=TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
                            category_counts=TRANCHE_3J_EXPECTED_CATEGORY_COUNTS)
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3k")
        self.assertEqual((TRANCHE_3J_HISTORICAL_LINE_COUNT,
                          TRANCHE_3K_HISTORICAL_LINE_COUNT), (42, 70))
        self.assertEqual(dti.SHARD_LINE_CAP, 600)
        self.assertLess(TRANCHE_3K_HISTORICAL_LINE_COUNT, dti.SHARD_LINE_CAP)
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3K_EXPECTED_ASSERTION_COUNT,
                        dti.SHARD_LINE_CAP)
        # Round 2 (C042): "the index held three shards at tranche 3k" is a past fact and is not required of the CURRENT index -- index validity is the validator's and the
        # index tests'. Only the constant-only historical record stays.
        self.assertEqual(TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT, 3)

    # -- membership --------------------------------------------------------

    def test_ids_are_exactly_the_hardcoded_source_order_expansion(self):
        """BL-038 tranche 3w (C035): accepted ids/order/count are past facts; manifest agreement is the validator's."""
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3k")

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
        # BL-038 tranche 3w (C034): accepted membership and counts are past facts from the ledger; the current tree keeps category/action consistency only.
        self.assertEqual((TRANCHE_3K_EXPECTED_A_IDS, TRANCHE_3K_EXPECTED_D_IDS),
                         (frozenset(), frozenset()))
        dth.assert_accepted(self, ROOT, "3k", category_counts=TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS)
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])

    def test_the_five_c_entries_are_layout_locks_sha_comments_and_a_quote_lock(self):
        """Not a keyword tally: each of the five is the exact assertion whose
        raw text a meaning-preserving workflow edit breaks."""
        # BL-038 tranche 3w (C043): the exact accepted C-id list is a past fact and is gone. What remains is a CURRENT contract about the source itself: the layout locks,
        # the pinned-SHA comment lines and the quote lock are still there.
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
        # A pinned SHA is a CURRENT structural contract, not historical evidence; which
        # category the manifest gives it today is the validator's business, not this
        # test's, so no category is frozen here.

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
        # BL-038 tranche 3w (C038): the accepted zero-duplicate measurement is not required of the current corpus; the accepted A=0 result is a ledger fact.
        record = dth.assert_accepted(self, ROOT, "3k",
                                     category_counts=TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS)
        self.assertEqual(record["historical"]["category_counts"]["A"], 0)

    def test_the_accepted_tranche_3k_shard_002_state_is_pinned_as_history(self):
        """Shard 002 AS ACCEPTED at PR #93's merge commit
        764da66947a9b480ee2f074d553111a8e5bb278c: 61 entries, 70 lines, SHA
        `1aee40fd...`, scope[0:2], A0/B34/C19/D8. Tranche 3l appended 23 more,
        so each of these is asserted to be HISTORY and NOT the current state.
        The parsed-content digest was derived from the accepted file, not
        regenerated here, so it pins targets/action/contract_summary/rationale
        for all 61 -- the fields the id, category and order guards cannot see."""
        # BL-038 tranche 3w (C040): every accepted statistic comes from the ledger; the positional [:61] window and exact accepted id list are gone.
        dth.assert_accepted(self, ROOT, "3k", sha256=TRANCHE_3K_HISTORICAL_SHA256,
                            line_count=TRANCHE_3K_HISTORICAL_LINE_COUNT,
                            entry_count=TRANCHE_3K_HISTORICAL_ENTRY_COUNT,
                            category_counts=TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS,
                            content_digest=TRANCHE_3K_HISTORICAL_CONTENT_SHA256)
        accepted_scope, historical = dth.accepted_window(ROOT, "3k")
        baseline = _subset_content_digest(accepted_scope, historical)
        # Demonstrated non-vacuous: the digest moves if any accepted field does.
        for field, value in (("category", "D"), ("action", "keep"),
                             ("rationale", "x"), ("contract_summary", "x"),
                             ("targets", ["README.md"])):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(historical))
                mutated[-1][field] = value
                self.assertNotEqual(_subset_content_digest(accepted_scope, mutated), baseline)
        # BL-038 tranche 3w-b: same reverse coupling as C048, removed for the same reason.
        # Measured: dropping tranche 3m leaves shard 002 byte-identical to the accepted 3l
        # state, and dropping 3l and 3m leaves it identical to this accepted 3k state --
        # both legal. The accepted state is protected by the ledger above, not by
        # requiring the current file to keep differing from it.
        dth.assert_accepted(self, ROOT, "3j", content_digest=TRANCHE_3J_HISTORICAL_CONTENT_SHA256)

    def test_dropping_the_appended_scope_entry_is_detected(self):
        """The appended 27 must not sit in the file with their class removed
        from scope -- they would then belong to no scoped class at all."""
        mutated = json.loads(json.dumps(self.shard))
        del mutated["scope"][1]
        self.assertNotEqual(dti.validate_manifest(mutated, root=ROOT)[0], [])

    def test_no_category_c_source_conversion_happened_in_this_tranche(self):
        """BL-038 tranche 3w (C036): "still Category C, still refactor_later, still 27 unconverted assertions" is a past fact, not a current contract. The accepted C
        count is read from the ledger; current consistency belongs to the validator."""
        record = dth.assert_accepted(self, ROOT, "3k",
                                     category_counts=TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS)
        self.assertEqual(record["historical"]["category_counts"]["C"], 19)


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
        cls.all_entries = cls.shard["assertions"]  # physical: shard-format tests only
        cls.entries = [e for e in dth.live_entries(ROOT) if e["file"] == TRANCHE_3L_SOURCE_FILE
                       and e["class"] in TRANCHE_3L_CLASSES]
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
        # BL-038 tranche 3w round 2 (C049): accepted scope from the pinned map; no current physical placement, and the generic duplicate-scope rule stays the validator's.
        accepted_scope, _window = dth.accepted_window(ROOT, "3l")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3l"])
        for class_name in TRANCHE_3L_CLASSES:
            with self.subTest(class_name=class_name):
                self.assertTrue(dth.owns("3l", TRANCHE_3L_SOURCE_FILE, class_name, self.entries[0]["method"]))
        self.assertEqual(self.source_classes, list(TRANCHE_3L_CLASSES))
        self.assertEqual(len(TRANCHE_3L_CLASSES), TRANCHE_3L_EXPECTED_CLASS_COUNT)
        # The older shard's accepted bytes and the 3h digest come from the ledger.
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            line_count=SHARD_001_CURRENT_LINE_COUNT, entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        dth.assert_accepted(self, ROOT, "3h", content_digest=TRANCHE_3H_HISTORICAL_CONTENT_SHA256)
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3l")

    def test_the_append_preserves_the_accepted_61_and_adds_no_third_shard(self):
        """Reasons 3-5: the accepted 61 keep ids, categories, order and parsed
        content; the cap does not bind (shard 001 had room too, so the choice
        needed a measured reason); the index is unchanged."""
        # BL-038 tranche 3w (C050): the accepted 61's digest comes from the ledger and the positional [:61] / [61:84] windows give way to contract continuity.
        dth.assert_accepted(self, ROOT, "3k", content_digest=TRANCHE_3K_HISTORICAL_CONTENT_SHA256)
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3l")
        self.assertEqual((TRANCHE_3K_HISTORICAL_LINE_COUNT, TRANCHE_3L_HISTORICAL_LINE_COUNT,
                          dti.SHARD_LINE_CAP), (70, 94, 600))
        self.assertLess(SHARD_002_CURRENT_LINE_COUNT, dti.SHARD_LINE_CAP)
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3L_EXPECTED_ASSERTION_COUNT,
                        dti.SHARD_LINE_CAP)
        # Round 2 (C050): the historical shard allocation is not required of the current index; index validity belongs to the validator and the index tests.
        self.assertEqual(TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT, 3)

    # -- membership --------------------------------------------------------

    def test_ids_and_api_breakdown_match_the_hardcoded_source_order(self):
        """BL-038 tranche 3w (C045): accepted ids, order, API breakdown and category membership are past facts; manifest agreement and order are the validator's."""
        dth.assert_accepted(self, ROOT, "3l", category_counts=TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS)
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3l")

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
        # BL-038 tranche 3w (C047): the accepted fingerprint duplicate groups, their counts and the accepted A id set were accepted-time measurement and are gone -- a
        # legal conversion moves fingerprints. The whole-method structural evidence above is a CURRENT property of the source and stays. The accepted A count is a past
        # fact in the ledger.
        dth.assert_accepted(self, ROOT, "3l", category_counts=TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS)
        leading = [e for e in self.entries
                   if e["method"] in TRANCHE_3L_A_METHOD_PAIR and e["ordinal"] == 1]
        self.assertEqual((len(leading), {e["assertion_api"] for e in leading}),
                         (2, {"assertTrue"}))

    def test_the_six_c_entries_are_sha_comment_welds_quote_locks_and_prose(self):
        """Not a keyword tally: each is the exact assertion a meaning-preserving
        edit of the live target file breaks."""
        # BL-038 tranche 3w (C051): the accepted C-id breakdown is a past fact and is gone; what remains are CURRENT contracts about the live target files. (a) Two raw
        # lines weld a full commit SHA to an inert `# vX.Y.Z` comment -- the shape accepted as C in tranche 3k.
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
        self.assertEqual(len(quote_locked), 3)
        for pattern in quote_locked:
            with self.subTest(pattern=pattern):
                self.assertRegex(dependabot, pattern)
                self.assertNotRegex(dependabot.replace('"', "'"), pattern)
        # (c) One raw absence check over ORDINARY ENGLISH WORDS -- what separates
        # it from the negative raw checks kept at B here and in tranche 3k, all of
        # which use non-prose structural tokens. (Exact tuple pinned above.)
        self.assertFalse([m for m in TRANCHE_3L_PROHIBITED["marker"] if m in dependabot])
        # No date, PR number or CI run id anywhere in the source; which category the
        # manifest gives each entry today is the validator's business, not this test's.
        self.assertNotRegex(self.source, r"20\d\d-\d\d-\d\d")

    def test_the_accepted_tranche_3l_shard_002_state_is_pinned_as_history(self):
        """Shard 002 AS ACCEPTED at PR #94's merge commit
        48cc4fdf38303e9693cf870fb2f73a595d4908b2: 84 entries, 94 lines, SHA
        `c0f81d14...`, scope[0:3], A6/B45/C25/D8. That accepted state is HISTORICAL
        EVIDENCE, held by the immutable ledger. The CURRENT shard may differ from it or
        may legally coincide with it again -- for instance once a legal re-shard moves a
        later tranche's class out -- so nothing here requires the two to stay different.
        The parsed-content digest was derived from the accepted file, not regenerated
        here, so it pins targets/action/contract_summary/rationale for all 84 -- the
        fields the id, category and order guards cannot see."""
        # BL-038 tranche 3w (C048): accepted statistics come from the ledger; the positional [:84] window and exact accepted id list are gone.
        dth.assert_accepted(self, ROOT, "3l", sha256=TRANCHE_3L_HISTORICAL_SHA256,
                            line_count=TRANCHE_3L_HISTORICAL_LINE_COUNT,
                            entry_count=TRANCHE_3L_HISTORICAL_ENTRY_COUNT,
                            category_counts=TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS,
                            content_digest=TRANCHE_3L_HISTORICAL_CONTENT_SHA256)
        accepted_scope, historical = dth.accepted_window(ROOT, "3l")
        baseline = _subset_content_digest(accepted_scope, historical)
        # Demonstrated non-vacuous: the digest moves if any accepted field does.
        for field, value in (("category", "D"), ("action", "keep"), ("rationale", "x"),
                             ("contract_summary", "x"), ("targets", ["README.md"])):
            with self.subTest(field=field):
                mutated = json.loads(json.dumps(historical))
                mutated[-1][field] = value
                self.assertNotEqual(_subset_content_digest(accepted_scope, mutated), baseline)
        # BL-038 tranche 3w-b: the "current must keep differing from history" assertions
        # are gone. They were reverse coupling, not preservation: a legal re-shard that
        # moves tranche 3m out leaves shard 002 byte-identical to its accepted tranche-3l
        # state, which is legitimate. The accepted state is protected by the ledger above.
        # PR #95 round 1 (Blocker 3): the accepted 84 are preserved by PARSED content, NOT
        # raw bytes, so raw-byte identity is never claimed. Round 2: the physical scope-entry
        # count and raw comma layout are the shard-format validator's contract, not pinned
        # here -- a legal re-shard changes both.
        # The accepted 3k and 3j digests are asserted from the ledger, not re-derived.
        dth.assert_accepted(self, ROOT, "3k", content_digest=TRANCHE_3K_HISTORICAL_CONTENT_SHA256)
        dth.assert_accepted(self, ROOT, "3j", content_digest=TRANCHE_3J_HISTORICAL_CONTENT_SHA256)

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
        # BL-038 tranche 3w (C044): "still C, still refactor_later, still 23 unconverted" is a past fact from the ledger, not a current requirement.
        dth.assert_accepted(self, ROOT, "3l", category_counts=TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS)
        # Round 2 (C044): the scope-drop mutations indexed a fixed physical scope position, which a legal re-shard moves. Scope ownership is the validator's generic rule
        # and is not re-implemented here; accepted coverage is contract continuity.
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3l")


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
        cls.all_entries = cls.shard["assertions"]  # physical: shard-format tests only
        cls.entries = [e for e in dth.live_entries(ROOT) if e["file"] == TRANCHE_3M_SOURCE_FILE
                       and e["class"] == TRANCHE_3M_CLASS]
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
                    if (scope_entry["file"] == TRANCHE_3M_SOURCE_FILE and name != SHARD_002_FILENAME
                            and "method_range" not in scope_entry): owned.add(class_name)
        unclassified = [(i, c) for i, c in enumerate(self.source_classes) if c not in owned and c != TRANCHE_3M_CLASS]
        # Still true after tranche 3o: 3o took a source-order method RANGE of the
        # over-cap class, not the whole class, so the class is not wholly owned.
        self.assertEqual(unclassified, [(0, TRANCHE_3M_OVER_CAP_CLASS)])
        self.assertTrue(any("method_range" in e for name in EXPECTED_SHARD_ORDER
                            for e in json.loads((ROOT / name).read_text(encoding="utf-8"))["scope"]
                            if e["file"] == TRANCHE_3M_SOURCE_FILE and TRANCHE_3M_OVER_CAP_CLASS in e["classes"]))
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
        # BL-038 tranche 3w round 2 (C060): accepted scope from the pinned map; no current physical position, and duplicate-scope enforcement stays the validator's.
        accepted_scope, _window = dth.accepted_window(ROOT, "3m")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3m"])
        self.assertEqual(tuple(self.shard.keys()), ("schema_version", "scope", "assertions"))
        self.assertIs(type(self.shard["schema_version"]), int)
        self.assertEqual(self.shard["schema_version"], 1)
        # BL-038 tranche 3w (C060): the older manifests' accepted bytes, lines and entry counts come from the ledger, not the current files.
        dth.assert_accepted(self, ROOT, "3f", sha256=BASE_MANIFEST_SHA256, line_count=BASE_MANIFEST_LINE_COUNT,
                            entry_count=585)
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            line_count=SHARD_001_CURRENT_LINE_COUNT, entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        # The class's absence from the other manifests is current physical placement and
        # is left to the validator, not pinned here.
        self.assertLess(SHARD_001_CURRENT_LINE_COUNT + TRANCHE_3M_EXPECTED_ASSERTION_COUNT, dti.SHARD_LINE_CAP)
        # Round 2 (C060): tranche 3m created no `_003` -- a past fact, kept as a constant and no longer required of the current index or shard set.
        self.assertEqual(TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT, 3)

    def test_no_class_is_owned_by_two_shards_and_the_84_keep_their_place(self):
        """Tranche 3m HISTORICAL evidence, anchored on the three shards that
        existed then. It deliberately does NOT say 'no class may ever appear in
        two shards': tranche 3n made that legal for disjoint, source-order
        method ranges of one class, and enforcing it here would break the next
        legal range append. That invariant now lives in the method-level
        ownership validator, which this suite exercises separately."""
        # BL-038 tranche 3w (C058): no current physical layout is re-frozen -- ownership is dth.owns(), coverage is contract continuity.
        self.assertEqual(len(TRANCHE_3M_HISTORICAL_SHARD_ORDER),
                         TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT)
        self.assertTrue(dth.owns("3m", TRANCHE_3M_SOURCE_FILE, TRANCHE_3M_CLASS, self.entries[0]["method"]))
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3m")

    # -- membership ---------------------------------------------------------

    def test_ids_and_api_breakdown_match_the_hardcoded_source_order(self):
        """BL-038 tranche 3w (C057): accepted ids, order, arity and API breakdown are past facts; manifest agreement is the validator's. The independent current
        contract kept is that the class defines no custom assertion helper."""
        self.assertEqual(dti._helper_defs_for_class(self.class_node), {})
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3m")

    def test_exact_category_membership_and_totals(self):
        # BL-038 tranche 3w (C056): accepted membership and counts are ledger facts; the current tree keeps category/action consistency.
        expected = set(self.expected_ids_in_source_order())
        dth.assert_accepted(self, ROOT, "3m", category_counts=SHARD_002_CURRENT_CATEGORY_COUNTS)
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
        # The four accepted C shapes still partition the accepted C id set exactly.
        self.assertEqual(TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS | TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS
                         | TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS | TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS, TRANCHE_3M_EXPECTED_C_IDS)
        self.assertEqual(sum(len(s) for s in (TRANCHE_3M_EXPECTED_WELDED_STATUS_C_IDS, TRANCHE_3M_EXPECTED_GIANT_LINE_C_IDS,
                                              TRANCHE_3M_EXPECTED_CURRENT_STATE_PROSE_C_IDS,
                                              TRANCHE_3M_EXPECTED_NORMALIZED_PROSE_C_IDS)), len(TRANCHE_3M_EXPECTED_C_IDS))
        # The accepted C/D id sets are not required to still be present in the current
        # enumeration -- a legal conversion may renumber or retire them.
        self.assertTrue(TRANCHE_3M_EXPECTED_C_IDS and TRANCHE_3M_EXPECTED_D_IDS)

    def test_tranche_3m_combined_945_is_history_and_the_index_still_validates(self):
        """945 was the combined total tranche 3m produced, and it still stood at
        the end of tranche 3n (which classified nothing). Tranche 3o's 146 make
        it history; what stays true about 3m is its arithmetic and the fact that
        the index it contributed to still validates clean."""
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(945, 928 + TRANCHE_3M_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(summary["inventoried_assertions"], INDEX_COMBINED_ASSERTION_COUNT)
        for historical in (945, 1091):
            with self.subTest(historical=historical):
                self.assertNotEqual(summary["inventoried_assertions"], historical)
        self.assertEqual({k: summary["category_counts"][k] for k in ("A", "B", "C", "D")},
                         INDEX_COMBINED_CATEGORY_COUNTS)
        self.assertEqual(sum(summary["category_counts"][k] for k in ("A", "B", "C", "D")),
                         INDEX_COMBINED_ASSERTION_COUNT)
        self.assertEqual((summary["unclassified"], summary["stale"], summary["fingerprint_mismatch"]), (0, 0, 0))

    # -- Category A: measured absence, not an unexamined zero ----------------

    def test_category_a_is_empty_because_no_pair_of_methods_parameterises(self):
        """Tranche 3l's A bar: normalising ONE varying token made two methods
        byte-identical. Three methods here share an AST node-type skeleton (node
        types cannot tell `assertIn` from `assertNotIn`), so the skeleton is not
        the measure -- every pair differs in at least TWO literals and carries
        different categories. The one real whole-method twin sits in a base-
        manifest class whose accepted rationale already declined consolidation."""
        # BL-038 tranche 3w (C052): accepted A=0 is a ledger fact; the structural evidence below is a current property of the source.
        self.assertEqual(TRANCHE_3M_EXPECTED_A_IDS, frozenset())
        dth.assert_accepted(self, ROOT, "3m", category_counts=SHARD_002_CURRENT_CATEGORY_COUNTS)
        # The survey runs over the methods the CURRENT manifest covers, so it does not
        # depend on the accepted method list still describing the live class.
        covered = sorted({e["method"] for e in self.entries})
        selected = [self.methods[m] for m in covered]
        skeleton = lambda n: tuple(type(x).__name__ for x in ast.walk(n))
        groups = {}
        for method in covered: groups.setdefault(skeleton(self.methods[method]), []).append(method)
        # BL-038 tranche 3w-b: the skeleton-group histogram and the exact shared-method
        # tuple were accepted-time measurements -- a legal Category C conversion changes a
        # method's AST and so its grouping. The surviving contract is the PROPERTY that
        # justified A=0: whatever methods share a skeleton today, no pair of them is a
        # one-token parameterisation of the other.
        literals = lambda name: [c.value for c in ast.walk(self.methods[name])
                                 if isinstance(c, ast.Constant) and isinstance(c.value, str)]
        for shared in [v for v in groups.values() if len(v) > 1]:
            for first, second in itertools.combinations(shared, 2):
                with self.subTest(pair=(first, second)):
                    differing = [a for a, b in zip(literals(first), literals(second)) if a != b]
                    # Two or more independent literals vary: not a one-token swap.
                    self.assertGreaterEqual(len(differing), 2)
                    self.assertNotEqual(ast.unparse(self.methods[first]),
                                        ast.unparse(self.methods[second]))
        # Every covered method's unparsed body is distinct.
        self.assertEqual(len({ast.unparse(n) for n in selected}), len(selected))
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
        # BL-038 tranche 3w (C061): the accepted D id set and the B/D split are past facts; only the live documents' content is asserted here.
        status_id = _B34 + "test_requirements_document_itself_is_version_17_draft::assert-02"
        self.assertNotIn(status_id, TRANCHE_3M_EXPECTED_D_IDS)

    # -- fingerprints, duplicates and cross-shard collisions ----------------

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
        # BL-038 tranche 3w (C059): shard 002's accepted bytes, lines and entry count are the ledger's tranche 3m record; the file is held to the format contract and cap.
        dth.assert_accepted(self, ROOT, "3m", sha256=SHARD_002_CURRENT_SHA256,
                            line_count=SHARD_002_CURRENT_LINE_COUNT, entry_count=SHARD_002_CURRENT_ENTRY_COUNT)
        lines = self.shard_text.splitlines()
        self.assertLessEqual(len(lines), dti.SHARD_LINE_CAP)
        self.assertEqual(dti.SHARD_LINE_CAP, BASE_MANIFEST_LINE_CAP)  # cap not raised
        self.assertTrue(self.shard_text.endswith("\n"))
        start = lines.index('  "assertions": [')
        entry_lines = lines[start + 1 : lines.index("  ]", start)]
        self.assertEqual(len(entry_lines), len(self.all_entries))
        for offset, line in enumerate(entry_lines):
            with self.subTest(line=start + 2 + offset): self.assertEqual(tuple(json.loads(line.strip().rstrip(","),
                                                  object_pairs_hook=OrderedDict).keys()), EXPECTED_ENTRY_KEY_ORDER)
        self.assertEqual(json.loads(self.shard_text), self.shard)
        self.assertEqual(len({e["id"] for e in self.all_entries}), len(self.all_entries))
        failures, summary = dti.validate_manifest(self.shard, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["manifest_assertions"], summary["inventoried_assertions"])
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
        # BL-038 tranche 3w (C054): "still C / still refactor_later" is a past fact.
        dth.assert_accepted(self, ROOT, "3m", category_counts=SHARD_002_CURRENT_CATEGORY_COUNTS)
        self.assertEqual({t for e in self.entries for t in e["targets"]}, {TRANCHE_3M_TARGET_BL009, TRANCHE_3M_TARGET_BL034,
                          TRANCHE_3M_TARGET_GAP_REGISTER, TRANCHE_3M_TARGET_GAP_016, TRANCHE_3M_TARGET_GAP_018, TRANCHE_3M_TARGET_REQUIREMENTS})
        # Backlog-scoped entries never claim a requirements target, or vice versa.
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                document = entry["targets"][0].split("#")[0]
                self.assertIn(document, ("BACKLOG.md", "SECURITY_REQUIREMENTS.md"))
                self.assertTrue((ROOT / document).is_file())
        # Round 2 (C054): the scope-drop mutations indexed a fixed physical scope position.
        # Scope ownership stays the validator's; accepted coverage is contract continuity.
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3m")

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
             "shards": [MANIFEST_PATH.name, SHARD_001_FILENAME, SHARD_002_FILENAME,
                        SHARD_003_FILENAME, SHARD_004_FILENAME, SHARD_005_FILENAME,
                        SHARD_006_FILENAME, SHARD_007_FILENAME]},
        )
        self.assertTrue(self.index_text.endswith("\n"))
        # Order is part of the contract: it fixes combined assertion order.
        self.assertEqual(tuple(self.index["shards"]), EXPECTED_SHARD_ORDER)
        self.assertEqual(self.index["shards"][0], MANIFEST_PATH.name)
        self.assertEqual(self.index["shards"][1], SHARD_001_FILENAME)
        self.assertEqual(self.index["shards"][2], SHARD_002_FILENAME)
        self.assertEqual(self.index["shards"][3], SHARD_003_FILENAME)
        self.assertEqual(self.index["shards"][4], SHARD_004_FILENAME)
        self.assertEqual(self.index["shards"][5], SHARD_005_FILENAME)
        self.assertEqual(self.index["shards"][6], SHARD_006_FILENAME)
        self.assertEqual(self.index["shards"][7], SHARD_007_FILENAME)
        self.assertEqual(len(self.index["shards"]), EXPECTED_SHARD_COUNT)
        self.assertEqual(EXPECTED_SHARD_COUNT, 8)
        self.assertEqual(len(set(self.index["shards"])), EXPECTED_SHARD_COUNT)
        # An unregistered shard file would silently vanish from the check.
        self.assertEqual(dti.discover_shard_filenames(ROOT), sorted(EXPECTED_SHARD_ORDER))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_001_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_002_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_003_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_004_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_005_FILENAME))
        self.assertTrue(dti.is_allowed_shard_filename(SHARD_006_FILENAME))
        self.assertFalse(dti.is_allowed_shard_filename(dti.INDEX_FILENAME))
        # Tranche 3g shipped a one-shard index, 3i a two-shard one and 3j-3n a
        # three-shard one; all three are history, not now.
        self.assertEqual(TRANCHE_3G_HISTORICAL_SHARD_COUNT, 1)
        self.assertEqual(TRANCHE_3I_HISTORICAL_SHARD_COUNT, 2)
        self.assertEqual(TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT, 3)
        for historical in (TRANCHE_3G_HISTORICAL_SHARD_COUNT, TRANCHE_3I_HISTORICAL_SHARD_COUNT,
                           TRANCHE_3J_TO_3N_HISTORICAL_SHARD_COUNT):
            with self.subTest(historical=historical):
                self.assertNotEqual(len(self.index["shards"]), historical)

    def test_combined_index_validation_reports_the_five_shard_totals(self):
        failures, combined = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        # BL-038 tranche 3w-b (C003 remediation): the exact CURRENT shard count and file
        # order are not pinned -- a legal re-shard adds a shard. What stays is that the
        # index the validator walked is the index on disk.
        self.assertEqual(combined["shard_files"], list(self.index["shards"]))
        self.assertEqual(combined["shard_count"], len(self.index["shards"]))
        self.assertEqual(combined["manifest_assertions"], combined["inventoried_assertions"])
        # BL-038 tranche 3v (C003): the combined total, its per-tranche decomposition and
        # the accepted category breakdown are accepted-time facts, each held by its own
        # tranche's immutable ledger record. The CURRENT index is held to internal
        # consistency and validator cleanliness only, so a legal Category C conversion
        # may move these numbers without rewriting history.
        for tranche in sorted(dth.ACCEPTED_SCOPES):
            with self.subTest(tranche=tranche):
                historical = dth.accepted(ROOT, tranche)["historical"]
                self.assertEqual(sum(historical["category_counts"].values()),
                                 historical["entry_count"])
        self.assertEqual(sum(combined["category_counts"].values()),
                         combined["manifest_assertions"])
        self.assertEqual(
            (combined["unclassified"], combined["stale"], combined["fingerprint_mismatch"]), (0, 0, 0)
        )
        # The scoped-file set was a historical corpus freeze; what carries independent
        # CURRENT meaning is that every scoped file exists and is covered exactly once.
        self.assertEqual(sorted(combined["scoped_files"]), sorted(set(combined["scoped_files"])))
        for name in combined["scoped_files"]:
            with self.subTest(file=name):
                self.assertTrue((ROOT / name).is_file())
        # BL-038 tranche 3v (C003): the accepted per-file assertion counts were pinned
        # here as well; they are past facts in the ledger, not properties the current
        # index must reproduce. Which files are in scope stays a current property above.

    def test_combined_assertion_order_follows_the_index_shard_by_shard(self):
        """BL-038 tranche 3w-b (C002 remediation): the 3w-a re-shard probe showed this row
        still pinned CURRENT physical placement -- an explicit EXPECTED_SHARD_ORDER load,
        a per-shard read of each file, and per-tranche `owner == shard 00N` assertions --
        which blocks a legal re-shard. The CURRENT responsibility kept here is minimal:
        the index loads, the combined order follows the index shard by shard, and no id
        repeats across shards. Which shard owns a class today is the validator's, and
        accepted coverage is contract continuity."""
        shards = list(self.index["shards"])
        load_failures, loaded = dti.load_shard_manifests(shards, root=ROOT)
        self.assertEqual(load_failures, [])
        self.assertEqual([shard for shard, _ in loaded], shards)
        combined_ids = dti.combined_assertion_ids(loaded)
        per_shard = [e["id"] for _, manifest in loaded for e in manifest["assertions"]]
        self.assertEqual(combined_ids, per_shard)  # index order, shard by shard
        self.assertEqual(len(set(combined_ids)), len(combined_ids))  # no cross-shard duplicate
        self.assertEqual([f.format() for f in dti.validate_indexed_manifests(root=ROOT)[0]], [])
        for tranche in sorted(dth.ACCEPTED_SCOPES):
            with self.subTest(tranche=tranche):
                dth.assert_accepted_contracts_accounted_for(self, ROOT, tranche)

    def test_legacy_single_manifest_path_still_validates_the_base_alone(self):
        """`--manifest` keeps working and keeps reporting the BASE manifest alone,
        untouched by the new shard. BL-038 tranche 3v (C004): the accepted 585 /
        A22/B175/C268/D120 record is a past fact in the ledger, no longer required of
        the current base manifest, which a legal conversion may move."""
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        failures, legacy = dti.validate_manifest(manifest, root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(legacy["manifest_assertions"], legacy["inventoried_assertions"])
        self.assertEqual(sum(legacy["category_counts"].values()), legacy["manifest_assertions"])
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
        # BL-038 tranche 3v (C001): the accepted bytes, line count, entry count and
        # category breakdown of the base manifest are past facts, asserted from the
        # immutable ledger. The CURRENT file is no longer byte-frozen, which is what
        # blocked Category C conversion; what stays is that tranche 3h-3l's work did
        # not leak into it and that the line cap was not raised.
        dth.assert_accepted(self, ROOT, "3f", sha256=BASE_MANIFEST_SHA256, line_count=BASE_MANIFEST_LINE_COUNT,
                            entry_count=BASE_EXPECTED_ASSERTION_COUNT, category_counts=BASE_EXPECTED_CATEGORY_COUNTS)
        raw = MANIFEST_PATH.read_bytes()
        text = raw.decode("utf-8")
        # The cap is why sharding exists: it must not be raised to make room.
        self.assertEqual(BASE_MANIFEST_LINE_CAP - BASE_MANIFEST_LINE_COUNT, 4)
        self.assertLessEqual(len(text.splitlines()), BASE_MANIFEST_LINE_CAP)
        manifest = json.loads(text)
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
        self.assertLess(len(manifest["assertions"]),
                        len(dti.combined_assertion_ids(dti.load_shard_manifests(
                            list(EXPECTED_SHARD_ORDER), root=ROOT)[1])))


# -- BL-038 tranche 3o -------------------------------------------------------
# The first METHOD-RANGE scope in the repository: a source-order contiguous
# window of one oversized class, opened by the tranche 3n infrastructure.
TRANCHE_3O_SOURCE_FILE = SECURITY_REQUIREMENTS_SOURCE_FILE
TRANCHE_3O_CLASS = "SecurityRequirementsTest"
TRANCHE_3O_RANGE_START = "test_document_is_approved_version_14_maintenance_update"
TRANCHE_3O_RANGE_END = "test_bl028_is_recorded_verbatim_as_complete"
TRANCHE_3O_METHOD_RANGE = {"start": TRANCHE_3O_RANGE_START, "end": TRANCHE_3O_RANGE_END}
TRANCHE_3O_SELECTION_CAP = 150
TRANCHE_3O_CLASS_METHOD_COUNT = 39
TRANCHE_3O_CLASS_ASSERTION_COUNT = 403
TRANCHE_3O_EXPECTED_METHOD_COUNT = 19
TRANCHE_3O_EXPECTED_ASSERTION_COUNT = 146
TRANCHE_3O_NEXT_METHOD = "test_bl029_is_recorded_verbatim_as_complete"
TRANCHE_3O_NEXT_METHOD_ASSERTION_COUNT = 18
TRANCHE_3O_NEXT_METHOD_RUNNING_TOTAL = 164
TRANCHE_3O_RIVAL_FILE = "test_source_usage_policy.py"
TRANCHE_3O_RIVAL_CLASS = "SourceUsagePolicyTest"
TRANCHE_3O_RIVAL_ASSERTION_COUNT = 140
TRANCHE_3O_RIVAL_METHOD_COUNT = 32
TRANCHE_3O_EXPECTED_CATEGORY_COUNTS = {"A": 0, "B": 70, "C": 54, "D": 22}
TRANCHE_3O_EXPECTED_API_COUNTS = {"assertEqual": 21, "assertIn": 89, "assertLess": 7,
                                  "assertNotIn": 13, "assertRegex": 14, "assertTrue": 2}
TRANCHE_3O_EXPECTED_METHOD_ORDER = (
    (TRANCHE_3O_RANGE_START, 14), ("test_required_sections_are_present", 1),
    ("test_sr_ids_are_stable_unique_and_contiguous_through_047", 9),
    ("test_published_output_correction_requirement_and_gap_are_recorded", 8),
    ("test_operations_requirements_are_met_by_documentation_only", 5),
    ("test_semantic_risk_is_evidenced_without_impossibility_generalization", 8),
    ("test_gap_ids_and_classifications_are_complete_and_limited", 7),
    ("test_current_control_mapping_breakdowns_match_individual_sr_states", 11),
    ("test_met_definition_is_repository_limited", 3),
    ("test_exception_output_inventory_is_comprehensive_and_precise", 3),
    ("test_external_response_size_audit_and_gap_are_recorded", 6),
    ("test_custom_domain_preflight_is_future_only_and_complete", 4),
    ("test_dast_is_not_duplicated", 4), ("test_translation_cache_gap_is_resolved_by_bl030", 6),
    ("test_approved_roadmap_decisions_are_bounded_and_not_implemented", 2),
    ("test_workflows_and_dependabot_reflect_bl026_implementation", 16),
    ("test_bl006_backlog_entry_records_completed_brand_migration", 14),
    ("test_bl006_accepted_head_final_head_and_merge_commit_are_distinct", 9),
    (TRANCHE_3O_RANGE_END, 16),
)
_S3O = f"{TRANCHE_3O_SOURCE_FILE}::{TRANCHE_3O_CLASS}::"


class Tranche3oMethodRangeSelectionTest(unittest.TestCase):
    """BL-038 tranche 3o: the SELECTION is what this class pins. The tranche 3n
    rule is deterministic -- start at the class's earliest unclassified test
    method, add whole methods in source order, stop just before the next one
    would exceed 150 -- so the window, its size, why it stops where it does, and
    why this candidate beat the other one are all re-derivable from live source.
    Every number below is measured here, never copied from the manifest."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / TRANCHE_3O_SOURCE_FILE).read_text(encoding="utf-8")
        cls.class_node = next(n for n in ast.parse(cls.source, filename=TRANCHE_3O_SOURCE_FILE).body
                              if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3O_CLASS)
        cls.order = [m.name for m in dti._class_test_methods_in_source_order(cls.class_node)]
        cls.whole = dti.enumerate_assertions(cls.source, TRANCHE_3O_SOURCE_FILE, [TRANCHE_3O_CLASS])
        cls.per = Counter(r.method for r in cls.whole)
        cls.window = dti.enumerate_assertions(cls.source, TRANCHE_3O_SOURCE_FILE, [TRANCHE_3O_CLASS],
                                              method_ranges={TRANCHE_3O_CLASS: TRANCHE_3O_METHOD_RANGE})

    def test_the_selected_file_class_and_boundaries_are_exactly_these(self):
        self.assertEqual((TRANCHE_3O_SOURCE_FILE, TRANCHE_3O_CLASS),
                         ("test_security_requirements.py", "SecurityRequirementsTest"))
        self.assertEqual(TRANCHE_3O_METHOD_RANGE, {"start": TRANCHE_3O_RANGE_START, "end": TRANCHE_3O_RANGE_END})
        # Both boundaries are real test methods of this class, in this order.
        self.assertIn(TRANCHE_3O_RANGE_START, self.order)
        self.assertIn(TRANCHE_3O_RANGE_END, self.order)
        self.assertLess(self.order.index(TRANCHE_3O_RANGE_START), self.order.index(TRANCHE_3O_RANGE_END))
        self.assertEqual((len(self.order), len(self.whole)),
                         (TRANCHE_3O_CLASS_METHOD_COUNT, TRANCHE_3O_CLASS_ASSERTION_COUNT))

    def test_the_window_starts_at_the_first_unclassified_method_of_the_class(self):
        """A window that did not start at the class's first still-unclassified
        method would be a cherry-pick, and the prefix invariant would reject it.
        Pinned as tranche 3o evidence: the shards that preceded 3o owned NONE of
        this class's methods, and 3o's own shard owns exactly the window. It is
        not a claim that no later shard may ever own more of the class -- the
        tail is legitimate future work."""
        # BL-038 tranche 3x (C063): "the shards before 3o owned none of this class and 3o's
        # own shard owns exactly the window" was reconstructed by reading historical shard
        # FILES and pinning ownership to a physical filename. Ownership is now logical, and
        # the accepted window is the ledger's; the accepted method prefix is not required of
        # the current source order.
        for method in {r.method for r in self.window}:
            with self.subTest(method=method):
                self.assertTrue(dth.owns("3o", TRANCHE_3O_SOURCE_FILE, TRANCHE_3O_CLASS, method))
        dth.assert_accepted(self, ROOT, "3o", entry_count=TRANCHE_3O_EXPECTED_ASSERTION_COUNT)

    def test_the_window_is_nineteen_methods_and_one_hundred_forty_six_assertions(self):
        self.assertEqual(len(TRANCHE_3O_EXPECTED_METHOD_ORDER), TRANCHE_3O_EXPECTED_METHOD_COUNT)
        self.assertEqual(len(self.window), TRANCHE_3O_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(sum(n for _, n in TRANCHE_3O_EXPECTED_METHOD_ORDER), TRANCHE_3O_EXPECTED_ASSERTION_COUNT)
        for method, count in TRANCHE_3O_EXPECTED_METHOD_ORDER:
            with self.subTest(method=method): self.assertEqual(self.per[method], count)
        # Whole methods only: every assertion of every windowed method is in.
        self.assertEqual(Counter(r.method for r in self.window),
                         Counter({m: self.per[m] for m, _ in TRANCHE_3O_EXPECTED_METHOD_ORDER}))
        self.assertLessEqual(TRANCHE_3O_EXPECTED_ASSERTION_COUNT, TRANCHE_3O_SELECTION_CAP)

    def test_the_window_stops_because_the_next_whole_method_would_overflow(self):
        nxt = self.order[TRANCHE_3O_EXPECTED_METHOD_COUNT]
        self.assertEqual(nxt, TRANCHE_3O_NEXT_METHOD)
        self.assertEqual(self.per[nxt], TRANCHE_3O_NEXT_METHOD_ASSERTION_COUNT)
        self.assertEqual(TRANCHE_3O_EXPECTED_ASSERTION_COUNT + self.per[nxt], TRANCHE_3O_NEXT_METHOD_RUNNING_TOTAL)
        self.assertGreater(TRANCHE_3O_NEXT_METHOD_RUNNING_TOTAL, TRANCHE_3O_SELECTION_CAP)
        # No single method is itself unclassifiable under the cap, so the greedy
        # prefix never had to stop on a method it could not take at all.
        self.assertLessEqual(max(self.per.values()), TRANCHE_3O_SELECTION_CAP)
        self.assertEqual(min(self.per.values()), 1)  # and none is empty

    def test_the_competing_candidate_is_smaller_so_the_winner_is_unique(self):
        """BL-038 tranche 3x (C062): which candidate won tranche 3o's selection is SELECTION
        HISTORY. Recomputing the runner-up's greedy prefix from the CURRENT source and
        pinning the result froze both files' live shape, and re-reading the historical
        shards to prove the runner-up was unscoped pinned physical placement. The record is
        kept as constants; the accepted window itself comes from the ledger."""
        self.assertGreater(TRANCHE_3O_EXPECTED_ASSERTION_COUNT, TRANCHE_3O_RIVAL_ASSERTION_COUNT)
        self.assertNotEqual(TRANCHE_3O_EXPECTED_ASSERTION_COUNT, TRANCHE_3O_RIVAL_ASSERTION_COUNT)  # no tie
        self.assertLessEqual(TRANCHE_3O_RIVAL_ASSERTION_COUNT, TRANCHE_3O_SELECTION_CAP)
        dth.assert_accepted(self, ROOT, "3o", entry_count=TRANCHE_3O_EXPECTED_ASSERTION_COUNT)


class Tranche3oShard003Test(unittest.TestCase):
    """The shard itself: scope shape, entry contract, and the two invariants the
    method-range form exists to enforce -- a method inserted INSIDE the window
    becomes `unclassified`, and the combined index covers an unbroken prefix."""

    @classmethod
    def setUpClass(cls):
        cls.text = SHARD_003_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.text, object_pairs_hook=OrderedDict)
        cls.entries = cls.shard["assertions"]
        cls.source = (ROOT / TRANCHE_3O_SOURCE_FILE).read_text(encoding="utf-8")

    def test_the_scope_is_one_method_range_over_one_class(self):
        # BL-038 tranche 3x (C068): the accepted scope descriptor and accepted line count are
        # past facts -- the descriptor from the pinned accepted map, the line count from the
        # ledger. The current file keeps only its schema shape and the line cap.
        accepted_scope, _window = dth.accepted_window(ROOT, "3o")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3o"])
        dth.assert_accepted(self, ROOT, "3o", line_count=SHARD_003_CURRENT_LINE_COUNT)
        self.assertEqual(self.shard["schema_version"], 1)
        scope = self.shard["scope"][0]
        self.assertEqual(tuple(scope), ("file", "classes", "method_range"))
        self.assertEqual(tuple(scope["method_range"]), ("start", "end"))
        self.assertLessEqual(len(self.text.splitlines()), dti.SHARD_LINE_CAP)

    def test_every_entry_matches_live_source_in_inventory_id_order(self):
        """BL-038 tranche 3x (C065): the accepted id list and its count are past facts, and
        source-to-manifest agreement on file/class/method/ordinal/api/fingerprint is the
        existing validator's contract, not re-implemented here. What stays is the entry key
        order and category/action consistency, plus accepted-contract continuity."""
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry), EXPECTED_ENTRY_KEY_ORDER)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3o")

    def test_the_category_and_api_breakdowns_are_the_recorded_ones(self):
        # BL-038 tranche 3x (C066): the accepted category and API breakdowns are past facts,
        # asserted from the immutable ledger rather than recounted on the current shard.
        dth.assert_accepted(self, ROOT, "3o", entry_count=TRANCHE_3O_EXPECTED_ASSERTION_COUNT,
                            category_counts=TRANCHE_3O_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(TRANCHE_3O_EXPECTED_API_COUNTS.values()), TRANCHE_3O_EXPECTED_ASSERTION_COUNT)

    def test_category_a_is_empty_on_measured_evidence(self):
        """Not an unexamined zero: no two methods in the window share an AST
        node-type skeleton, so there is no whole-method parameterisation to
        consolidate, and the one internal fingerprint duplicate sits in two
        methods of different arity and different API mix."""
        # BL-038 tranche 3x (C064): the accepted A=0 result is a ledger fact. The accepted
        # method prefix, the exact twin method names, their arities and the accepted category
        # set were accepted-time measurement and are gone. What stays is the PROPERTY that
        # justified A=0, measured over the methods this shard currently owns: no two of them
        # are a whole-method parameterisation of each other.
        record = dth.assert_accepted(self, ROOT, "3o",
                                     category_counts=TRANCHE_3O_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(record["historical"]["category_counts"]["A"], 0)
        owned = {e["method"] for e in self.entries}
        nodes = {m.name: m for m in dti._class_test_methods_in_source_order(
            next(n for n in ast.parse(self.source, filename=TRANCHE_3O_SOURCE_FILE).body
                 if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3O_CLASS)) if m.name in owned}
        groups = {}
        for name, node in nodes.items():
            groups.setdefault(tuple(type(x).__name__ for x in ast.walk(node)), []).append(name)
        for shared in [v for v in groups.values() if len(v) > 1]:
            for first, second in itertools.combinations(sorted(shared), 2):
                with self.subTest(pair=(first, second)):
                    self.assertNotEqual(ast.unparse(nodes[first]), ast.unparse(nodes[second]))

    def test_a_method_inserted_inside_the_window_becomes_unclassified(self):
        """The reason the scope names BOUNDARIES rather than 19 method names: a
        method added between them is inventoried, and with no manifest entry it
        fails `unclassified` instead of being silently skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in list(EXPECTED_SHARD_ORDER) + [dti.INDEX_FILENAME]:
                shutil.copy(ROOT / name, root / name)
            for name in {f for _, m in dti.load_shard_manifests(list(EXPECTED_SHARD_ORDER), root=ROOT)[1]
                         for f in {e["file"] for e in m["scope"]}}:
                shutil.copy(ROOT / name, root / name)
            for name in ("BACKLOG.md", "SECURITY_REQUIREMENTS.md", "STATUS.md", "DECISIONS.md", "AGENTS.md"):
                shutil.copy(ROOT / name, root / name)
            shutil.copytree(ROOT / ".github", root / ".github")
            self.assertEqual(dti.validate_indexed_manifests(root=root)[0], [])
            marker = "    def test_required_sections_are_present(self):\n"
            self.assertIn(marker, self.source)
            inserted = ("    def test_inserted_by_a_later_edit(self):\n"
                        "        self.assertIn('x', 'xyz')\n")
            (root / TRANCHE_3O_SOURCE_FILE).write_text(self.source.replace(marker, inserted + marker, 1),
                                                       encoding="utf-8")
            failures = dti.validate_indexed_manifests(root=root)[0]
            self.assertEqual({f.mismatch_type for f in failures}, {"unclassified"})
            self.assertEqual({f.method for f in failures}, {"test_inserted_by_a_later_edit"})

    def test_the_combined_index_covers_an_unbroken_prefix_of_the_class(self):
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertNotIn("method-range-prefix-gap", {f.mismatch_type for f in failures})
        self.assertEqual(summary["manifest_assertions"], summary["inventoried_assertions"])
        # BL-038 tranche 3x (C067): the accepted prefix length, the accepted tail counts and
        # the combined total are past facts. The surviving CURRENT invariant is the one the
        # method-range form exists for: what this shard owns is an unbroken PREFIX of the
        # class in source order, with the tail left as deliberate future work.
        order = [m.name for m in dti._class_test_methods_in_source_order(
            next(n for n in ast.parse(self.source, filename=TRANCHE_3O_SOURCE_FILE).body
                 if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3O_CLASS))]
        owned = {e["method"] for e in self.entries}
        self.assertEqual([m for m in order if m in owned], order[:len(owned)])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3o")

    def test_the_three_accepted_shards_are_byte_identical_and_unshared(self):
        """BL-038 tranche 3x (C069): requiring the prior shards to stay byte-identical is
        exactly what blocks Category C conversion. Their accepted bytes and entry counts are
        asserted from the immutable ledger instead, and the generic duplicate-scope rule is
        the validator's."""
        dth.assert_accepted(self, ROOT, "3f", sha256=BASE_MANIFEST_SHA256, entry_count=585)
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        dth.assert_accepted(self, ROOT, "3m", sha256=SHARD_002_CURRENT_SHA256,
                            entry_count=SHARD_002_CURRENT_ENTRY_COUNT)


# -- BL-038 tranche 3p -------------------------------------------------------
# The second method-range scope, and the first on a class no shard had touched.
TRANCHE_3P_SOURCE_FILE = "test_source_usage_policy.py"
TRANCHE_3P_CLASS = "SourceUsagePolicyTest"
TRANCHE_3P_RANGE_START = "test_gemini_gate_references_point_to_chapter_5"
TRANCHE_3P_RANGE_END = "test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified"
TRANCHE_3P_METHOD_RANGE = {"start": TRANCHE_3P_RANGE_START, "end": TRANCHE_3P_RANGE_END}
TRANCHE_3P_SELECTION_CAP = 150
TRANCHE_3P_CLASS_METHOD_COUNT = 36
TRANCHE_3P_CLASS_ASSERTION_COUNT = 177
TRANCHE_3P_EXPECTED_METHOD_COUNT = 32
TRANCHE_3P_EXPECTED_ASSERTION_COUNT = 140
TRANCHE_3P_NEXT_METHOD = "test_mandiant_distinguishes_rss_evidence_from_terms_evidence"
TRANCHE_3P_NEXT_METHOD_ASSERTION_COUNT = 11
TRANCHE_3P_NEXT_METHOD_RUNNING_TOTAL = 151
TRANCHE_3P_TAIL_METHOD_COUNT = 4
TRANCHE_3P_TAIL_ASSERTION_COUNT = 37
# The runner-up this tranche beat: SecurityRequirementsTest's next window.
TRANCHE_3P_RIVAL_FILE = SECURITY_REQUIREMENTS_SOURCE_FILE
TRANCHE_3P_RIVAL_CLASS = "SecurityRequirementsTest"
TRANCHE_3P_RIVAL_START = "test_bl029_is_recorded_verbatim_as_complete"
TRANCHE_3P_RIVAL_METHOD_COUNT = 11
TRANCHE_3P_RIVAL_ASSERTION_COUNT = 124
TRANCHE_3P_EXPECTED_CATEGORY_COUNTS = {"A": 2, "B": 80, "C": 50, "D": 8}
TRANCHE_3P_EXPECTED_API_COUNTS = {"assertEqual": 27, "assertIn": 89, "assertNotIn": 18, "assertNotRegex": 1, "assertTrue": 5}
TRANCHE_3P_EXPECTED_A_METHODS = ("test_metadata_only_disallows_ai_processing", "test_disabled_legal_review_disallows_network_fetch")
_S3P = f"{TRANCHE_3P_SOURCE_FILE}::{TRANCHE_3P_CLASS}::"


class Tranche3pMethodRangeSelectionTest(unittest.TestCase):
    """BL-038 tranche 3p SELECTION, re-derivable from live source: the window,
    why it stops where it does, and why it beat the other candidate. Unlike
    tranche 3o's class, this one had no prior classification at all, so its
    window starts at the class's very first test method."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / TRANCHE_3P_SOURCE_FILE).read_text(encoding="utf-8")
        cls.node = next(n for n in ast.parse(cls.source, filename=TRANCHE_3P_SOURCE_FILE).body
                        if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3P_CLASS)
        cls.order = [m.name for m in dti._class_test_methods_in_source_order(cls.node)]
        cls.per = Counter(r.method for r in dti.enumerate_assertions(cls.source, TRANCHE_3P_SOURCE_FILE, [TRANCHE_3P_CLASS]))
        cls.window = dti.enumerate_assertions(cls.source, TRANCHE_3P_SOURCE_FILE, [TRANCHE_3P_CLASS],
                                              method_ranges={TRANCHE_3P_CLASS: TRANCHE_3P_METHOD_RANGE})

    def test_the_selected_file_class_and_boundaries_are_exactly_these(self):
        self.assertEqual((TRANCHE_3P_SOURCE_FILE, TRANCHE_3P_CLASS), ("test_source_usage_policy.py", "SourceUsagePolicyTest"))
        self.assertEqual(TRANCHE_3P_METHOD_RANGE, {"start": TRANCHE_3P_RANGE_START, "end": TRANCHE_3P_RANGE_END})
        self.assertIn(TRANCHE_3P_RANGE_START, self.order)
        self.assertIn(TRANCHE_3P_RANGE_END, self.order)
        self.assertLess(self.order.index(TRANCHE_3P_RANGE_START), self.order.index(TRANCHE_3P_RANGE_END))
        self.assertEqual((len(self.order), sum(self.per.values())), (TRANCHE_3P_CLASS_METHOD_COUNT, TRANCHE_3P_CLASS_ASSERTION_COUNT))

    def test_the_window_starts_at_the_first_unclassified_method_of_the_class(self):
        """Pinned as tranche 3p evidence: every shard that preceded `_004` owned
        none of this class, and `_004` owns exactly the window, which begins at
        source index 0. It is not a ceiling on what a later shard may own."""
        # BL-038 tranche 3x (C071): ownership is logical, not reconstructed by reading the
        # historical shard files and pinning it to a physical filename; the accepted window
        # is the ledger's.
        for method in {r.method for r in self.window}:
            with self.subTest(method=method):
                self.assertTrue(dth.owns("3p", TRANCHE_3P_SOURCE_FILE, TRANCHE_3P_CLASS, method))
        dth.assert_accepted(self, ROOT, "3p", entry_count=TRANCHE_3P_EXPECTED_ASSERTION_COUNT)

    def test_the_window_is_thirtytwo_methods_and_one_hundred_forty_assertions(self):
        self.assertEqual(len(self.window), TRANCHE_3P_EXPECTED_ASSERTION_COUNT)
        self.assertEqual(len({r.method for r in self.window}), TRANCHE_3P_EXPECTED_METHOD_COUNT)
        self.assertEqual(self.order[TRANCHE_3P_EXPECTED_METHOD_COUNT - 1], TRANCHE_3P_RANGE_END)
        # Whole methods only: every assertion of every windowed method is in.
        self.assertEqual(Counter(r.method for r in self.window), Counter({m: self.per[m] for m in self.order[:TRANCHE_3P_EXPECTED_METHOD_COUNT]}))
        self.assertLessEqual(TRANCHE_3P_EXPECTED_ASSERTION_COUNT, TRANCHE_3P_SELECTION_CAP)

    def test_the_window_stops_because_the_next_whole_method_would_overflow(self):
        nxt = self.order[TRANCHE_3P_EXPECTED_METHOD_COUNT]
        self.assertEqual((nxt, self.per[nxt]), (TRANCHE_3P_NEXT_METHOD, TRANCHE_3P_NEXT_METHOD_ASSERTION_COUNT))
        self.assertEqual(TRANCHE_3P_EXPECTED_ASSERTION_COUNT + self.per[nxt], TRANCHE_3P_NEXT_METHOD_RUNNING_TOTAL)
        self.assertGreater(TRANCHE_3P_NEXT_METHOD_RUNNING_TOTAL, TRANCHE_3P_SELECTION_CAP)
        self.assertLessEqual(max(self.per.values()), TRANCHE_3P_SELECTION_CAP)
        self.assertEqual(min(self.per.values()), 1)  # and none is empty

    def test_the_uncovered_tail_is_four_methods_and_thirtyseven_assertions(self):
        """Legitimate future work, deliberately left: the tail must stay
        classifiable by a later disjoint range, so this records its size rather
        than forbidding anything."""
        tail = self.order[TRANCHE_3P_EXPECTED_METHOD_COUNT:]
        self.assertEqual(len(tail), TRANCHE_3P_TAIL_METHOD_COUNT)
        self.assertEqual(sum(self.per[m] for m in tail), TRANCHE_3P_TAIL_ASSERTION_COUNT)
        self.assertEqual(tail[0], TRANCHE_3P_NEXT_METHOD)
        self.assertEqual(TRANCHE_3P_EXPECTED_ASSERTION_COUNT + TRANCHE_3P_TAIL_ASSERTION_COUNT, TRANCHE_3P_CLASS_ASSERTION_COUNT)

    def test_the_competing_candidate_is_smaller_so_the_winner_is_unique(self):
        """The rival is the NEXT window of the class tranche 3o started: its own
        greedy prefix from its first still-unclassified method."""
        # BL-038 tranche 3x (C070): as with C062, the accepted selection outcome is history.
        # Recomputing the rival's greedy prefix from the CURRENT source -- and deriving its
        # start by re-reading the historical shard files -- froze both live shapes.
        self.assertGreater(TRANCHE_3P_EXPECTED_ASSERTION_COUNT, TRANCHE_3P_RIVAL_ASSERTION_COUNT)
        self.assertNotEqual(TRANCHE_3P_EXPECTED_ASSERTION_COUNT, TRANCHE_3P_RIVAL_ASSERTION_COUNT)  # no tie
        self.assertLessEqual(TRANCHE_3P_RIVAL_ASSERTION_COUNT, TRANCHE_3P_SELECTION_CAP)
        dth.assert_accepted(self, ROOT, "3p", entry_count=TRANCHE_3P_EXPECTED_ASSERTION_COUNT)


class Tranche3pShard004Test(unittest.TestCase):
    """The shard: scope shape, entry-to-source agreement, the measured basis for
    the two Category A entries, and the prefix invariant."""

    @classmethod
    def setUpClass(cls):
        cls.text = SHARD_004_PATH.read_text(encoding="utf-8")
        cls.shard = json.loads(cls.text, object_pairs_hook=OrderedDict)
        cls.entries = cls.shard["assertions"]
        cls.source = (ROOT / TRANCHE_3P_SOURCE_FILE).read_text(encoding="utf-8")

    def test_the_scope_is_one_method_range_over_one_class(self):
        # BL-038 tranche 3x (C076): accepted scope descriptor from the pinned map, accepted
        # line count from the ledger; the current file keeps its schema shape and the cap.
        accepted_scope, _window = dth.accepted_window(ROOT, "3p")
        self.assertEqual(accepted_scope, dth.ACCEPTED_SCOPES["3p"])
        dth.assert_accepted(self, ROOT, "3p", line_count=SHARD_004_CURRENT_LINE_COUNT)
        self.assertEqual(self.shard["schema_version"], 1)
        scope = self.shard["scope"][0]
        self.assertEqual(tuple(scope), ("file", "classes", "method_range"))
        self.assertEqual(tuple(scope["method_range"]), ("start", "end"))
        self.assertLessEqual(len(self.text.splitlines()), dti.SHARD_LINE_CAP)

    def test_every_entry_matches_live_source_in_inventory_id_order(self):
        """BL-038 tranche 3x (C072): the accepted id list and count are past facts, and
        source-to-manifest agreement is the validator's contract. The entry key order and
        category/action consistency stay, plus accepted-contract continuity."""
        for entry in self.entries:
            with self.subTest(id=entry["id"]):
                self.assertEqual(tuple(entry), EXPECTED_ENTRY_KEY_ORDER)
                self.assertEqual(entry["action"], dti.CATEGORY_TO_ACTION[entry["category"]])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3p")

    def test_the_category_and_api_breakdowns_are_the_recorded_ones(self):
        # BL-038 tranche 3x (C073): accepted category and API breakdowns from the ledger.
        dth.assert_accepted(self, ROOT, "3p", entry_count=TRANCHE_3P_EXPECTED_ASSERTION_COUNT,
                            category_counts=TRANCHE_3P_EXPECTED_CATEGORY_COUNTS)
        self.assertEqual(sum(TRANCHE_3P_EXPECTED_API_COUNTS.values()), TRANCHE_3P_EXPECTED_ASSERTION_COUNT)

    def test_category_a_rests_on_a_measured_whole_method_parameterisation(self):
        """A is two entries, and the evidence is the METHODS, not the
        fingerprints (which differ). The two methods have identical AST
        skeletons and differ in exactly one (mode, column) parameter pair."""
        a_methods = sorted({e["method"] for e in self.entries if e["category"] == "A"})
        self.assertEqual(a_methods, sorted(TRANCHE_3P_EXPECTED_A_METHODS))
        self.assertEqual(sum(1 for e in self.entries if e["category"] == "A"), 2)
        nodes = {m.name: m for m in dti._class_test_methods_in_source_order(
            next(n for n in ast.parse(self.source, filename=TRANCHE_3P_SOURCE_FILE).body
                 if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3P_CLASS))}
        skeletons = [tuple(type(x).__name__ for x in ast.walk(nodes[m])) for m in TRANCHE_3P_EXPECTED_A_METHODS]
        self.assertEqual(skeletons[0], skeletons[1])
        fingerprints = {e["fingerprint"] for e in self.entries if e["category"] == "A"}
        self.assertEqual(len(fingerprints), 2)  # NOT a fingerprint duplicate
        # Normalising the one parameter pair makes the two bodies identical.
        lines = self.source.split("\n")
        bodies = ["\n".join(lines[nodes[m].lineno:nodes[m].end_lineno]) for m in TRANCHE_3P_EXPECTED_A_METHODS]
        normalised = [bodies[0].replace("metadata_only", "M").replace("ai_processing", "C"),
                      bodies[1].replace("disabled_legal_review", "M").replace("network_fetch", "C")]
        self.assertEqual(normalised[0], normalised[1])

    def test_the_combined_index_covers_an_unbroken_prefix_and_leaves_the_tail(self):
        failures, summary = dti.validate_indexed_manifests(root=ROOT)
        self.assertEqual([f.format() for f in failures], [])
        self.assertNotIn("method-range-prefix-gap", {f.mismatch_type for f in failures})
        self.assertEqual(summary["manifest_assertions"], summary["inventoried_assertions"])
        # BL-038 tranche 3x (C074): accepted prefix length, tail count and combined total are
        # past facts; the surviving CURRENT invariant is unbroken-prefix ownership.
        order = [m.name for m in dti._class_test_methods_in_source_order(next(n for n in ast.parse(self.source, filename=TRANCHE_3P_SOURCE_FILE).body
                 if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3P_CLASS))]
        owned = {e["method"] for e in self.entries}
        self.assertEqual([m for m in order if m in owned], order[:len(owned)])
        dth.assert_accepted_contracts_accounted_for(self, ROOT, "3p")

    def test_the_four_accepted_shards_are_byte_identical_and_unshared(self):
        """BL-038 tranche 3x (C075): the prior shards' accepted bytes and entry counts come
        from the immutable ledger; requiring the CURRENT files to stay byte-identical is what
        blocks Category C conversion. The cap arithmetic that chose `_004` stays as a
        constant-only record."""
        dth.assert_accepted(self, ROOT, "3f", sha256=BASE_MANIFEST_SHA256, entry_count=585)
        dth.assert_accepted(self, ROOT, "3i", sha256=SHARD_001_CURRENT_SHA256,
                            entry_count=SHARD_001_CURRENT_ENTRY_COUNT)
        dth.assert_accepted(self, ROOT, "3m", sha256=SHARD_002_CURRENT_SHA256,
                            entry_count=SHARD_002_CURRENT_ENTRY_COUNT)
        dth.assert_accepted(self, ROOT, "3o", entry_count=SHARD_003_CURRENT_ENTRY_COUNT)
        self.assertGreater(BASE_MANIFEST_LINE_COUNT + SHARD_004_CURRENT_ENTRY_COUNT, dti.SHARD_LINE_CAP)


# The load-bearing bindings an assertion fingerprint cannot see: for each
# selected method, the string literals OUTSIDE its assertion and subTest calls --
# section boundaries, table column names, source_id and mode filters, required
# tuples, the audit-date exception set and the blacklist. Compared as a MULTISET,
# because ast.walk is breadth-first: introducing a harmless alias reshuffles the
# order without changing a single manifest claim. Where order does carry meaning
# -- the per-source trigger pairing -- a dedicated guard pins it below.
# This deliberately does NOT digest the whole outer AST: that also failed on
# harmless equivalences such as `{}` versus `dict()` or an added alias, which
# change no manifest claim (PR #98 round 3). Non-string outer semantics that DO
# carry manifest meaning are pinned individually below.
TRANCHE_3P_USED_OUTER_LITERALS = {
    "test_required_chapters_are_present": ( '## 1. Purpose', '## 2. Legal and policy framework', '## 3. Content usage modes',
         '## 4. Source-by-source audit matrix', '## 5. Gemini data-use gate', '## 6. Attribution requirements',
         '## 7. Output-similarity and quotation controls', '## 8. Recheck triggers', '## 9. Unknowns and owner verification',
         '## 10. Relationship to BL-032 and BL-009'), "test_17_source_ids_match_source_definitions_exactly": ( 'source_id',),
    "test_checked_at_is_2026_07_29_except_google_terms_sources": ( 'google_tag', 'mandiant', '2026-07-30', '2026-07-29', 'source_id'),
    "test_mode_counts_are_5_4_2_2_4_by_proposed_mode_column": ( 'source_id', 'proposed_mode'),
    "test_proposed_mode_matches_the_table_the_row_appears_in": ( 'structured_open', '### structured_open (5件)', '### feed_summary (4件)',
         'feed_summary', '### feed_summary (4件)', '### limited_feed_analysis (2件)', 'limited_feed_analysis', '### limited_feed_analysis (2件)',
         '### metadata_only (2件)', 'metadata_only', '### metadata_only (2件)', '### disabled_legal_review (4件)', '### disabled_legal_review (4件)'),
    "test_metadata_only_disallows_ai_processing": ( 'metadata_only', 'proposed_mode'),
    "test_disabled_legal_review_disallows_network_fetch": ( 'disabled_legal_review', 'proposed_mode'),
    "test_feed_summary_is_gated_by_gemini_paid_service_confirmation": ( '### limited_feed_analysis (2件)', '## 6. Attribution requirements',
         '### feed_summary (4件)', '## 5. Gemini data-use gate'),
    "test_gemini_data_use_status_is_paid_verified": ( '## 6. Attribution requirements', '## 5. Gemini data-use gate'),
    "test_gemini_owner_verification_is_recorded_without_secrets": ( '## 6. Attribution requirements', '## 5. Gemini data-use gate'),
    "test_gemini_gate_no_longer_lists_unknown_as_current_unresolved_issue": ( '## 10. Relationship to BL-032 and BL-009',
         '## 9. Unknowns and owner verification'),
    "test_feed_summary_production_enforcement_still_deferred_to_bl032": ( '## 6. Attribution requirements', '## 5. Gemini data-use gate'),
    "test_google_terms_2026_07_30_recheck_is_recorded_as_completed": ( '## 9. Unknowns and owner verification', '## 8. Recheck triggers'),
    "test_mandiant_and_google_tag_recheck_triggers_are_specific": ( 'mandiant', 'google_tag', 'Google Cloud Threat Intelligence固有の利用条件の変更',
         'Google Security Blog/Blogger固有の利用条件の変更', 'recheck_trigger'),
    "test_google_terms_recheck_moved_to_confirmed_in_unknowns_section": ( '## 10. Relationship to BL-032 and BL-009',
         '## 9. Unknowns and owner verification'),
    "test_attribution_requirements_are_recorded_for_each_group": ( '`fsa`', '`nist`', '`nist_nvd`', '`ncsc`', '`cisa_kev`', 'jpcert_cc',
         'limited_feed_analysis', 'metadata_only', 'disabled_legal_review', '## 7. Output-similarity and quotation controls',
         '## 6. Attribution requirements'),
    "test_limited_feed_analysis_mode_definition_is_present": ( '## 4. Source-by-source audit matrix', '## 3. Content usage modes'),
    "test_limited_feed_analysis_rows_have_expected_allow_flags": ( 'the_hacker_news', 'krebs_on_security'),
    "test_risk_acceptance_rationale_is_recorded_and_not_asserted_as_permission": ( '## 4. Source-by-source audit matrix', '## 3. Content usage modes'),
    "test_metadata_only_allows_metadata_fetch_and_does_not_prohibit_human_browsing": ( '## 4. Source-by-source audit matrix',
         '## 3. Content usage modes'), "test_cisco_talos_and_krebs_uncertainty_is_not_asserted_as_definitive": ( 'cisco_talos', 'krebs_on_security',
         '## 10. Relationship to BL-032 and BL-009', '## 9. Unknowns and owner verification'),
    "test_official_evidence_url_contains_only_urls_or_a_bare_dash": ( 'official_evidence_url',),
    "test_official_evidence_url_has_no_descriptive_text_mixed_in": ( '証跡', 'supporting:', 'URL未特定', '見つからなかった', 'terms文書ではなく'),
    "test_multi_url_rows_have_matching_evidence_type_count_when_types_differ": ( 'official_evidence_url', 'evidence_type'),
    "test_krebs_about_page_is_recorded_as_supporting_source_page_not_a_terms_url": ( 'krebs_on_security', 'official_evidence_url'),
    "test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified": ( 'cisa',), }
TRANCHE_3P_USED_OUTER_LITERAL_COUNT = 90
TRANCHE_3P_HELPER_OUTER_LITERALS = { "parse_rows": ( '|---', 'source_id', '| ', '|', '|'), "_split_cell": ( '；',), }
# Which source_id row each source-specific assertion ultimately reads. The outer
# literal multiset cannot see the RHS of two row bindings swapped -- the literals
# and all 140 fingerprints survive it -- yet every one of those manifest entries
# names its source explicitly (PR #98 round 4). Resolved through the bindings, so
# renaming a local row variable is free.
_KREBS, _TALOS, _CISA = "krebs_on_security", "cisco_talos", "cisa"
TRANCHE_3P_SOURCE_ROW_READS = { "test_cisco_talos_and_krebs_uncertainty_is_not_asserted_as_definitive":
        {1: _TALOS, 2: _KREBS, 3: _KREBS, 4: _KREBS}, "test_krebs_about_page_is_recorded_as_supporting_source_page_not_a_terms_url":
        {n: _KREBS for n in range(1, 6)},
    "test_cisa_has_no_url_in_official_evidence_url_and_is_terms_not_identified": {n: _CISA for n in range(1, 4)}, }
def _row_source_of(method):
    """Map each local variable to the source_id whose matrix row it ultimately reads.
    `self.rows_by_id` resolves to a marker any harmless local alias inherits, row
    bindings resolve through that marker rather than through a literal
    `self.rows_by_id[...]` shape, and a variable derived from exactly one resolved row
    inherits it -- to fixpoint, so no local name (a row's or the alias's) is a contract."""
    env, changed, REGISTRY = {}, True, object()
    def registry(node):  # `self.rows_by_id` itself, or any local alias of it
        return (isinstance(node, ast.Attribute) and node.attr == "rows_by_id") or (isinstance(node, ast.Name) and env.get(node.id) is REGISTRY)
    while changed:
        changed = False
        for a in ast.walk(method):
            if not (isinstance(a, ast.Assign) and len(a.targets) == 1 and isinstance(a.targets[0], ast.Name) and a.targets[0].id not in env):
                continue  # first binding wins, so the fixpoint is monotone and terminates
            value, resolved = a.value, None
            if registry(value): resolved = REGISTRY
            elif isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Constant) and registry(value.value):
                resolved = value.slice.value
            else:
                seen = {env[n.id] for n in ast.walk(value) if isinstance(n, ast.Name) and n.id in env} - {REGISTRY}
                resolved = seen.pop() if len(seen) == 1 else None
            if resolved is not None: env[a.targets[0].id], changed = resolved, True
    return {name: sid for name, sid in env.items() if sid is not REGISTRY}
TRANCHE_3P_REQUIRED_CHAPTERS = ("## 1. Purpose", "## 2. Legal and policy framework", "## 3. Content usage modes",
    "## 4. Source-by-source audit matrix", "## 5. Gemini data-use gate",
    "## 6. Attribution requirements", "## 7. Output-similarity and quotation controls",
    "## 8. Recheck triggers", "## 9. Unknowns and owner verification", "## 10. Relationship to BL-032 and BL-009")


class Tranche3pUsedBindingGuardTest(unittest.TestCase):
    """PR #98 round 1, Blocker 2. An ordinary assertion fingerprint covers the
    assertion CALL and nothing else, so a manifest entry whose meaning rests on
    an assignment, tuple, slice boundary or helper outside that call can be
    falsified without any fingerprint moving. Following the tranche 3m
    precedent, this pins ONLY the bindings the tranche 3p manifest actually
    uses -- audited entry by entry, with cosmetic subTest labels and unused
    fields deliberately left free."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / TRANCHE_3P_SOURCE_FILE).read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=TRANCHE_3P_SOURCE_FILE)
        cls.class_node = next(n for n in cls.tree.body if isinstance(n, ast.ClassDef) and n.name == TRANCHE_3P_CLASS)
        cls.methods = {m.name: m for m in dti._class_test_methods_in_source_order(cls.class_node)}

    @staticmethod
    def _expr(text):
        """`text` rendered by THIS interpreter's unparse, so both sides of an
        expression comparison are normalised the same way and no expected value
        written here can depend on a CPython release's rendering choices."""
        return ast.unparse(ast.parse(text, mode="eval").body)

    @staticmethod
    def _outer_literals(method, skip_docstring=False):
        """String literals the fingerprint cannot see: everything outside an
        assertion call, minus subTest labels (cosmetic)."""
        hidden = set()
        if (skip_docstring and method.body and isinstance(method.body[0], ast.Expr) and isinstance(method.body[0].value, ast.Constant)):
            hidden.add(id(method.body[0].value))
        for node in ast.walk(method):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"
                    and (node.func.attr.startswith("assert") or node.func.attr == "subTest")):
                hidden |= {id(x) for x in ast.walk(node)}
        return tuple(n.value for n in ast.walk(method) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in hidden)

    def test_the_documents_the_manifest_targets_are_the_ones_read(self):
        """Every entry targets SOURCE_USAGE_POLICY.md, and one targets
        source_definitions.json. Retargeting either path would falsify all 140
        summaries without moving a single fingerprint."""
        paths = {t.targets[0].id: ast.unparse(t.value) for t in self.tree.body if isinstance(t, ast.Assign) and isinstance(t.targets[0], ast.Name)
                 and t.targets[0].id in ("POLICY_PATH", "SOURCE_DEFINITIONS_PATH")}
        self.assertEqual(paths, {"POLICY_PATH": "ROOT / 'SOURCE_USAGE_POLICY.md'", "SOURCE_DEFINITIONS_PATH": "ROOT / 'source_definitions.json'"})

    def test_setupclass_binds_the_matrix_rows_and_ids_the_manifest_describes(self):
        """`matrix`, `rows`, `rows_by_id` and `source_ids` decide what "the audit
        matrix", "the row", and "the registry's id set" mean in 140 summaries."""
        setup = next(m for m in self.class_node.body if isinstance(m, ast.FunctionDef) and m.name == "setUpClass")
        assigns = {ast.unparse(a.targets[0]): ast.unparse(a.value) for a in setup.body if isinstance(a, ast.Assign)}
        self.assertEqual(assigns["cls.policy"], "POLICY_PATH.read_text(encoding='utf-8')")
        self.assertEqual(assigns["cls.rows"], "parse_rows(cls.matrix)")
        self.assertEqual(assigns["cls.rows_by_id"], "{row['source_id']: row for row in cls.rows}")
        # The matrix binding is pinned as an EXPRESSION, not as "these markers
        # appear somewhere": chapter 4 opened, [1] taken, chapter 5 closed, [0]
        # taken, each with maxsplit 1.
        self.assertEqual(assigns["cls.matrix"], self._expr(
            "cls.policy.split('## 4. Source-by-source audit matrix', 1)[1].split('## 5. Gemini data-use gate', 1)[0]"))
        # The id set comes from the registry's own `sources[].id`.
        for fragment in ("SOURCE_DEFINITIONS_PATH.read_text", "'sources'", "s['id']"):
            with self.subTest(fragment=fragment): self.assertIn(fragment, assigns["cls.source_ids"])

    def test_parse_rows_still_resolves_columns_by_header(self):
        """Every "cell"/"column" claim in the manifest assumes header-keyed
        parsing across the four per-mode tables. A positional parser would keep
        the same fingerprints and make those summaries wrong."""
        parse_rows = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "parse_rows")
        self.assertEqual(self._outer_literals(parse_rows, skip_docstring=True), TRANCHE_3P_HELPER_OUTER_LITERALS["parse_rows"])
        # ... and the header/cell zip itself, which no literal can express.
        zips = [n for n in ast.walk(parse_rows) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "zip"]
        self.assertEqual([len(z.args) for z in zips], [2])

    def test_split_cell_still_splits_on_the_full_width_separator(self):
        """`official_evidence_url` and `evidence_type` are `；`-separated lists;
        the URL-shape, count-matching and Krebs entries all depend on it."""
        split_cell = next(m for m in self.class_node.body if isinstance(m, ast.FunctionDef) and m.name == "_split_cell")
        self.assertEqual(self._outer_literals(split_cell), TRANCHE_3P_HELPER_OUTER_LITERALS["_split_cell"])
        # The delimiter is a literal, but stripping and the empty-token filter
        # are structure: dropping `if part.strip()` keeps every literal and every
        # fingerprint, and would let a blank token through (PR #98 round 2).
        comps = [n for n in ast.walk(split_cell) if isinstance(n, ast.comprehension)]
        self.assertEqual(len(comps), 1)
        strips = [n for n in ast.walk(split_cell) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "strip"]
        self.assertEqual(len(strips), 2)  # the element and the filter
        self.assertEqual([type(n).__name__ for n in comps[0].ifs], ["Call"])

    def test_the_audit_date_exception_set_and_dates_are_pinned(self):
        """Blocker 2-1: the assertion is only `assertEqual(row['checked_at'],
        expected)`. The two exception sources and both dates live outside it,
        yet the manifest records them as exact audit evidence (D)."""
        body = ast.unparse(self.methods["test_checked_at_is_2026_07_29_except_google_terms_sources"])
        self.assertIn("updated = {'google_tag', 'mandiant'}", body)
        self.assertIn("expected = '2026-07-30' if row['source_id'] in updated else '2026-07-29'", body)
        self.assertIn("assertEqual(row['checked_at'], expected)", body)

    def test_the_required_chapter_tuple_is_pinned(self):
        """Blocker 2-2: the assertion is only `assertIn(heading, self.policy)`;
        all ten headings live in the loop tuple."""
        literals = self._outer_literals(self.methods["test_required_chapters_are_present"])
        self.assertEqual(sorted(literals), sorted(TRANCHE_3P_REQUIRED_CHAPTERS))
        self.assertEqual(len(literals), 10)

    def test_the_descriptive_text_blacklist_is_pinned(self):
        """Blocker 2-3: the assertion is only `assertNotIn(forbidden, ...)`; the
        five blacklisted fragments the C rationale names live in the tuple."""
        literals = self._outer_literals(self.methods["test_official_evidence_url_has_no_descriptive_text_mixed_in"])
        self.assertEqual(sorted(literals), sorted(("証跡", "supporting:", "URL未特定", "見つからなかった", "terms文書ではなく")))

    def test_every_selected_method_keeps_its_used_outer_literals(self):
        """The full audit across all 32 selected methods, narrowed in round 3 to
        the values a manifest entry actually rests on -- compared as multisets so
        an alias or a reordered statement cannot fail it."""
        selected = [m.name for m in dti._class_test_methods_in_source_order(self.class_node)][:TRANCHE_3P_EXPECTED_METHOD_COUNT]
        actual = {name: Counter(self._outer_literals(self.methods[name])) for name in selected}
        self.assertEqual({k: v for k, v in actual.items() if v}, {k: Counter(v) for k, v in TRANCHE_3P_USED_OUTER_LITERALS.items()})
        self.assertEqual(sum(len(v) for v in TRANCHE_3P_USED_OUTER_LITERALS.values()), TRANCHE_3P_USED_OUTER_LITERAL_COUNT)
        # Six methods read only self.policy in-node and are left entirely free.
        self.assertEqual(len(selected) - len(TRANCHE_3P_USED_OUTER_LITERALS), 6)

    def test_each_recheck_source_keeps_its_own_source_specific_trigger(self):
        """The multiset sweep cannot see a swap of the two trigger phrases, but
        the manifest says each row records "its own source-specific" trigger.
        Resolved through the row bindings, so a local rename cannot fail it."""
        method = self.methods["test_mandiant_and_google_tag_recheck_triggers_are_specific"]
        rows = {a.targets[0].id: a.value.slice.value for a in ast.walk(method) if isinstance(a, ast.Assign) and isinstance(a.targets[0], ast.Name)
                and isinstance(a.value, ast.Subscript) and isinstance(a.value.slice, ast.Constant)}
        loop = next(n for n in ast.walk(method) if isinstance(n, ast.For) and isinstance(n.iter, ast.Tuple))
        self.assertEqual({rows[e.elts[0].id]: e.elts[1].value for e in loop.iter.elts}, {"mandiant": "Google Cloud Threat Intelligence固有の利用条件の変更",
                          "google_tag": "Google Security Blog/Blogger固有の利用条件の変更"})

    def test_each_source_specific_assertion_reads_its_own_source_row(self):
        """PR #98 round 4. Swapping the RHS of two `self.rows_by_id[...]` bindings
        leaves the assertion calls, all 140 fingerprints and the outer literal
        multiset untouched, but sends each assertion at a different source's row --
        and every one of these manifest entries names its source. Pinned as
        assertion ordinal -> source_id, resolved semantically by _row_source_of, so
        renaming a local row variable -- or aliasing the registry itself -- is free.
        Membership loops such as the two limited_feed_analysis rows apply the same
        assertions to both sources and are deliberately left unordered."""
        for name, expected in TRANCHE_3P_SOURCE_ROW_READS.items():
            method = self.methods[name]
            source_of = _row_source_of(method)
            actual, ordinal = {}, 0
            for node in ast.walk(method):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "self" and node.func.attr.startswith("assert")):
                    continue
                ordinal += 1
                read = {source_of[n.id] for n in ast.walk(node) if isinstance(n, ast.Name) and n.id in source_of}
                if len(read) == 1: actual[ordinal] = read.pop()
            with self.subTest(method=name): self.assertEqual(actual, expected)

    def test_the_multi_url_count_rule_keeps_its_comparator_and_threshold(self):
        """Blocker 1 of round 2: `if len(types) > 1:` sits OUTSIDE the assertion,
        so `> 2` would leave all 140 fingerprints and every outer string intact
        while silently exempting every 2-type row -- and the manifest's "more
        than one distinct evidence_type" summary would be wrong."""
        method = self.methods["test_multi_url_rows_have_matching_evidence_type_count_when_types_differ"]
        compares = [n for n in ast.walk(method) if isinstance(n, ast.Compare)]
        self.assertEqual(len(compares), 1)
        self.assertEqual([type(o).__name__ for o in compares[0].ops], ["Gt"])
        self.assertEqual([c.value for c in compares[0].comparators], [1])

    def test_method_local_section_bindings_keep_their_slice_topology(self):
        """Round 2: pinning the marker strings is not enough. Each section slice
        is pinned as a whole EXPRESSION -- source object, ordered start/end,
        maxsplit and the [1]/[0] direction -- so swapping an index cannot leave
        every fingerprint and every outer string unchanged."""
        expected = { "gate": "self.policy.split('## 5. Gemini data-use gate', 1)[1]" ".split('## 6. Attribution requirements', 1)[0]",
            "unknowns": "self.policy.split('## 9. Unknowns and owner verification', 1)[1]" ".split('## 10. Relationship to BL-032 and BL-009', 1)[0]",
            "modes": "self.policy.split('## 3. Content usage modes', 1)[1]" ".split('## 4. Source-by-source audit matrix', 1)[0]",
            "recheck": "self.policy.split('## 8. Recheck triggers', 1)[1]" ".split('## 9. Unknowns and owner verification', 1)[0]",
            "attribution": "self.policy.split('## 6. Attribution requirements', 1)[1]"
                           ".split('## 7. Output-similarity and quotation controls', 1)[0]",
            "feed_summary_section": "self.matrix.split('### feed_summary (4件)', 1)[1]" ".split('### limited_feed_analysis (2件)', 1)[0]", }
        seen = {}
        for name in [m.name for m in dti._class_test_methods_in_source_order(self.class_node)][:TRANCHE_3P_EXPECTED_METHOD_COUNT]:
            for node in ast.walk(self.methods[name]):
                if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in expected):
                    seen.setdefault(node.targets[0].id, set()).add(ast.unparse(node.value))
        self.assertEqual({k: sorted(v) for k, v in seen.items()}, {k: [self._expr(v)] for k, v in expected.items()})


# ---------------------------------------------------------------------------
# BL-038 tranche 3t: the accepted-classification history FOUNDATION.
#
# Tranches 3f..3s asserted "shard X was exactly this at tranche N's merge" by hashing
# the CURRENT shard against the accepted value. That conflates a fact about the past
# with a claim about the present, and freezing the present is what blocks the
# Category C conversions BL-038 exists to make.
#
# 3t is the foundation half only: the accepted facts get an independent offline home
# (`document_test_history`), the couplings where HISTORY was DERIVED from current
# constants are undone, and the ledger is pinned, shape-checked and cross-checked
# against BL-038's acceptance record. Every pre-existing byte/index guard is left
# exactly as it was, so Category C conversion is still blocked after 3t. Retargeting
# those guards onto a migration-aware current contract is tranche 3u.
TRANCHE_3T_LEDGER_RECORD_COUNT = 12
TRANCHE_3T_ACCEPTED_TRANCHES = ("3f", "3h", "3i", "3j", "3k", "3l", "3m",
                                "3o", "3p", "3q", "3r", "3s")
# Second independent copy of every scalar accepted fact, so an edit to the ledger is
# caught even if `LEDGER_DIGEST` is re-pinned to match.
# (tranche, pull_request, shard suffix, scope_slice, line_count, entry_count, counts)
TRANCHE_3T_ACCEPTED_FACTS = (
    ("3f", 88, "", [0, 4], 596, 585, {"A": 22, "B": 175, "C": 268, "D": 120}),
    ("3h", 90, "_001", [0, 1], 144, 136, {"A": 0, "B": 38, "C": 91, "D": 7}),
    ("3i", 91, "_001", [0, 2], 268, 259, {"A": 0, "B": 109, "C": 135, "D": 15}),
    ("3j", 92, "_002", [0, 1], 42, 34, {"A": 0, "B": 12, "C": 14, "D": 8}),
    ("3k", 93, "_002", [0, 2], 70, 61, {"A": 0, "B": 34, "C": 19, "D": 8}),
    ("3l", 94, "_002", [0, 3], 94, 84, {"A": 6, "B": 45, "C": 25, "D": 8}),
    ("3m", 95, "_002", [0, 4], 112, 101, {"A": 6, "B": 53, "C": 32, "D": 10}),
    ("3o", 97, "_003", [0, 1], 154, 146, {"A": 0, "B": 70, "C": 54, "D": 22}),
    ("3p", 98, "_004", [0, 1], 148, 140, {"A": 2, "B": 80, "C": 50, "D": 8}),
    ("3q", 99, "_005", [0, 1], 130, 124, {"A": 0, "B": 49, "C": 42, "D": 33}),
    ("3r", 100, "_006", [0, 1], 141, 133, {"A": 0, "B": 60, "C": 37, "D": 36}),
    ("3s", 101, "_007", [0, 1], 45, 37, {"A": 0, "B": 16, "C": 20, "D": 1}),
)
# Second copy of the accepted contract multiset digests. Tranche 3u compares these
# against the live tree plus a migration ledger; 3t only keeps them honest.
TRANCHE_3T_ACCEPTED_CONTRACTS_DIGESTS = {
    "3f": "4971c083471d9987488bab2687be533d42ff48ddac1fc7ae9ee6cd8ca1fab2c8",
    "3h": "4973b69efc1c5c6b2db8d89bdb8ffa49ba796014d2f2a2c8c509844b84ced912",
    "3i": "176be3153b5adf5814775128c44876dc979fc6995b3c831574dc5562efb6a8c1",
    "3j": "84a52ec44295b9fb93837c5b442174de5b49ee4f1357ee38e65a2a4ce259f648",
    "3k": "e2f5a68d982d3be73ff24bac999a287a053c7a022e0f3b705d0fe1b72b6596b6",
    "3l": "8539d9986038cbcd6315d3f2f286a4dca670a65983e7031c32e808a1ebcb11ec",
    "3m": "39bb1af577eddb06c7809d9f5b2906bbaafd3bba5f49fc25dc3970d7b8982a06",
    "3o": "88d0cbc32ee7dc90c79df1d03fd74d47f4efc67ddae2b949b1ddc0e52c79635f",
    "3p": "1c335eaa6d31db5405644485614171a2ce9986348224b884285805dc4c86f0d7",
    "3q": "8a7deefc5ca142a9922ecea2ebe494975ce45c5d50e20bc7358a5dff86479abb",
    "3r": "a3daf507a0a1805ec6936927e2b141e5f2132477829613418d87ddecf4fea2c8",
    "3s": "cf0ec672e88b9ad81459e59e32c881bf26c4f6cd7dfb681290575c87353e56ac",
}
# Exactly these four accepted records carry a parsed-content digest; the rest were
# pinned by bytes alone. Hardcoded so a null<->value edit cannot drift.
TRANCHE_3T_TRANCHES_WITH_CONTENT_DIGEST = ("3h", "3j", "3k", "3l")
# The inline constants that already recorded an accepted fact: two copies must agree.
TRANCHE_3T_INLINE_ACCEPTED_SHAS = {
    "3f": BASE_MANIFEST_SHA256, "3h": TRANCHE_3H_HISTORICAL_SHA256,
    "3i": SHARD_001_CURRENT_SHA256, "3j": TRANCHE_3J_HISTORICAL_SHA256,
    "3k": TRANCHE_3K_HISTORICAL_SHA256, "3l": TRANCHE_3L_HISTORICAL_SHA256,
    "3m": SHARD_002_CURRENT_SHA256,
}
TRANCHE_3T_INLINE_ACCEPTED_CONTENT_DIGESTS = {
    "3h": TRANCHE_3H_HISTORICAL_CONTENT_SHA256, "3j": TRANCHE_3J_HISTORICAL_CONTENT_SHA256,
    "3k": TRANCHE_3K_HISTORICAL_CONTENT_SHA256, "3l": TRANCHE_3L_HISTORICAL_CONTENT_SHA256,
}
# A Category C conversion rewrites these entry fields; the contracts digest is blind
# to them by design, which is what 3u builds its continuity rule on.
TRANCHE_3T_CONVERSION_FIELDS = ("assertion_api", "fingerprint", "category", "action",
                                "contract_summary", "rationale")
TRANCHE_3T_FORBIDDEN_IN_HISTORY_MODULE = ("subprocess", "urllib", "requests", "socket",
                                          "http.client", "os.system")


def _setter(path, value):
    """A one-mutation edit function for a (path, value) schema case."""
    def apply(payload):
        target = payload
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return apply


def _record_facts(record):
    """One ledger record's scalar facts, in TRANCHE_3T_ACCEPTED_FACTS order minus the
    tranche name -- the shape the second copy is compared against."""
    historical = record["historical"]
    return (record["pull_request"],
            record["shard"].replace("document_test_classification", "").replace(".json", ""),
            record["scope_slice"], historical["line_count"], historical["entry_count"],
            historical["category_counts"])


class ClassificationHistoryLedgerTest(unittest.TestCase):
    """The accepted-history ledger: pinned, well-formed, offline, and agreeing with the
    inline accepted constants and with BL-038's own acceptance record."""

    def test_the_ledger_is_pinned_well_formed_and_completely_populated(self):
        indexed = set(json.loads(INDEX_PATH.read_text(encoding="utf-8"))["shards"])
        self.assertEqual(dth.ledger_digest(ROOT), ACCEPTED_LEDGER_DIGEST)
        self.assertEqual(dth.LEDGER_DIGEST, ACCEPTED_LEDGER_DIGEST)
        self.assertEqual(dth.ledger_shape_failures(ROOT, indexed_shards=indexed), [])
        ledger = dth.load_ledger(ROOT)
        self.assertEqual(ledger["schema_version"], dth.LEDGER_SCHEMA_VERSION)
        self.assertEqual(len(ledger["accepted"]), TRANCHE_3T_LEDGER_RECORD_COUNT)
        self.assertEqual(tuple(r["tranche"] for r in ledger["accepted"]),
                         TRANCHE_3T_ACCEPTED_TRANCHES)
        self.assertEqual({r["shard"] for r in ledger["accepted"]} - indexed, set())

    def test_every_accepted_fact_has_a_second_independent_copy(self):
        """What makes "any accepted fact is caught" true even against a re-pinned
        ledger: the tables above live in a different file from the ledger."""
        self.assertEqual(tuple(f[0] for f in TRANCHE_3T_ACCEPTED_FACTS),
                         TRANCHE_3T_ACCEPTED_TRANCHES)
        for tranche, pr, suffix, span, lines, entries, counts in TRANCHE_3T_ACCEPTED_FACTS:
            with self.subTest(tranche=tranche):
                record = dth.accepted(ROOT, tranche)
                self.assertEqual(_record_facts(record),
                                 (pr, suffix, span, lines, entries, counts))
                self.assertEqual(sum(counts.values()), entries)
                self.assertEqual(record["historical"]["contracts_digest"],
                                 TRANCHE_3T_ACCEPTED_CONTRACTS_DIGESTS[tranche])
                self.assertIs(record["historical"]["content_digest"] is None,
                              tranche not in TRANCHE_3T_TRANCHES_WITH_CONTENT_DIGEST)

    def test_the_ledger_agrees_with_every_inline_accepted_constant(self):
        for tranche, sha in TRANCHE_3T_INLINE_ACCEPTED_SHAS.items():
            with self.subTest(tranche=tranche, field="sha256"):
                dth.assert_accepted_history(self, ROOT, tranche, sha256=sha)
        for tranche, digest in TRANCHE_3T_INLINE_ACCEPTED_CONTENT_DIGESTS.items():
            with self.subTest(tranche=tranche, field="content_digest"):
                dth.assert_accepted_history(self, ROOT, tranche, content_digest=digest)
        for tranche, counts in (("3k", TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS),
                                ("3l", TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS)):
            with self.subTest(tranche=tranche, field="category_counts"):
                dth.assert_accepted_history(self, ROOT, tranche, category_counts=counts)
        for tranche, entries, lines in (("3h", TRANCHE_3H_HISTORICAL_ENTRY_COUNT,
                                         TRANCHE_3H_HISTORICAL_LINE_COUNT),
                                        ("3j", TRANCHE_3J_HISTORICAL_ENTRY_COUNT,
                                         TRANCHE_3J_HISTORICAL_LINE_COUNT),
                                        ("3k", TRANCHE_3K_HISTORICAL_ENTRY_COUNT,
                                         TRANCHE_3K_HISTORICAL_LINE_COUNT),
                                        ("3l", TRANCHE_3L_HISTORICAL_ENTRY_COUNT,
                                         TRANCHE_3L_HISTORICAL_LINE_COUNT)):
            with self.subTest(tranche=tranche, field="counts"):
                dth.assert_accepted_history(self, ROOT, tranche, entry_count=entries,
                                            line_count=lines)

    def test_the_historical_constants_are_no_longer_derived_from_current_counts(self):
        """The foundation half of Round 1 finding 1: these were computed from CURRENT
        expected counts, so a conversion inside an accepted window would have silently
        rewritten history. They are accepted literals now, and the module-level source
        text is checked so the derivation cannot creep back."""
        source = (ROOT / "test_document_test_classification.py").read_text(encoding="utf-8")
        for constant, literal in (("TRANCHE_3H_HISTORICAL_ENTRY_COUNT", "136"),
                                  ("TRANCHE_3H_HISTORICAL_LINE_COUNT", "144"),
                                  ("TRANCHE_3J_HISTORICAL_ENTRY_COUNT", "34"),
                                  ("TRANCHE_3K_HISTORICAL_ENTRY_COUNT", "61"),
                                  ("TRANCHE_3L_HISTORICAL_ENTRY_COUNT", "84")):
            with self.subTest(constant=constant):
                self.assertIn(f"{constant} = {literal}", source)
        for constant, counts in (("TRANCHE_3K_HISTORICAL_CATEGORY_COUNTS",
                                  '{"A": 0, "B": 34, "C": 19, "D": 8}'),
                                 ("TRANCHE_3L_HISTORICAL_CATEGORY_COUNTS",
                                  '{"A": 6, "B": 45, "C": 25, "D": 8}')):
            with self.subTest(constant=constant):
                self.assertIn(f"{constant} = {counts}", source)
        # The values did not change, only where they come from.
        self.assertEqual((TRANCHE_3H_HISTORICAL_ENTRY_COUNT, TRANCHE_3J_HISTORICAL_ENTRY_COUNT,
                          TRANCHE_3K_HISTORICAL_ENTRY_COUNT, TRANCHE_3L_HISTORICAL_ENTRY_COUNT),
                         (136, 34, 61, 84))

    def test_backlog_independently_records_the_same_accepted_evidence(self):
        """Not the only copy: BL-038's acceptance record already carries every accepted
        shard SHA and merge commit, so a lone ledger edit contradicts the repository."""
        backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        for record in dth.load_ledger(ROOT)["accepted"]:
            with self.subTest(tranche=record["tranche"]):
                self.assertIn(record["historical"]["sha256"], backlog)
                self.assertIn(record["merge_commit"], backlog)

    def test_history_is_offline_and_never_derived_from_a_live_shard(self):
        """No network, no subprocess, no git -- and nothing in the module reads a shard,
        because history recomputed from the current tree is the coupling 3t undoes."""
        source = (ROOT / "document_test_history.py").read_text(encoding="utf-8")
        for token in TRANCHE_3T_FORBIDDEN_IN_HISTORY_MODULE:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        self.assertNotIn("document_test_inventory", source)
        # Tranche 3u adds a CURRENT half that legitimately reads the index and shards.
        # The HISTORICAL half must still read the accepted ledger and nothing else:
        # history recomputed from the current tree is the coupling 3t/3u remove.
        historical = source[source.index("def load_ledger"):source.index("def contract_of")]
        self.assertEqual(historical.count("read_text"), 1)
        for token in ("shard", "index", "migration", "live"):
            with self.subTest(token=token):
                self.assertNotIn(token, historical)

    def test_the_ledger_schema_is_validated_fail_closed(self):
        """Round 1 finding 3: `is not` identity comparison on schema_version, and no
        shape contract on the rest. Every field is checked now, bools are rejected as
        ints, and the category breakdown must sum to the accepted entry count."""
        indexed = set(json.loads(INDEX_PATH.read_text(encoding="utf-8"))["shards"])
        good = dth.load_ledger(ROOT)
        R0, H0, H1 = ("accepted", 0), ("accepted", 0, "historical"), ("accepted", 1, "historical")
        cases = (
            (("schema_version",), True), (("schema_version",), 2), (("schema_version",), "1"),
            (("note",), "x"), (("accepted",), []),
            (R0 + ("pull_request",), True), (R0 + ("pull_request",), 0),
            (R0 + ("pull_request",), "88"), (R0 + ("merge_commit",), "abc"),
            (R0 + ("merge_commit",), "z" * 40), (R0 + ("shard",), ""),
            (R0 + ("shard",), "nope.json"), (R0 + ("scope_slice",), [0]),
            (R0 + ("scope_slice",), [-1, 2]), (R0 + ("scope_slice",), [2, 2]),
            (R0 + ("scope_slice",), [False, True]), (H0 + ("sha256",), "ab"),
            (H0 + ("contracts_digest",), "g" * 64), (H1 + ("content_digest",), "ab"),
            (H0 + ("line_count",), True), (H0 + ("line_count",), 0),
            (H0 + ("entry_count",), "585"),
            (H0 + ("category_counts",), {"A": 1, "B": 2, "C": 3}),
            (H0 + ("category_counts", "A"), True), (H0 + ("category_counts", "A"), -1),
            (H0 + ("category_counts", "A"), 23), (H0 + ("x",), 1),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def failures_for(mutate):
                ledger = json.loads(json.dumps(good))
                mutate(ledger)
                (root / dth.LEDGER_FILENAME).write_text(
                    json.dumps(ledger, ensure_ascii=False), encoding="utf-8")
                return dth.ledger_shape_failures(root, indexed_shards=indexed)

            self.assertEqual(failures_for(lambda l: None), [])
            for path, value in cases:
                with self.subTest(path=path, value=value):
                    self.assertNotEqual(failures_for(_setter(path, value)), [])
            self.assertNotEqual(failures_for(
                lambda l: l["accepted"].append(json.loads(json.dumps(l["accepted"][0])))), [])
        self.assertEqual(dth.ledger_shape_failures(ROOT, indexed_shards=indexed), [])

    def test_editing_any_accepted_fact_in_the_ledger_is_detected(self):
        """Every accepted field, in the first and last record, is tamper-evident -- and
        against a witness that survives an attacker who also re-pins `LEDGER_DIGEST`:
        the second-copy tables, or BACKLOG.md's acceptance record."""
        original = (ROOT / dth.LEDGER_FILENAME).read_text(encoding="utf-8")
        backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        mutations = (
            ("historical", "sha256", "0" * 64),
            ("historical", "content_digest", "1" * 64),
            ("historical", "contracts_digest", "2" * 64),
            ("historical", "line_count", 999),
            ("historical", "entry_count", 999),
            ("historical", "category_counts", {"A": 9, "B": 9, "C": 9, "D": 9}),
            (None, "merge_commit", "f" * 40),
            (None, "pull_request", 4242),
            (None, "shard", "document_test_classification_003.json"),
            (None, "scope_slice", [1, 2]),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for block, field, value in mutations:
                for index in (0, TRANCHE_3T_LEDGER_RECORD_COUNT - 1):
                    with self.subTest(field=field, record=index):
                        ledger = json.loads(original)
                        record = ledger["accepted"][index]
                        target = record if block is None else record[block]
                        self.assertNotEqual(target.get(field), value)
                        target[field] = value
                        (root / dth.LEDGER_FILENAME).write_text(
                            json.dumps(ledger, ensure_ascii=False), encoding="utf-8")
                        self.assertNotEqual(dth.ledger_digest(root), ACCEPTED_LEDGER_DIGEST)
                        self.assertTrue(self._witnesses(root, index, backlog),
                                        f"re-pinning would hide a {field} edit")
        self.assertEqual((ROOT / dth.LEDGER_FILENAME).read_text(encoding="utf-8"), original)
        self.assertEqual(dth.ledger_digest(ROOT), ACCEPTED_LEDGER_DIGEST)

    def _witnesses(self, root, index, backlog):
        """Which copies of the accepted facts OTHER than LEDGER_DIGEST disagree with the
        ledger at `root`. Non-empty means a re-pinned edit is still caught."""
        tranche = TRANCHE_3T_ACCEPTED_TRANCHES[index]
        record = dth.accepted(root, tranche)
        historical = record["historical"]
        disagree = set()
        if _record_facts(record) != TRANCHE_3T_ACCEPTED_FACTS[index][1:]:
            disagree.add("second-copy-scalars")
        if historical["contracts_digest"] != TRANCHE_3T_ACCEPTED_CONTRACTS_DIGESTS[tranche]:
            disagree.add("second-copy-contracts-digest")
        if record["merge_commit"] not in backlog:
            disagree.add("backlog-merge-commit")
        if historical["sha256"] not in backlog:
            disagree.add("backlog-sha256")
        if (historical["content_digest"] is None) is not (
                tranche not in TRANCHE_3T_TRANCHES_WITH_CONTENT_DIGEST):
            disagree.add("content-digest-presence")
        return disagree

    def test_a_dropped_or_renamed_accepted_record_cannot_pass_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = dth.load_ledger(ROOT)
            ledger["accepted"] = [r for r in ledger["accepted"] if r["tranche"] != "3l"]
            (root / dth.LEDGER_FILENAME).write_text(json.dumps(ledger, ensure_ascii=False),
                                                    encoding="utf-8")
            with self.assertRaises(KeyError):
                dth.accepted(root, "3l")
            self.assertNotEqual(dth.ledger_digest(root), ACCEPTED_LEDGER_DIGEST)

    def test_the_migration_engine_exists_and_the_ledger_starts_empty(self):
        """Was `test_the_foundation_does_not_yet_gate_the_current_tree`, tranche 3t's
        boundary: back then the ledger was additive and no current-side machinery
        existed. Tranche 3u supplies the engine, so the boundary moves -- but only to
        the ENGINE. Retargeting the repository's coupled guards onto it is tranche 3v,
        and the migration ledger ships empty because 3u converts nothing."""
        module = (ROOT / "document_test_history.py").read_text(encoding="utf-8")
        for token in ("owns", "accepted_window", "migrations_for", "live_entries",
                      "reconstruct_accepted_contracts", "successor_reference_failures",
                      "window_boundary_failures", "assert_accepted_contracts_accounted_for"):
            with self.subTest(token=token):
                self.assertIn(f"def {token}", module)
        self.assertEqual(dth.load_migrations(ROOT), {"schema_version": 1, "migrations": []})
        self.assertEqual(dth.migration_shape_failures(ROOT), [])
        self.assertEqual(dth.accepted_scopes_digest(), dth.ACCEPTED_SCOPES_DIGEST)
        # 3u does NOT claim the repository's coupled guards are retargeted: the
        # pre-existing byte/positional guards are still exactly as tranche 3t left them.
        source = (ROOT / "test_document_test_classification.py").read_text(encoding="utf-8")
        for still_there in ("hashlib.sha256(MANIFEST_PATH.read_bytes())",
                            "_subset_content_digest(self.shard[",
                            "self.all_entries[:TRANCHE_3K_HISTORICAL_ENTRY_COUNT]"):
            with self.subTest(pending_3v=still_there):
                self.assertIn(still_there, source)


class AcceptedContractsDigestTest(unittest.TestCase):
    """The contracts digest's semantics, proved on a synthetic fixture. Tranche 3t only
    records the digests; 3u builds `live - successors + retired == accepted` on exactly
    these properties, so they are pinned here before anything depends on them."""

    SCOPE = [{"file": "x.py", "classes": ["XTest"]}]
    FIXTURE = [{"id": "x.py::XTest::test_a::assert-01", "file": "x.py", "class": "XTest",
                "method": "test_a", "ordinal": 1, "assertion_api": "assertIn",
                "fingerprint": "a" * 64, "targets": ["DOC.md"], "category": "C",
                "action": "refactor_later", "contract_summary": "s", "rationale": "r"}]

    def test_the_digest_covers_exactly_the_documented_fields(self):
        base = dth.contracts_digest(self.SCOPE, dth.window_contracts(self.FIXTURE))
        self.assertEqual(dth.CONTRACT_FIELDS, ("file", "class", "method", "targets"))
        for field in dth.CONTRACT_FIELDS:
            with self.subTest(sensitive_to=field):
                mutated = json.loads(json.dumps(self.FIXTURE))
                mutated[0][field] = ["Z.md"] if field == "targets" else "z"
                self.assertNotEqual(
                    dth.contracts_digest(self.SCOPE, dth.window_contracts(mutated)), base)
        # Blind to what a conversion rewrites, and to a split's renumbering.
        for field in TRANCHE_3T_CONVERSION_FIELDS + ("id", "ordinal"):
            with self.subTest(blind_to=field):
                mutated = json.loads(json.dumps(self.FIXTURE))
                mutated[0][field] = 9 if field == "ordinal" else "z"
                self.assertEqual(
                    dth.contracts_digest(self.SCOPE, dth.window_contracts(mutated)), base)
        # Sensitive to losing, gaining or re-scoping a contract -- the properties a
        # migration-aware continuity rule needs.
        for label, scope, entries in (("dropped", self.SCOPE, []),
                                      ("added", self.SCOPE, self.FIXTURE * 2),
                                      ("scope", [{"file": "y.py", "classes": []}], self.FIXTURE)):
            with self.subTest(sensitive_to=label):
                self.assertNotEqual(
                    dth.contracts_digest(scope, dth.window_contracts(entries)), base)
        self.assertNotEqual(base, _subset_content_digest(self.SCOPE[0], self.FIXTURE))


# ---------------------------------------------------------------------------
# BL-038 tranche 3u: the migration ENGINE. Continuity is
# `live - successors + retired == accepted` over CONTRACTS -- (file, class, method,
# targets) -- never ids or ordinals, which is what makes a split's ordinal drift
# free. Retargeting the repository's ~67 historical/current coupled tests onto this
# rule is tranche 3v; 3u fixes the engine contract only.
TRANCHE_3U_ID = "x.py::XTest::%s::assert-%02d"
# The validator only accepts the canonical shard filenames, so engine
# fixtures must use them too -- an illegal layout is not a proof.
TRANCHE_3U_SHARD_A = "document_test_classification.json"
TRANCHE_3U_SHARD_B = "document_test_classification_001.json"
TRANCHE_3U_TARGETS = ["DOC.md"]
TRANCHE_3U_CONVERSION_FIELDS = ("assertion_api", "fingerprint", "category", "action",
                                "contract_summary", "rationale")


def _u_entry(ordinal, method="test_a", targets=None, cls="XTest", file="x.py"):
    return {"id": f"{file}::{cls}::{method}::assert-{ordinal:02d}", "file": file,
            "class": cls, "method": method, "ordinal": ordinal,
            "assertion_api": "assertIn", "fingerprint": f"{ordinal:064d}",
            "targets": list(targets or TRANCHE_3U_TARGETS), "category": "C",
            "action": "refactor_later", "contract_summary": "s", "rationale": "r"}


def _u_root(case):
    holder = tempfile.TemporaryDirectory()
    case.addCleanup(holder.cleanup)
    return Path(holder.name)


def _u_register(case, tranche, scope, range_methods=None):
    """Synthetic tranches are absent from the real maps; register one per test so
    ownership stays logical rather than falling back to a positional slice."""
    dth.ACCEPTED_SCOPES[tranche] = scope
    case.addCleanup(dth.ACCEPTED_SCOPES.pop, tranche, None)
    if range_methods is not None:
        dth.ACCEPTED_RANGE_METHODS[tranche] = range_methods
        case.addCleanup(dth.ACCEPTED_RANGE_METHODS.pop, tranche, None)


def _u_write(root, shards, migrations=()):
    """shards: {filename: (scope, entries)}. Writes an index over all of them, so the
    engine reconstructs windows from the whole indexed manifest set."""
    (root / dth.INDEX_FILENAME).write_text(
        json.dumps({"schema_version": 1, "shards": list(shards)}), encoding="utf-8")
    for name, (scope, entries) in shards.items():
        (root / name).write_text(json.dumps(
            {"schema_version": 1, "scope": scope, "assertions": entries},
            ensure_ascii=False), encoding="utf-8")
    (root / dth.MIGRATIONS_FILENAME).write_text(json.dumps(
        {"schema_version": 1, "migrations": list(migrations)}, ensure_ascii=False),
        encoding="utf-8")


def _u_ledger(root, records):
    """records: {tranche: (scope, accepted_entries)} -> a ledger whose accepted digest
    is taken from those entries."""
    (root / dth.LEDGER_FILENAME).write_text(json.dumps({"schema_version": 1, "accepted": [
        {"tranche": t, "pull_request": 1, "merge_commit": "a" * 40, "shard": TRANCHE_3U_SHARD_A,
         "scope_slice": [0, len(scope)],
         "historical": {"sha256": "b" * 64, "line_count": len(entries) + 8,
                        "entry_count": len(entries), "content_digest": None,
                        "category_counts": {"A": 0, "B": 0, "C": len(entries), "D": 0},
                        "contracts_digest": dth.contracts_digest(
                            scope, dth.window_contracts(entries))}}
        for t, (scope, entries) in records.items()]}, ensure_ascii=False), encoding="utf-8")


def _u_mig(retired, successors, mid="m1", kind="split", method="test_a", targets=None):
    t = list(targets or TRANCHE_3U_TARGETS)
    return {"id": mid, "tranche": "3z", "kind": kind, "reason": "why",
            "retired": [{"id": TRANCHE_3U_ID % (method, n), "targets": t} for n in retired],
            "successors": [{"id": TRANCHE_3U_ID % (method, n), "targets": t}
                           for n in successors]}


TRANCHE_3U_SYNTHETIC_SOURCE = '''import unittest


class XTest(unittest.TestCase):
    def test_a(self):
        self.assertIn("a", "abc")

    def test_b(self):
        self.assertIn("b", "abc")

    def test_c(self):
        self.assertIn("c", "abc")

    def test_d(self):
        self.assertIn("d", "abc")
'''


def _u_write_shard(path, scope, entries):
    """Write a shard in the canonical physical format the real validator requires:
    one scope entry and one assertion per line, fixed key order, trailing newline."""
    body = ",\n".join("    " + json.dumps(e, ensure_ascii=False, separators=(",", ":"))
                      for e in entries)
    scoped = ",\n".join("    " + json.dumps(sc, ensure_ascii=False, separators=(",", ":"))
                        for sc in scope)
    path.write_text('{\n  "schema_version": 1,\n  "scope": [\n%s\n  ],\n'
                    '  "assertions": [\n%s\n  ]\n}\n' % (scoped, body), encoding="utf-8")


def _u_real_root(case, layout):
    """A temp root the REAL validator accepts: a synthetic source file, an index, and
    shards whose entries carry the fingerprints `document_test_inventory` computes from
    that source. `layout` maps shard filename -> scope list. Returns (root, entries).

    Needed because an engine-only fixture can look green while describing a current
    state `validate_indexed_manifests()` would reject -- which is exactly how the first
    re-shard test passed while sharing one whole-class scope across two shards.
    """
    root = _u_root(case)
    (root / "x.py").write_text(TRANCHE_3U_SYNTHETIC_SOURCE, encoding="utf-8")
    records = dti.enumerate_assertions(TRANCHE_3U_SYNTHETIC_SOURCE, "x.py", ["XTest"])
    live = {r.id: r for r in records}
    (root / dth.INDEX_FILENAME).write_text(
        json.dumps({"schema_version": 1, "shards": list(layout)}), encoding="utf-8")
    owned = {}
    for name, scope in layout.items():
        entries = []
        for r in records:
            for sc in scope:
                if sc["file"] != "x.py" or r.cls not in sc["classes"]:
                    continue
                rng = sc.get("method_range")
                methods = [m for m in ("test_a", "test_b", "test_c", "test_d")]
                if rng and not (methods.index(rng["start"]) <= methods.index(r.method)
                                <= methods.index(rng["end"])):
                    continue
                entries.append({"id": r.id, "file": r.file, "class": r.cls, "method": r.method,
                                "ordinal": r.ordinal, "assertion_api": r.assertion_api,
                                "fingerprint": r.fingerprint, "targets": ["DOC.md"],
                                "category": "C", "action": "refactor_later",
                                "contract_summary": "s", "rationale": "r"})
                break
        owned[name] = entries
        _u_write_shard(root / name, scope, entries)
    (root / dth.MIGRATIONS_FILENAME).write_text(
        json.dumps({"schema_version": 1, "migrations": []}), encoding="utf-8")
    return root, [e for entries in owned.values() for e in entries]

class MigrationEngineTest(unittest.TestCase):
    """The 3u engine on synthetic fixtures, so its semantics are pinned independently
    of whatever the real shards contain today."""

    SCOPE = [{"file": "x.py", "classes": ["XTest"]}]
    ACCEPTED = [_u_entry(n) for n in range(1, 6)]

    def _root(self, entries=None, migrations=(), scope=None, shards=None):
        root = _u_root(self)
        scope = scope or self.SCOPE
        _u_register(self, "3z", scope)
        entries = self.ACCEPTED if entries is None else entries
        _u_ledger(root, {"3z": (scope, self.ACCEPTED)})
        _u_write(root, shards or {TRANCHE_3U_SHARD_A: (scope, entries)}, migrations)
        return root

    def _ok(self, root, tranche="3z"):
        dth.assert_accepted_contracts_accounted_for(self, root, tranche)

    def _fails(self, root, tranche="3z"):
        with self.assertRaises((AssertionError, LookupError)):
            dth.assert_accepted_contracts_accounted_for(self, root, tranche)

    def test_an_unchanged_tree_reconciles_with_no_migrations(self):
        self._ok(self._root())

    def test_a_one_to_one_conversion_needs_no_migration_metadata(self):
        converted = json.loads(json.dumps(self.ACCEPTED))
        for e in converted:
            for field in TRANCHE_3U_CONVERSION_FIELDS:
                e[field] = "already_structural" if field == "action" else "converted"
        self._ok(self._root(converted))

    def test_pure_ordinal_drift_needs_no_migration_metadata(self):
        """Renumbering every id and ordinal, and reordering, declares nothing."""
        drifted = [dict(e, id=TRANCHE_3U_ID % ("test_a", e["ordinal"] + 7),
                        ordinal=e["ordinal"] + 7) for e in self.ACCEPTED]
        self._ok(self._root(drifted))
        self._ok(self._root(drifted[::-1]))

    def test_a_split_needs_only_its_own_mapping_not_the_drifted_tail(self):
        """assert-02 becomes two and assert-03..05 shift to 04..06. The ONLY migration
        recorded is the split; the drifted tail declares nothing."""
        after = [_u_entry(1), _u_entry(2), _u_entry(3)] + [_u_entry(n + 1) for n in range(3, 6)]
        split = _u_mig([2], [2, 3])
        self._ok(self._root(after, [split]))
        self.assertEqual(len(split["retired"]) + len(split["successors"]), 3)
        self._fails(self._root(after))

    def test_merge_and_retarget_need_their_mapping(self):
        self._ok(self._root([_u_entry(n) for n in range(1, 5)],
                            [_u_mig([4, 5], [4], kind="merge")]))
        retargeted = json.loads(json.dumps(self.ACCEPTED))
        retargeted[0]["targets"] = ["OTHER.md"]
        self._fails(self._root(retargeted))
        self._ok(self._root(retargeted, [{
            "id": "m1", "tranche": "3z", "kind": "retarget", "reason": "narrower section",
            "retired": [{"id": TRANCHE_3U_ID % ("test_a", 1), "targets": TRANCHE_3U_TARGETS}],
            "successors": [{"id": TRANCHE_3U_ID % ("test_a", 1), "targets": ["OTHER.md"]}]}]))

    def test_silent_deletion_cannot_pass(self):
        """Removing an assertion from source AND manifest leaves the current tree
        self-consistent, so only continuity can catch it."""
        self._fails(self._root(self.ACCEPTED[:-1]))
        root = self._root(self.ACCEPTED[:-1], [{
            "id": "m1", "tranche": "3z", "kind": "split", "reason": "drop it",
            "retired": [{"id": TRANCHE_3U_ID % ("test_a", 5), "targets": TRANCHE_3U_TARGETS}],
            "successors": []}])
        self.assertNotEqual(dth.migration_shape_failures(root), [])

    def test_incomplete_or_wrong_mappings_cannot_pass(self):
        after = [_u_entry(1), _u_entry(2), _u_entry(3)] + [_u_entry(n + 1) for n in range(3, 6)]
        for label, migration in (("no retired", _u_mig([], [2, 3])),
                                 ("successor missing", _u_mig([2], [2])),
                                 ("extra successor", _u_mig([2], [2, 3, 4]))):
            with self.subTest(broken=label):
                self._fails(self._root(after, [migration]))
        with self.subTest(broken="successor target not live"):
            bad = _u_mig([2], [2, 3]); bad["successors"][1]["targets"] = ["NOPE.md"]
            root = self._root(after, [bad])
            self.assertNotEqual(dth.successor_reference_failures(root), [])
        with self.subTest(broken="two migrations claim one successor"):
            twin = _u_mig([2], [2, 3], mid="m2")
            self.assertNotEqual(
                dth.migration_shape_failures(self._root(after, [_u_mig([2], [2, 3]), twin])), [])

    def test_a_successor_id_must_resolve_to_exactly_that_live_entry(self):
        """Blocker 2. The id is load-bearing, not decoration: a nonexistent ordinal with
        an otherwise-correct contract, and a real id with mismatched targets, both fail.
        Retired ids stay historical locators and are never required to exist now."""
        after = [_u_entry(1), _u_entry(2), _u_entry(3)] + [_u_entry(n + 1) for n in range(3, 6)]
        with self.subTest(mutation="nonexistent id, same contract"):
            bad = _u_mig([2], [2, 3])
            bad["successors"][1]["id"] = TRANCHE_3U_ID % ("test_a", 99)
            root = self._root(after, [bad])
            self.assertNotEqual(dth.successor_reference_failures(root), [])
            self._fails(root)
        with self.subTest(mutation="existing id, mismatched targets"):
            bad = _u_mig([2], [2, 3])
            bad["successors"][1]["targets"] = ["OTHER.md"]
            self.assertNotEqual(
                dth.successor_reference_failures(self._root(after, [bad])), [])
        with self.subTest(retired="historical locator only"):
            gone = _u_mig([9], [2, 3])   # assert-09 no longer exists anywhere
            self.assertEqual(dth.successor_reference_failures(self._root(after, [gone])), [])
        with self.subTest(mutation="duplicate live id"):
            root = self._root(after + [_u_entry(2)], [_u_mig([2], [2, 3])])
            self.assertNotEqual(dth.successor_reference_failures(root), [])

    def test_nested_whole_class_windows_share_one_migration(self):
        """3k/3l/3m shape: genuinely different accepted window SIZES over one shard, so
        one recorded split must satisfy the inner and the outer window alike."""
        inner_scope = [{"file": "x.py", "classes": ["XTest"]}]
        outer_scope = inner_scope + [{"file": "x.py", "classes": ["YTest"]}]
        inner = [_u_entry(n) for n in range(1, 4)]
        outer = inner + [_u_entry(n, cls="YTest", method="test_y") for n in (1, 2)]
        root = _u_root(self)
        _u_register(self, "3inner", inner_scope)
        _u_register(self, "3outer", outer_scope)
        _u_ledger(root, {"3inner": (inner_scope, inner), "3outer": (outer_scope, outer)})
        self.assertNotEqual(len(inner), len(outer))
        after = [_u_entry(1), _u_entry(2), _u_entry(3), _u_entry(4)] + \
                [_u_entry(n, cls="YTest", method="test_y") for n in (1, 2)]
        one = _u_mig([3], [3, 4])
        _u_write(root, {TRANCHE_3U_SHARD_A: (outer_scope, after)}, [one])
        for tranche in ("3inner", "3outer"):
            with self.subTest(window=tranche):
                dth.assert_accepted_contracts_accounted_for(self, root, tranche)
        _u_write(root, {TRANCHE_3U_SHARD_A: (outer_scope, after)})
        for tranche in ("3inner", "3outer"):
            with self.subTest(window=tranche, migration="missing"):
                with self.assertRaises(AssertionError):
                    dth.assert_accepted_contracts_accounted_for(self, root, tranche)

    def test_disjoint_method_ranges_over_one_class_never_see_each_other(self):
        """3o/3q/3r and 3p/3s shape: same file, same class, different accepted ranges.
        A migration inside range A must not be applied to B or C."""
        entries = [_u_entry(1, method=m) for m in ("test_a", "test_b", "test_c")]
        ranges = {"A": "test_a", "B": "test_b", "C": "test_c"}
        root = _u_root(self)
        records = {}
        for tranche, method in ranges.items():
            scope = [{"file": "x.py", "classes": ["XTest"],
                      "method_range": {"start": method, "end": method}}]
            _u_register(self, tranche, scope, {"x.py::XTest": [method]})
            records[tranche] = (scope, [e for e in entries if e["method"] == method])
        _u_ledger(root, records)
        after = entries + [_u_entry(2, method="test_a")]
        split = _u_mig([1], [1, 2], method="test_a")
        _u_write(root, {TRANCHE_3U_SHARD_A: (records["A"][0], after)}, [split])
        self.assertEqual([t for t in ranges if dth.migrations_for(root, t)], ["A"])
        for tranche in ranges:
            with self.subTest(range=tranche):
                dth.assert_accepted_contracts_accounted_for(self, root, tranche)
        # Without the mapping only the OWNING range fails; the others stay green.
        _u_write(root, {TRANCHE_3U_SHARD_A: (records["A"][0], after)})
        with self.assertRaises(AssertionError):
            dth.assert_accepted_contracts_accounted_for(self, root, "A")
        for tranche in ("B", "C"):
            with self.subTest(unaffected=tranche):
                dth.assert_accepted_contracts_accounted_for(self, root, tranche)

    def test_a_missing_range_boundary_method_fails_closed(self):
        scope = [{"file": "x.py", "classes": ["XTest"],
                  "method_range": {"start": "test_a", "end": "test_c"}}]
        entries = [_u_entry(1, method=m) for m in ("test_a", "test_b", "test_c")]
        root = _u_root(self)
        _u_register(self, "3rng", scope, {"x.py::XTest": ["test_a", "test_b", "test_c"]})
        _u_ledger(root, {"3rng": (scope, entries)})
        _u_write(root, {TRANCHE_3U_SHARD_A: (scope, [e for e in entries if e["method"] != "test_c"])})
        self.assertNotEqual(dth.window_boundary_failures(root, "3rng"), [])
        self._fails(root, "3rng")

    def test_an_accepted_contract_may_be_resharded_legally(self):
        """Round 2 Blocker 1. The accepted window is reconstructed from the whole
        indexed manifest set, so moving part of it into another CURRENT shard keeps
        continuity green with no migration and no change to history.

        The layout is one the REAL validator accepts: two disjoint method ranges over
        one class. The first version of this test shared a whole-class scope across two
        shards, which the engine accepted but `validate_indexed_manifests()` would
        reject -- proved below -- so it was not a re-shard proof at all.
        """
        whole = [{"file": "x.py", "classes": ["XTest"]}]
        _u_register(self, "3z", whole)
        before_root, accepted_entries = _u_real_root(self, {TRANCHE_3U_SHARD_A: whole})
        self.assertEqual([f.format() for f in
                          dti.validate_indexed_manifests(root=before_root)[0]], [])
        _u_ledger(before_root, {"3z": (whole, accepted_entries)})
        dth.assert_accepted_contracts_accounted_for(self, before_root, "3z")
        ledger_bytes = (before_root / dth.LEDGER_FILENAME).read_bytes()

        # Re-shard: the same four accepted contracts, now split across two shards by
        # disjoint method ranges. Accepted history is untouched.
        split = {TRANCHE_3U_SHARD_A: [{"file": "x.py", "classes": ["XTest"],
                              "method_range": {"start": "test_a", "end": "test_b"}}],
                 TRANCHE_3U_SHARD_B: [{"file": "x.py", "classes": ["XTest"],
                              "method_range": {"start": "test_c", "end": "test_d"}}]}
        root, entries = _u_real_root(self, split)
        shutil.copy2(before_root / dth.LEDGER_FILENAME, root / dth.LEDGER_FILENAME)
        failures, summary = dti.validate_indexed_manifests(root=root)
        self.assertEqual([f.format() for f in failures], [])
        self.assertEqual(summary["inventoried_assertions"], len(accepted_entries))
        self.assertEqual(len(json.loads((root / TRANCHE_3U_SHARD_A).read_text())["assertions"]), 2)
        self.assertEqual(len(json.loads((root / TRANCHE_3U_SHARD_B).read_text())["assertions"]), 2)
        scope, window = dth.accepted_window(root, "3z")
        self.assertEqual(len(window), len(accepted_entries))
        dth.assert_accepted_contracts_accounted_for(self, root, "3z")
        self.assertEqual(dth.load_migrations(root)["migrations"], [])
        self.assertEqual((root / dth.LEDGER_FILENAME).read_bytes(), ledger_bytes)

    def test_sharing_one_whole_class_scope_across_shards_is_rejected(self):
        """The negative half: the layout the first re-shard test used is illegal, so an
        engine-only green cannot be mistaken for a legal current state."""
        whole = [{"file": "x.py", "classes": ["XTest"]}]
        root, _ = _u_real_root(self, {TRANCHE_3U_SHARD_A: whole, TRANCHE_3U_SHARD_B: whole})
        failures, _ = dti.validate_indexed_manifests(root=root)
        self.assertNotEqual([f.format() for f in failures], [])

    def test_an_accepted_contract_may_move_to_another_method(self):
        """Round 2 Blocker 2. A retarget that moves an accepted contract to a method
        OUTSIDE the accepted range: the losing window adds its retired contract back and
        ignores the successor that landed outside it, so lineage is anchored on the
        retired side while the successor is still validated exactly."""
        accepted_scope = [{"file": "x.py", "classes": ["XTest"],
                           "method_range": {"start": "test_a", "end": "test_b"}}]
        _u_register(self, "3z", accepted_scope, {"x.py::XTest": ["test_a", "test_b"]})
        old_id, new_id = TRANCHE_3U_ID % ("test_a", 1), TRANCHE_3U_ID % ("test_c", 1)
        accepted = [_u_entry(1, method="test_a"), _u_entry(1, method="test_b")]
        root = _u_root(self)
        _u_ledger(root, {"3z": (accepted_scope, accepted)})
        # test_a's contract is gone; an equivalent one now lives in test_c, outside the
        # accepted range but inside the shard the index lists.
        after = [_u_entry(1, method="test_b"), _u_entry(1, method="test_c")]
        wide = [{"file": "x.py", "classes": ["XTest"]}]
        _u_write(root, {TRANCHE_3U_SHARD_A: (wide, after)})
        self.assertEqual(dth.successor_reference_failures(root), [])
        with self.subTest(stage="no migration"):
            self._fails(root)
        retarget = {"id": "m1", "tranche": "3z", "kind": "retarget",
                    "reason": "the contract moved to a new method",
                    "retired": [{"id": old_id, "targets": TRANCHE_3U_TARGETS}],
                    "successors": [{"id": new_id, "targets": TRANCHE_3U_TARGETS}]}
        _u_write(root, {TRANCHE_3U_SHARD_A: (wide, after)}, [retarget])
        with self.subTest(stage="explicit retarget migration"):
            self.assertEqual(dth.successor_reference_failures(root), [])
            self._ok(root)
        with self.subTest(stage="successor id still validated exactly"):
            bad = json.loads(json.dumps(retarget))
            bad["successors"][0]["id"] = TRANCHE_3U_ID % ("test_c", 99)
            _u_write(root, {TRANCHE_3U_SHARD_A: (wide, after)}, [bad])
            self.assertNotEqual(dth.successor_reference_failures(root), [])

    def test_a_method_move_does_not_disturb_another_accepted_range(self):
        """The receiving range is a separate accepted window: it subtracts the arrived
        contract and ignores the retired side, so neither window is broken by the other's
        migration."""
        losing = [{"file": "x.py", "classes": ["XTest"],
                   "method_range": {"start": "test_a", "end": "test_a"}}]
        gaining = [{"file": "x.py", "classes": ["XTest"],
                    "method_range": {"start": "test_c", "end": "test_c"}}]
        _u_register(self, "3lose", losing, {"x.py::XTest": ["test_a"]})
        _u_register(self, "3gain", gaining, {"x.py::XTest": ["test_c"]})
        root = _u_root(self)
        _u_ledger(root, {"3lose": (losing, [_u_entry(1, method="test_a")]),
                         "3gain": (gaining, [_u_entry(1, method="test_c")])})
        after = [_u_entry(1, method="test_c"), _u_entry(2, method="test_c")]
        wide = [{"file": "x.py", "classes": ["XTest"]}]
        move = {"id": "m1", "tranche": "3z", "kind": "retarget", "reason": "moved",
                "retired": [{"id": TRANCHE_3U_ID % ("test_a", 1), "targets": TRANCHE_3U_TARGETS}],
                "successors": [{"id": TRANCHE_3U_ID % ("test_c", 2),
                                "targets": TRANCHE_3U_TARGETS}]}
        _u_write(root, {TRANCHE_3U_SHARD_A: (wide, after)}, [move])
        for tranche in ("3lose", "3gain"):
            with self.subTest(window=tranche):
                dth.assert_accepted_contracts_accounted_for(self, root, tranche)
        _u_write(root, {TRANCHE_3U_SHARD_A: (wide, after)})
        for tranche in ("3lose", "3gain"):
            with self.subTest(window=tranche, migration="missing"):
                with self.assertRaises(AssertionError):
                    dth.assert_accepted_contracts_accounted_for(self, root, tranche)


class MigrationLedgerSchemaTest(unittest.TestCase):
    """Fail-closed shape contract for the migration ledger."""

    GOOD = {"id": "m1", "tranche": "3z", "kind": "split", "reason": "why",
            "retired": [{"id": "x.py::XTest::test_a::assert-01", "targets": ["DOC.md"]}],
            "successors": [{"id": "x.py::XTest::test_a::assert-01", "targets": ["DOC.md"]},
                           {"id": "x.py::XTest::test_a::assert-02", "targets": ["DOC.md"]}]}

    def _failures(self, mutate):
        root = _u_root(self)
        data = {"schema_version": 1, "migrations": [json.loads(json.dumps(self.GOOD))]}
        mutate(data)
        (root / dth.MIGRATIONS_FILENAME).write_text(json.dumps(data, ensure_ascii=False),
                                                    encoding="utf-8")
        return dth.migration_shape_failures(root)

    def test_the_committed_ledger_is_empty_and_well_formed(self):
        self.assertEqual(dth.load_migrations(ROOT), {"schema_version": 1, "migrations": []})
        self.assertEqual(dth.migration_shape_failures(ROOT), [])
        self.assertEqual(dth.successor_reference_failures(ROOT), [])

    def test_every_malformed_shape_is_reported(self):
        self.assertEqual(self._failures(lambda d: None), [])
        M0 = ("migrations", 0)
        for path, value in (
            (("schema_version",), True), (("schema_version",), 2), (("schema_version",), "1"),
            (("note",), 1), (("migrations",), {}),
            (M0 + ("id",), ""), (M0 + ("tranche",), " "), (M0 + ("kind",), "vibes"),
            (M0 + ("reason",), "   "), (M0 + ("retired",), []), (M0 + ("successors",), []),
            (M0 + ("retired", 0, "id"), "nope"),
            (M0 + ("retired", 0, "id"), "x.py::XTest::test_a::nope-01"),
            (M0 + ("successors", 0, "targets"), []),
            (M0 + ("successors", 0, "targets"), [""]),
        ):
            with self.subTest(path=path, value=value):
                self.assertNotEqual(self._failures(_setter(path, value)), [])
        for label, mutate in (
            ("missing key", lambda d: d["migrations"][0].pop("reason")),
            ("extra key", lambda d: d["migrations"][0].__setitem__("extra", 1)),
            ("member extra key", lambda d: d["migrations"][0]["retired"][0].__setitem__("x", 1)),
            ("duplicate migration id",
             lambda d: d["migrations"].append(json.loads(json.dumps(self.GOOD)))),
            ("duplicate retired id",
             lambda d: d["migrations"][0]["retired"].append(
                 json.loads(json.dumps(self.GOOD["retired"][0])))),
            ("duplicate successor id",
             lambda d: d["migrations"][0]["successors"].append(
                 json.loads(json.dumps(self.GOOD["successors"][0])))),
            ("no-op migration",
             lambda d: d["migrations"][0].__setitem__(
                 "successors", json.loads(json.dumps(self.GOOD["retired"])))),
        ):
            with self.subTest(broken=label):
                self.assertNotEqual(self._failures(mutate), [])

    def test_two_migrations_cannot_claim_the_same_contract(self):
        for side in ("retired", "successors"):
            with self.subTest(side=side):
                def mutate(d, side=side):
                    twin = json.loads(json.dumps(self.GOOD)); twin["id"] = "m2"
                    for other in ("retired", "successors"):
                        if other != side:
                            twin[other] = [{"id": "x.py::XTest::test_a::assert-09",
                                            "targets": ["DOC.md"]}]
                    d["migrations"].append(twin)
                self.assertNotEqual(self._failures(mutate), [])

    def test_the_accepted_scope_maps_are_pinned_and_cover_every_record(self):
        self.assertEqual(dth.accepted_scopes_digest(), dth.ACCEPTED_SCOPES_DIGEST)
        self.assertEqual(sorted(dth.ACCEPTED_SCOPES), sorted(TRANCHE_3T_ACCEPTED_TRANCHES))
        ranged = {t for t, scope in dth.ACCEPTED_SCOPES.items()
                  if any("method_range" in s for s in scope)}
        self.assertEqual(ranged, set(dth.ACCEPTED_RANGE_METHODS))
        self.assertEqual(ranged, {"3o", "3p", "3q", "3r", "3s"})
        for tranche in TRANCHE_3T_ACCEPTED_TRANCHES:
            with self.subTest(tranche=tranche):
                self.assertEqual(dth.window_boundary_failures(ROOT, tranche), [])
                scope, window = dth.accepted_window(ROOT, tranche)
                self.assertEqual(scope, dth.ACCEPTED_SCOPES[tranche])
                # BL-038 tranche 3v (C010): the CURRENT window length is NOT required to
                # equal the historical accepted entry_count -- a legal split or merge
                # changes it. Continuity of the accepted contracts is the live contract.
                dth.assert_accepted_contracts_accounted_for(self, ROOT, tranche)


# BL-038 tranche 3v. The frozen Round 0 planning snapshot of historical/current
# coupling candidates, measured against main 22af0284. It is a PLANNING record, not a
# current-state tracker: these guards check the snapshot's own schema, baseline, counts,
# ids, grouping and corrections. Deliberately absent is any requirement that the listed
# test methods still exist in the current tree -- that would re-freeze the very thing
# tranches 3v-3y exist to unfreeze.
COUPLING_INVENTORY_PATH = ROOT / "document_test_coupling_inventory_3v.json"
COUPLING_BASELINE_MAIN = "22af028435f759077b6b4d6352dda35afc5d88de"
COUPLING_MECHANISM_COUNTS = {"H1": 34, "H2": 9, "H3": 19, "H4": 18, "H5": 38,
                             "H6": 50, "H7": 11, "H8": 8, "H9": 30, "H10": 0}
COUPLING_TRANCHE_COUNTS = {"3v": 23, "3w": 38, "3x": 27, "3y": 18}
COUPLING_GROUP_COUNTS = {"G1": 38, "G2": 13, "G3": 9, "G4": 27, "G5": 18, "G6": 1}
COUPLING_DESTINATIONS = frozenset({"accepted_history_ledger", "migration_continuity",
                                   "current_validator", "current_structural_guard",
                                   "mixed", "none"})


class CouplingInventorySnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(COUPLING_INVENTORY_PATH.read_text(encoding="utf-8"))
        cls.candidates = cls.snapshot["candidates"]

    def test_the_snapshot_is_a_planning_record_pinned_to_the_round_0_baseline(self):
        self.assertEqual(self.snapshot["schema_version"], 2)
        self.assertEqual(self.snapshot["artifact"], "document_test_coupling_inventory_3v")
        self.assertEqual(self.snapshot["baseline_main"], COUPLING_BASELINE_MAIN)
        self.assertEqual(self.snapshot["candidate_unit"], "test_method")
        self.assertEqual(self.snapshot["measurement_definition_version"], 1)
        self.assertIn("NOT a current-state tracker", self.snapshot["purpose"])
        self.assertEqual(self.snapshot["category_c_unblock_boundary"], "tranche 3y acceptance")

    def test_the_candidate_population_and_mechanism_histogram_are_frozen(self):
        self.assertEqual(self.snapshot["candidate_count"], 106)
        self.assertEqual(len(self.candidates), 106)
        self.assertEqual(self.snapshot["corrected_mechanism_counts"], COUPLING_MECHANISM_COUNTS)
        counted = {key: 0 for key in COUPLING_MECHANISM_COUNTS}
        for candidate in self.candidates:
            for mechanism in candidate["mechanisms"]:
                counted[mechanism] += 1
        self.assertEqual(counted, COUPLING_MECHANISM_COUNTS)
        self.assertEqual(counted["H10"], 0)

    def test_candidate_ids_are_unique_and_complete(self):
        ids = [c["candidate_id"] for c in self.candidates]
        self.assertEqual(ids, [f"C{n:03d}" for n in range(1, 107)])
        self.assertEqual(len(set(ids)), 106)
        keys = {(c["test_file"], c["class"], c["test_method"]) for c in self.candidates}
        self.assertEqual(len(keys), 106)  # one row per test method, deduped

    def test_grouping_covers_every_candidate_exactly_once(self):
        groups = {key: 0 for key in COUPLING_GROUP_COUNTS}
        tranches = {key: 0 for key in COUPLING_TRANCHE_COUNTS}
        mapping = {"G6": "3v", "G2": "3v", "G3": "3v", "G1": "3w", "G4": "3x", "G5": "3y"}
        for candidate in self.candidates:
            with self.subTest(candidate=candidate["candidate_id"]):
                self.assertEqual(mapping[candidate["group"]], candidate["tranche"])
            groups[candidate["group"]] += 1
            tranches[candidate["tranche"]] += 1
        self.assertEqual(groups, COUPLING_GROUP_COUNTS)
        self.assertEqual(tranches, COUPLING_TRANCHE_COUNTS)
        self.assertEqual(sum(tranches.values()), 106)

    def test_every_row_carries_a_destination_disposition_and_preservation_note(self):
        for candidate in self.candidates:
            with self.subTest(candidate=candidate["candidate_id"]):
                self.assertIn(candidate["retarget_destination"], COUPLING_DESTINATIONS)
                self.assertIn(candidate["keep_or_remove"], ("rewrite", "remove_obsolete"))
                self.assertTrue(candidate["retarget_needed"])
                self.assertTrue(candidate["historical_fact"])
                self.assertTrue(candidate["historical_fact_preserved_by"])
                if candidate["keep_or_remove"] == "remove_obsolete":
                    self.assertEqual(candidate["retarget_destination"], "none")
        self.assertNotIn("none_removed",
                         {c["retarget_destination"] for c in self.candidates})

    def test_the_h7_ruling_records_no_live_fingerprint_invariant(self):
        ruling = self.snapshot["h7_ruling"]
        self.assertEqual((ruling["H7-A"], ruling["H7-A+B"], ruling["H7-B_pure"], ruling["H7-C"]),
                         (9, 2, 0, 0))
        self.assertEqual(len([c for c in self.candidates if c.get("h7_class") == "H7-A"]), 9)
        self.assertEqual(len([c for c in self.candidates if c.get("h7_class") == "H7-A+B"]), 2)
        self.assertEqual([c for c in self.candidates if c.get("h7_class") == "H7-C"], [])
        self.assertIn("not a repository invariant", ruling["h7c_refutation"])

    def test_the_corrections_are_recorded_rather_than_silently_applied(self):
        corrections = {c["id"]: c for c in self.snapshot["corrections"]}
        self.assertEqual(sorted(corrections),
                         ["3v-1", "3v-2", "3w-1", "3w-2",
                          "R0.1-1", "R0.1-2", "R0.1-3", "R0.2-1"])
        # Tranche 3w-a found an out-of-population H7 false negative and handled it in the
        # same tranche, so it is a recorded correction but does NOT join the unresolved
        # future work. 3w-2 belongs to the 3m family and is appended in tranche 3w-b.
        self.assertEqual(corrections["3w-1"]["status"], "handled in tranche 3w")
        self.assertEqual(corrections["3w-1"]["mechanisms"], ["H7"])
        self.assertEqual(corrections["3w-1"]["ruling"],
                         {"h7_class": "H7-A", "retarget_destination": "none",
                          "keep_or_remove": "remove_obsolete"})
        self.assertEqual(corrections["3w-1"]["population_change"], 0)
        # Tranche 3w-b appends 3w-2 on the same terms; both were handled in-tranche, so
        # neither joins the unresolved future work -- 3v-1 stays the only entry there.
        self.assertEqual(corrections["3w-2"]["status"], "handled in tranche 3w-b")
        self.assertEqual(corrections["3w-2"]["ruling"], corrections["3w-1"]["ruling"])
        self.assertEqual(corrections["3w-2"]["population_change"], 0)
        # The C002/C003 remediation is a fix to existing frozen rows, NOT a new candidate
        # or correction, so it must not appear in the appendix.
        self.assertEqual([c for c in corrections if "C002" in c or "C003" in c], [])
        self.assertEqual([g["correction"] for g in self.snapshot["known_false_negatives"]],
                         ["3v-1"])
        # The tranche 3v conversion proof found one measurement false negative. It is
        # recorded with its root cause and deferred to tranche 3y; the frozen 106
        # population is deliberately NOT edited to absorb it.
        self.assertEqual(corrections["3v-1"]["status"], "open, deferred to tranche 3y")
        gap = self.snapshot["known_false_negatives"]
        self.assertEqual([(g["group"], g["tranche"], g["correction"]) for g in gap],
                         [("G5", "3y", "3v-1")])
        self.assertNotIn((gap[0]["class"], gap[0]["test_method"]),
                         {(c["class"], c["test_method"]) for c in self.candidates})
        for identifier, correction in corrections.items():
            with self.subTest(correction=identifier):
                self.assertTrue(correction["reason"])
                self.assertIn("field", correction)
        self.assertEqual(corrections["R0.1-3"]["status"], "withdrawn at Round 0.2")
        self.assertEqual(corrections["R0.2-1"]["status"], "canonical")

    def test_the_empirical_probe_figures_are_defined_not_merely_quoted(self):
        probe = self.snapshot["empirical_probe_summary"]
        self.assertEqual(probe["empirical_raw_failure_count"], 43)
        self.assertEqual(probe["empirical_final_candidate_count"], 29)
        self.assertEqual(probe["excluded_by_o1_o6"], 14)
        self.assertEqual(probe["one_to_one_shard007_failing_methods"]
                         + probe["split_base_shard_failing_methods"], 13 + 41)
        self.assertEqual(probe["empirical_raw_failure_count"]
                         - probe["empirical_final_candidate_count"], probe["excluded_by_o1_o6"])
        for key in ("empirical_raw_failure_definition", "empirical_final_candidate_definition"):
            with self.subTest(key=key):
                self.assertTrue(probe[key])

    def test_the_tranche_3v_slice_is_the_twenty_three_rows_handled_here(self):
        rows = [c for c in self.candidates if c["tranche"] == "3v"]
        self.assertEqual(len(rows), 23)
        self.assertEqual(sorted({c["group"] for c in rows}), ["G2", "G3", "G6"])
        # PLANNED disposition, kept as the planning-time record: 21 rewrite / 2 remove.
        self.assertEqual(len([c for c in rows if c["keep_or_remove"] == "remove_obsolete"]), 2)
        self.assertEqual(len([c for c in rows if c["keep_or_remove"] == "rewrite"]), 21)
        # The 83 frozen-inventory rows left for tranches 3w/3x/3y.
        self.assertEqual(len([c for c in self.candidates if c["tranche"] != "3v"]), 83)

    def test_the_actual_3v_disposition_differs_from_the_plan_only_via_correction_3v_2(self):
        """Correction 3v-2 moved C021 from the planned H5/H6 mixed/rewrite to H7-A
        none/remove_obsolete, so the ACTUAL tranche 3v result is 20 rewrite / 3 removed.
        The frozen row keeps its planning-time values; the two must not be conflated."""
        correction = {c["id"]: c for c in self.snapshot["corrections"]}["3v-2"]
        self.assertEqual(correction["field"], "C021 mechanisms / disposition")
        self.assertEqual(correction["original_frozen_planning"],
                         {"mechanisms": ["H5", "H6"], "retarget_destination": "mixed",
                          "keep_or_remove": "rewrite"})
        self.assertEqual(correction["implementation_ruling"],
                         {"h7_class": "H7-A", "retarget_destination": "none",
                          "keep_or_remove": "remove_obsolete"})
        self.assertEqual((correction["population_change"], correction["group_change"],
                          correction["tranche_change"]), (0, 0, 0))
        self.assertEqual(correction["effect_on_tranche_3v_totals"],
                         {"planned": {"rewrite": 21, "remove_obsolete": 2},
                          "actual": {"rewrite": 20, "remove_obsolete": 3}})
        # The frozen C021 row itself was NOT rewritten to match the ruling.
        c021 = {c["candidate_id"]: c for c in self.candidates}["C021"]
        self.assertEqual((c021["mechanisms"], c021["retarget_destination"],
                          c021["keep_or_remove"]), (["H5", "H6"], "mixed", "rewrite"))
        self.assertEqual((c021["group"], c021["tranche"]), ("G2", "3v"))

    def test_the_planned_h7_a_plus_b_rows_are_c012_in_3v_and_c077_in_3x(self):
        planned = {c["candidate_id"]: c["tranche"] for c in self.candidates
                   if c.get("h7_class") == "H7-A+B"}
        self.assertEqual(planned, {"C012": "3v", "C077": "3x"})

    def test_the_residual_accounting_never_claims_a_complete_universe(self):
        acc = self.snapshot["residual_accounting"]
        self.assertEqual(acc["frozen_planning_population"], 106)
        self.assertEqual(acc["frozen_3v_handled"], 23)
        # Round 2: this block is the record AS OF TRANCHE 3V ACCEPTANCE and is deliberately
        # NOT advanced by later tranches -- current progress lives in BACKLOG/STATUS only.
        self.assertEqual(acc["recorded_at"], "tranche 3v acceptance")
        self.assertIs(acc["is_current_tracker"], False)
        self.assertEqual(acc["frozen_inventory_residual"], 83)
        self.assertEqual(acc["known_out_of_inventory_false_negatives"], 1)
        self.assertEqual(acc["known_future_residual_at_least"], 84)
        self.assertEqual([k for k in acc if "3w" in k], [])  # no per-tranche progress fields
        self.assertEqual(acc["frozen_inventory_residual"]
                         + acc["known_out_of_inventory_false_negatives"],
                         acc["known_future_residual_at_least"])
        self.assertEqual(acc["tranche_3y_frozen_rows"], 18)
        self.assertEqual(acc["tranche_3y_known_additional_corrections"], 1)
        self.assertEqual(acc["tranche_3y_frozen_rows"]
                         + acc["tranche_3y_known_additional_corrections"],
                         acc["tranche_3y_known_work_at_least"])
        self.assertIn("NOT a current progress tracker", acc["note"])
        self.assertIn("not a proven-complete coupling universe", acc["note"])


if __name__ == "__main__":
    unittest.main()
