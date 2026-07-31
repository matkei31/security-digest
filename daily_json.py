#!/usr/bin/env python3
"""
日次JSON (data/YYYY-MM-DD.json, data/index.json) の生成・検証・保存 (Ticket 3)

fetch.py からのみ import される。fetch.py には依存しない(循環import回避のため、
必要な値はすべて引数として受け取る設計にしている)。
"""

import datetime
import hashlib
import json
import os
import re
import tempfile
import unicodedata
import urllib.parse
from pathlib import Path

# ── パス ──────────────────────────────────────────────────────────────────
# 実行時のカレントディレクトリに依存させず、このファイルの配置場所を基準にする。
REPOSITORY_ROOT = Path(__file__).resolve().parent
DATA_DIR = REPOSITORY_ROOT / "data"

# ── バージョン・スキーマ定数(一元管理) ───────────────────────────────────────
# BL-032: schema_version 1では、AI各件数・counts集計がtotal_itemsへ一致する契約
# だったが、metadata_only相当の記事をAI成功率の分母・「未判定」集計から除外する
# 要件と両立しないため、2へbumpする。過去のschema_version=1 daily JSONは
# 一切書き換えず、そのままレガシー契約(このファイル内のv1専用ロジック)で読む。
SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
ARTICLE_PROMPT_VERSION = "article-analysis-v8"
# BL-021: 後方互換のためprompt_versionという既存フィールド名を維持するが、
# 新値はLLM promptではなくToday's Brief composition contractのversionを表す。
# BL-029: 「重要・優先事項」をARTICLE analysis.summary/financial_impactの
# 同一記事ペアから構成するcomposition contractへ更新し、v2へbumpした。
# 過去daily JSON(today-brief-extractive-v1／today-brief-v3等)は書き換えない。
BRIEF_PROMPT_VERSION = "today-brief-extractive-v2"
BRIEF_MODEL = "deterministic-extractive"
CATEGORY_VERSION = "v1"

VALID_RUN_STATUSES = {"success", "partial", "failed", "not_attempted"}
VALID_ANALYSIS_STATUSES = {"success", "fallback", "failed", "not_attempted"}
VALID_BRIEF_STATUSES = {"success", "failed", "not_attempted"}

# Ticket 8: Today's Brief 4要素の件数上限。fetch.py側の正規化・response_schemaと
# ここでの保存前検証の両方から参照し、値を二重管理しない。
BRIEF_MAX_HIGHLIGHTS = 3
BRIEF_MAX_DISCUSSION_POINTS = 3
BRIEF_MAX_CHECK_ITEMS = 2
# BL-021 extractive contractではdiscussion_pointsを「金融機関との関連」として
# 最大2件だけ構成する。保存前検証の後方互換上限3件は過去Brief向けに維持する。
BRIEF_EXTRACTIVE_MAX_DISCUSSION_POINTS = 2
VALID_ERROR_TYPES = {
    "rate_limit", "quota_exceeded", "billing_or_balance", "schema_parse_error",
    "network_error", "api_error", "unknown",
    "resource_exhausted", "permission_denied",
}

# Ticket 4: category/importance/urgency/tagsの許容値はここで一元管理し、
# Gemini response_schema・コード側バリデーション・countsの3箇所すべてで
# この定数を参照する(値の二重管理をしない)。

IMPORTANCE_VALUES = ("高", "中", "低")
IMPORTANCE_KEYS = IMPORTANCE_VALUES + ("未判定",)

URGENCY_VALUES = ("本日確認", "今週確認", "参考")
URGENCY_KEYS = URGENCY_VALUES + ("未判定",)

CATEGORY_VALUES = (
    "脆弱性・パッチ", "攻撃・脅威動向", "インシデント", "規制・ガバナンス",
    "クラウド・サプライチェーン", "AI・新技術リスク", "その他",
)
CATEGORY_KEYS = CATEGORY_VALUES + ("未判定",)

TAG_ALLOWLIST = (
    "CVE", "KEV", "ゼロデイ", "悪用確認済み", "パッチ", "ランサムウェア", "APT",
    "フィッシング", "認証", "IAM", "クラウド", "SaaS", "サプライチェーン",
    "委託先管理", "AI", "LLM", "AIエージェント", "規制", "ガイドライン", "監督",
    "インシデント", "情報漏えい", "業務停止", "決済", "SWIFT", "CSCF", "DORA", "NIST",
)
MAX_TAGS = 5

JST = datetime.timezone(datetime.timedelta(hours=9))

DAILY_FILENAME_RE = re.compile(r"\d{4}-\d{2}-\d{2}\.json")
DIGEST_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

# Ticket 12a-review: facts.cvesの最低限の値検証で使う許容値。
# nullableな日時・CVSS等の全面検証までは行わない(過剰な厳密化はしない)。
FACTS_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,19}")
VALID_NVD_STATUSES = {"found", "not_found", "unavailable"}
VALID_KEV_STATUSES = {"listed", "not_listed", "unknown"}
VALID_FACTS_RETRIEVAL_VALUES = {"live", "cache_fresh", "cache_stale", "unavailable"}


class DailyJsonError(Exception):
    """日次JSON生成・検証・保存に関するエラー"""


# ── エラー分類 (一箇所に集約) ─────────────────────────────────────────────

def classify_gemini_error(exception=None, http_status=None):
    """Gemini呼び出しの例外・HTTPステータスから保存用のerror_typeを判定する。
    複雑な文字列判定は避け、例外の型とHTTPステータスコードのみで分類する。

    Gemini APIの公式エラーコードでは、403はPERMISSION_DENIED、
    429はRESOURCE_EXHAUSTED(RPM/TPM/RPDに限らず、spend-based limitや
    アカウントの利用階層・請求履歴に基づく制限も含みうる)である。
    HTTPステータスだけではrate_limit/quota_exceeded/billing_or_balanceの
    いずれが原因かを正確に断定できないため、429はresource_exhausted、
    403はpermission_deniedとしてそのまま保存し、それ以上の細分化は行わない。
    """
    if http_status is not None:
        if http_status == 403:
            return "permission_denied"
        if http_status == 429:
            return "resource_exhausted"
        if http_status == 402:
            return "billing_or_balance"
        return "api_error"

    if exception is not None:
        import urllib.error
        if isinstance(exception, urllib.error.URLError):
            return "network_error"
        return "unknown"

    return None


# ── 日時 ──────────────────────────────────────────────────────────────────

def parse_datetime(date_string):
    """RSS/Atom/API由来の日付文字列を解釈する共通parser(Ticket 14a-3)。
    fetch.parse_date()とparse_date_to_jst()はこのparserを使い、フォーマット一覧を
    二重管理しない。

    戻り値:
    - タイムゾーン情報付き日時: timezone-awareなdatetime
    - 日付のみ(YYYY-MM-DD): naiveなdatetime(KEV等の既存用途のため維持)
    - タイムゾーンなしの時刻付き日時(例 2026-07-13T09:00:00): 正確な瞬間を特定できず
      解釈不能としてNone(recent判定・UTC比較の根拠がないため採用対象へ広げない)
    - その他の解釈不能値: None
    例外は送出しない(呼び出し元へ漏らさない)。対応: ISO 8601(小数秒あり/なし・数値
    オフセット・Z表記)、RFC822/2822(数値オフセット・GMT/UTC)、日付のみYYYY-MM-DD。
    日付文字列以外(レスポンス本文等)はここへ渡らない前提で、ログ出力も行わない。
    """
    if not isinstance(date_string, str):
        return None
    s = date_string.strip()
    if not s:
        return None

    # 末尾Z/zを+00:00へ正規化する(strptimeの%zがZ非対応なPython版への保険。
    # 3.9.6ではZも解釈できるが、明示正規化で版差を吸収する)。
    normalized = s
    if normalized[-1] in ("Z", "z"):
        normalized = normalized[:-1] + "+00:00"

    # (1) タイムゾーン付き(aware)。小数秒あり→なしの順に試す。
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M%z",
        "%a, %d %b %Y %H:%M:%S %z",
    ):
        try:
            return datetime.datetime.strptime(normalized, fmt)
        except ValueError:
            continue

    # (2) RFC822の名前付きUTC(GMT/UTC)はUTCとして扱う(aware)。
    for fmt in ("%a, %d %b %Y %H:%M:%S GMT", "%a, %d %b %Y %H:%M:%S UTC"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue

    # (3) 日付のみ(YYYY-MM-DD)はnaiveなdatetimeとして許可する(KEV dateAdded等)。
    # タイムゾーンなしの「時刻付き」ISO日時は正確な瞬間を特定できないため受理せず
    # (2)以降のいずれにも一致させない=最終的にNoneとなる。
    for fmt in (
        "%Y-%m-%d",
    ):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue

    return None


def parse_date_to_jst(date_string):
    """RSS/API由来の日付文字列を、タイムゾーン情報を保持したままJSTへ正規化する。
    解析できない場合、またはオフセット情報がなく正確な日時を特定できない場合はNoneを返す。
    parse_datetime()(共通parser)を用いる。fetch.pyのparse_date()(ソート・カットオフ
    判定用、tzinfoを破棄する実装)とは戻り値の扱いのみ異なる。表示用のため小数秒は落とす。
    """
    dt = parse_datetime(date_string)
    if dt is None or dt.tzinfo is None:
        # タイムゾーン情報が無い(日付のみ等)は正確な瞬間を特定できないためNone(従来通り)。
        return None
    return dt.astimezone(JST).replace(microsecond=0)


# ── URL正規化・ID・content_hash ──────────────────────────────────────────

def normalize_url_for_id(url):
    """記事ID用のURL正規化 (Phase 1): scheme/hostを小文字化、fragmentを削除。
    path/queryは維持する。正規化できない場合は元のURLをそのまま返す。
    既存のsafe_url()・HTMLリンク処理には一切影響しない(別関数・別用途)。
    """
    if not url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return url
        return urllib.parse.urlunsplit((
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path,
            parts.query,
            "",
        ))
    except ValueError:
        return url


def compute_article_id(source_id, raw_title, published_at_iso, canonical_url):
    """canonical_urlがあればそれのみを、なければ
    source_id + raw_title + published_at のフォールバック文字列をハッシュ化する。
    """
    if canonical_url:
        basis = canonical_url
    else:
        basis = f"{source_id}\n{raw_title or ''}\n{published_at_iso or ''}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def compute_content_hash(canonical_url, raw_title, raw_excerpt):
    """canonical_url + raw_title + raw_excerpt のSHA-256。nullは空文字として連結する。"""
    basis = f"{canonical_url or ''}\n{raw_title or ''}\n{raw_excerpt or ''}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ── raw_excerpt ───────────────────────────────────────────────────────────

def build_raw_excerpt(raw_summary):
    """取得済みの概要からHTMLタグを除去し、前後の空白を除去、最大200文字に切り詰める。
    本文の新規取得(スクレイピング)は行わない。値がなければNoneを返す。
    """
    if not raw_summary:
        return None
    text = re.sub(r"<[^>]+>", "", raw_summary).strip()
    if not text:
        return None
    return text[:200]


# ── source定義の解決 ──────────────────────────────────────────────────────

def resolve_source_meta(source_name, source_definitions):
    """item["source"](表示名)からsource_definitions.json上の対応エントリを検索し、
    記事へ付与するメタ情報を返す。解決できない場合は、どのソース名が解決できなかったか
    分かる明確なエラーを送出する(記事を黙って落とさない)。
    """
    for s in source_definitions:
        if s["name"] == source_name:
            return {
                "source_id": s["id"],
                "source_name": s["name"],
                "source_type": s["source_type"],
                "source_tier": s["source_tier"],
                "collection_method": s["collection_method"],
                "language": s["language"],
            }
    raise DailyJsonError(
        f"source_definitions.json に一致するソースが見つかりません: source name={source_name!r}"
    )


# ── 取得元別content usage policy (BL-032) ────────────────────────────────
# 正本: SOURCE_USAGE_POLICY.md Version 0.1 (Approved) 3章・5章・6章・7章・10章。

CONTENT_USAGE_MODES = (
    "structured_open",
    "feed_summary",
    "limited_feed_analysis",
    "metadata_only",
    "disabled_legal_review",
)

# AI評価(Gemini入力・facts取得・Brief/dashboard集計)の対象となるmode。
# feed_summary/limited_feed_analysisはGemini data-use gateを満たす場合のみ
# ここに含まれる(gate未充足時はcompute_effective_content_usage_modeが
# metadata_onlyへdowngradeするため、この集合の判定だけで十分)。
AI_ELIGIBLE_CONTENT_USAGE_MODES = ("structured_open", "feed_summary", "limited_feed_analysis")

GEMINI_DATA_USE_STATUSES = ("paid_verified", "unpaid", "unknown")

# BL-032: policy違反・gate未充足によるdowngrade理由の一元管理された識別子。
# 秘密情報・publisher本文を含まない、machine-readableな短い文字列のみを用いる。
DOWNGRADE_REASONS = (
    "gemini_gate_not_paid",
    "output_length_violation",
    "verbatim_long_match",
    "forbidden_translated_title",
    "missing_attribution",
    "forbidden_publisher_text_persistence",
    "invalid_mode_analysis_combination",
    "analysis_unavailable",
    "archive_attribution_snapshot_invalid",
)

# BL-032: structured_open分類のうち、attribution表示にURLを要する(=
# source_definitions.jsonの変更に伴い将来無効化し得る)source_idの集合。
# この集合に属するsourceは、schema v2 daily JSON生成時に実際に使用可能
# だったURLをpolicy.attribution_urlへsnapshotとして保存し、Archive再生成が
# 現在のsource_definitions.jsonではなくこのsnapshotだけを参照することで、
# source policyの後日変更に関わらず決定論的に同じ結果を再現できるようにする。
STRUCTURED_OPEN_ATTRIBUTION_URL_SOURCE_IDS = frozenset({"ncsc"})


def is_safe_attribution_url(url):
    """attribution_url snapshot専用の、http(s) URLの妥当性検証。

    fetch.safe_url()(記事リンク全般に対する、schemeプレフィックスだけの
    軽量な検証)とは意図的に別のロジックを持つ――ここではNCSCのOGL v3リンクの
    ようなactual clickable URLとしての妥当性、具体的には次のすべてを要求する:
    * 文字列であること
    * 前後の空白のみ許容し、ASCII制御文字(\\x00-\\x20)を含まないこと
    * schemeが`http`または`https`であること
    * netloc(ホスト部分)が空でないこと
    * hostnameが解析可能かつ空でないこと
    `https://`・`https:///missing-host`・`http://?query`のような、
    schemeプレフィックスだけでhostを持たない値はすべて拒否する。
    daily_json.pyはfetch.pyに依存しないため、検証ロジックをここで独立して
    持つ(fetch.safe_url()とロジックを共有しない。記事リンク全般の検証仕様は
    変更しない)。
    """
    if not isinstance(url, str):
        return False
    stripped = url.strip()
    if not stripped or re.search(r"[\x00-\x20]", stripped):
        return False
    try:
        parsed = urllib.parse.urlsplit(stripped)
        hostname = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not parsed.netloc or not hostname:
        return False
    return True

# BL-032: 出力fieldごとの文字数上限(一元管理、他ファイルへ複製しない)。
# summary/financial_impact(200文字)・reason(150文字)・category_reason(100文字)は
# 既存ARTICLE promptが既に「〜文字以内目安」として明示している値をそのまま
# 強制上限として再利用し、新たな閾値を二重定義しない。title_ja(60文字)・
# recommended_actionsの各要素(150文字、reasonの1文相当の粒度)は、既存prompt
# ガイドラインに数値の明記がないため、本Ticketで新たに決定した値である
# (簡潔な見出し・確認事項という既存の運用意図に基づく)。
OUTPUT_FIELD_MAX_CHARS = {
    "title_ja": 60,
    "summary": 200,
    "financial_impact": 200,
    "reason": 150,
    "category_reason": 100,
    "recommended_action_item": 150,
}

# BL-032: 原文(Geminiへ渡したtransient input)との長い連続完全一致を検出する
# 最小文字数。意味的近接性・異言語間の近接翻訳の完全検出は約束しない
# (追加モデルを使わない決定論的な文字列一致のみ)。短い一般語・source名・
# 製品名・CVE番号等の偶然一致による誤検知を避けるため、単純な短句より
# 長い40文字を採用する(本Ticketで決定)。
VERBATIM_LONG_MATCH_MIN_CHARS = 40

# BL-032: feed_summary／limited_feed_analysisのGemini入力(transient、保存しない)
# の最大文字数(SOURCE_USAGE_POLICY.md 3章B・C)。
TRANSIENT_INPUT_MAX_CHARS = 1000

# 検証対象field(title_jaは対象外。原文と自然に一致しない日本語見出しであり、
# limited_feed_analysisではそもそも生成禁止のため)。
_VERBATIM_CHECK_FIELDS = ("summary", "financial_impact", "reason", "category_reason")


def resolve_source_policy(source_definition):
    """source定義の`policy`オブジェクトを取り出す。存在しない、またはdictでない
    場合はDailyJsonErrorを送出する(暗黙のdefaultで補わない)。"""
    policy = source_definition.get("policy")
    if not isinstance(policy, dict):
        raise DailyJsonError(
            f"source policyが存在しません: id={source_definition.get('id')!r}"
        )
    return policy


def compute_effective_content_usage_mode(source_policy, gemini_data_use_status):
    """configured mode(source_policy['content_usage_mode'])とGemini data-use gate
    の状態から、実際に適用するeffective modeとdowngrade理由を決定する(BL-032)。

    戻り値: (effective_mode, downgrade_reason または None)
    """
    configured_mode = source_policy.get("content_usage_mode")
    if configured_mode not in CONTENT_USAGE_MODES:
        raise DailyJsonError(f"content_usage_modeが不正です: {configured_mode!r}")

    if configured_mode in ("feed_summary", "limited_feed_analysis"):
        if gemini_data_use_status != "paid_verified":
            return "metadata_only", "gemini_gate_not_paid"

    return configured_mode, None


def is_ai_eligible_content_usage_mode(effective_mode):
    """このeffective modeの記事がAI評価(Gemini呼び出し・facts取得・
    Today's Brief/dashboard集計)対象かどうかを判定する共通predicate。"""
    return effective_mode in AI_ELIGIBLE_CONTENT_USAGE_MODES


def normalize_for_verbatim_compare(text):
    """verbatim long-match検出用に、Unicode正規化(NFKC)・casefold・
    連続空白/改行の単一スペース圧縮を行う(意味解析はしない)。"""
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.casefold()
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def detect_verbatim_long_match(source_text, output_text, min_chars=VERBATIM_LONG_MATCH_MIN_CHARS):
    """source_text(Geminiへのtransient input)とoutput_text(AI出力の公開field)の
    間に、正規化後で長さmin_chars以上の連続完全一致があるかを決定論的に検出する。
    追加モデルは使わない。意味的近接性・異言語間の近接翻訳の完全検出は
    約束しない(このcontrolの限界として明示する)。
    """
    src = normalize_for_verbatim_compare(source_text)
    out = normalize_for_verbatim_compare(output_text)
    if len(out) < min_chars or not src:
        return False
    for start in range(len(out) - min_chars + 1):
        if out[start:start + min_chars] in src:
            return True
    return False


def validate_output_policy(effective_mode, source_text, analysis, attribution_ok=True):
    """AI出力(analysis: normalize_article_analysis()等で正規化済みのdict)が
    BL-032のoutput policyに違反していないか検証する。

    違反があれば (False, downgrade_reason) を、なければ (True, None) を返す。
    source_text: Geminiへ渡したtransient input(検証対象はfeed_summary/
    limited_feed_analysisのみ。structured_openは公式ライセンス上、原文との
    重なりを問題としない)。
    """
    if not isinstance(analysis, dict):
        return False, "invalid_mode_analysis_combination"

    if effective_mode == "limited_feed_analysis" and analysis.get("title_ja"):
        return False, "forbidden_translated_title"

    for field, limit in OUTPUT_FIELD_MAX_CHARS.items():
        if field == "recommended_action_item":
            continue
        value = analysis.get(field)
        if isinstance(value, str) and len(value) > limit:
            return False, "output_length_violation"

    for action in analysis.get("recommended_actions") or []:
        if isinstance(action, str) and len(action) > OUTPUT_FIELD_MAX_CHARS["recommended_action_item"]:
            return False, "output_length_violation"

    if effective_mode in ("feed_summary", "limited_feed_analysis"):
        candidates = [analysis.get(field) for field in _VERBATIM_CHECK_FIELDS]
        candidates += list(analysis.get("recommended_actions") or [])
        for value in candidates:
            if isinstance(value, str) and detect_verbatim_long_match(source_text, value):
                return False, "verbatim_long_match"

    if not attribution_ok:
        return False, "missing_attribution"

    return True, None


def build_item_content_policy(source_id, configured_mode, effective_mode, downgrade_reason):
    """daily JSON item(および記事分析パイプライン内)へ付与するpolicy状態を
    組み立てる。ai_eligibleはeffective_modeのみから機械的に決まる。"""
    return {
        "source_id": source_id,
        "configured_mode": configured_mode,
        "effective_mode": effective_mode,
        "ai_eligible": is_ai_eligible_content_usage_mode(effective_mode),
        "downgrade_reason": downgrade_reason,
    }


# ── 記事オブジェクトの構築 ─────────────────────────────────────────────────

def build_analysis_section(item, model):
    """item["ai_analysis_meta"](fetch.py の enrich_with_ai() が設定)を基に
    analysisオブジェクトを構築する。meta が存在しない場合は、AI分析が
    一切試行されなかった(not_attempted)ことを意味する。
    """
    meta = item.get("ai_analysis_meta")
    analysis = item.get("ai_analysis")

    if meta is None:
        return {
            "status": "not_attempted",
            "model": model,
            "prompt_version": ARTICLE_PROMPT_VERSION,
            "generated_at": None,
            "category": None,
            "category_version": CATEGORY_VERSION,
            "category_reason": None,
            "tags": [],
            "importance": None,
            "urgency": None,
            "summary": None,
            "financial_impact": None,
            "recommended_actions": [],
            "reason": None,
            "error_type": None,
            "http_status": None,
        }

    return {
        "status": meta["status"],
        "model": model,
        "prompt_version": ARTICLE_PROMPT_VERSION,
        "generated_at": meta.get("generated_at"),
        "category": analysis.get("category") if analysis else None,
        "category_version": CATEGORY_VERSION,
        "category_reason": analysis.get("category_reason") if analysis else None,
        "tags": analysis.get("tags", []) if analysis else [],
        "importance": analysis["importance"] if analysis else None,
        "urgency": analysis.get("urgency") if analysis else None,
        "summary": analysis["summary"] if analysis else None,
        "financial_impact": analysis["financial_impact"] if analysis else None,
        "recommended_actions": analysis["recommended_actions"] if analysis else [],
        "reason": analysis.get("reason") if analysis else None,
        "error_type": meta.get("error_type"),
        "http_status": meta.get("http_status"),
    }


SOURCES_WITH_SHARED_URL = {"cisa_kev"}
"""記事ごとに個別のURLを持たず、全件が同一の固定リンクを共有するsource_id。
CISA KEVは各記事の"link"がCISAの一覧ページ固定URLであり、記事間で重複するため、
IDの一意性をcanonical_urlに依存できない(compute_article_idはこの集合に含まれる
source_idについてはcanonical_urlを使わず、フォールバック方式のみを使用する)。"""


def compute_rule_flags(source_id):
    """source_idから機械的に判定できるrule_flagsを算出する。
    build_article_entry()とfetch.py側(Geminiへの入力構築)の両方から呼び出し、
    判定ロジックを一箇所に集約する。"""
    if source_id == "cisa_kev":
        return ["kev_entry"]
    return []


def build_article_entry(item, source_definitions, model, fetched_at):
    """収集済みの1記事(item)から、日次JSON用の記事オブジェクトを構築する。
    fetched_at: 収集処理完了直後の共通JST時刻(datetime、tz付き)。

    BL-032: item["content_policy"]は収集時(fetch.pyの
    annotate_item_content_policy())に設定済みの前提であり、欠落時は
    黙って補わずDailyJsonErrorを送出する。
    """
    source_meta = resolve_source_meta(item["source"], source_definitions)

    content_policy = item.get("content_policy")
    if not isinstance(content_policy, dict):
        raise DailyJsonError(
            f"item['content_policy']が設定されていません: source={item.get('source')!r}"
        )

    source_def = next(
        (s for s in source_definitions if s["id"] == source_meta["source_id"]), None
    )
    source_policy = resolve_source_policy(source_def) if source_def else {}

    # raw_excerpt(publisher由来の抜粋)は、downgradeされておらず、かつ
    # source policyがallow_excerpt_storageを許可する場合のみ保存する
    # (現状はstructured_openのみがallow_excerpt_storage=trueであり、
    # downgradeはfeed_summary/limited_feed_analysisのみに起きるため、
    # 実質的にstructured_openのみが対象になる)。
    allow_excerpt_storage = (
        bool(source_policy.get("allow_excerpt_storage"))
        and not content_policy.get("downgrade_reason")
    )

    raw_title = item.get("raw_title") or ""
    raw_excerpt = (
        build_raw_excerpt(item.get("raw_summary")) if allow_excerpt_storage else None
    )

    published_at_dt = item.get("published_at_jst")
    published_at_iso = published_at_dt.isoformat() if published_at_dt else None

    link = item.get("link") or None
    canonical_url = normalize_url_for_id(link)

    # canonical_urlが記事間で共有される(=一意な識別子として使えない)ソースは
    # IDの算出にcanonical_urlを使わず、フォールバック方式に統一する。
    id_basis_url = None if source_meta["source_id"] in SOURCES_WITH_SHARED_URL else canonical_url

    article_id = compute_article_id(
        source_meta["source_id"], raw_title, published_at_iso, id_basis_url
    )
    content_hash = compute_content_hash(canonical_url, raw_title, raw_excerpt)

    rule_flags = compute_rule_flags(source_meta["source_id"])

    # BL-032: structured_openのうちURL依存attribution(現状ncscのみ)を
    # 要するsourceについて、生成時に実際に使用可能だった(source_definitions
    # 側で設定済み、かつ安全なhttp(s) URL)attribution_urlだけをsnapshotとして
    # 保存する。Archive再生成は、このsnapshotだけを参照し、将来
    # source_definitions.jsonが変更されても保存済み結果を変えない
    # (digest_items_for_html/render_structured_open_attribution_html参照)。
    # 対象外のmode/source、またはURLが無効・欠落の場合はNoneのままとする
    # (Noneを保存すること自体は許容され、Archive再生成側がfail-closedに扱う)。
    attribution_url_snapshot = None
    if (
        content_policy["ai_eligible"]
        and content_policy["effective_mode"] == "structured_open"
        and source_meta["source_id"] in STRUCTURED_OPEN_ATTRIBUTION_URL_SOURCE_IDS
    ):
        candidate_url = source_policy.get("attribution_url")
        if is_safe_attribution_url(candidate_url):
            attribution_url_snapshot = candidate_url

    return {
        "id": article_id,
        "source_id": source_meta["source_id"],
        "source_name": source_meta["source_name"],
        "source_type": source_meta["source_type"],
        "source_tier": source_meta["source_tier"],
        "collection_method": source_meta["collection_method"],
        "language": source_meta["language"],

        "url": link,
        "canonical_url": canonical_url,

        "published_at": published_at_iso,
        "fetched_at": fetched_at.isoformat(),

        "title": item.get("title") or "",
        "raw_title": raw_title,
        "raw_excerpt": raw_excerpt,

        "content_hash": content_hash,
        "rule_flags": rule_flags,

        "policy": {
            "configured_mode": content_policy["configured_mode"],
            "effective_mode": content_policy["effective_mode"],
            "ai_eligible": content_policy["ai_eligible"],
            "downgrade_reason": content_policy.get("downgrade_reason"),
            "attribution_url": attribution_url_snapshot,
        },

        "analysis": build_analysis_section(item, model),

        # Ticket 12a: vulnerability_facts.build_facts_for_items()がitem["facts"]を
        # 設定する(fetch.pyのmain()内、Gemini記事分析より前)。未設定(=facts取得
        # 自体を経由していない呼び出し元)の場合もfactsキー自体は省略しない。
        # facts自体が壊れた値(例: {}や不正な型)で渡された場合はデフォルトへ
        # フォールバックせず、そのままvalidate_daily_digest()の検証へ委ねる
        # (キーが存在しない場合のみデフォルトを設定する)。
        "facts": item["facts"] if "facts" in item else {"cves": []},
    }


# ── run / counts / brief ─────────────────────────────────────────────────

def _entry_is_ai_eligible(entry):
    """schema v2のarticle entryがAI評価対象(policy.ai_eligible)かどうかを返す。
    v1由来のentry(policyキーがない、レガシー処理経由)は常にeligible扱いとし、
    v1の挙動(全記事が同一の共通処理を通っていた)を変えない。"""
    policy = entry.get("policy")
    if not isinstance(policy, dict):
        return True
    return bool(policy.get("ai_eligible", True))


def compute_run_meta(article_entries, force_schema_version=None):
    """BL-032: policy.ai_eligible=Falseの記事(metadata_only相当)は
    policy_excluded_countへ計上し、AI各件数(ai_attempted/success/fallback/
    failed/not_attempted)・run.statusの算出対象からは除外する
    (意図的なpolicy非評価と、AI処理自体の失敗を混同しないため)。
    total_items = policy_excluded_count + ai_eligible_count。

    どのentryも"policy"を持たない(過去のschema_version=1 daily JSONを
    そのまま渡した場合等)は完全にレガシー入力とみなし、policy_excluded_count/
    ai_eligible_countキー自体を含めない、v1と同一shapeの辞書を返す
    (v1 daily JSONの再検証・repair toolからの呼び出しでbyte-for-byte一致を保つ)。
    article_entriesが空の場合はentry自体から判定できないため、force_schema_version
    (build_daily_digest等、schema_versionを確定的に把握している呼び出し元が渡す)を
    優先する。force_schema_versionを渡さない直接呼び出しでは、空リストは
    レガシー(v1)として扱う(既存のrepair tool呼び出しの後方互換性のため)。
    """
    total = len(article_entries)
    if force_schema_version is not None:
        is_legacy_input = force_schema_version == LEGACY_SCHEMA_VERSION
    else:
        is_legacy_input = not any(isinstance(e.get("policy"), dict) for e in article_entries)

    if is_legacy_input:
        eligible_entries = article_entries
        ai_eligible_count = total
        policy_excluded_count = 0
    else:
        eligible_entries = [e for e in article_entries if _entry_is_ai_eligible(e)]
        ai_eligible_count = len(eligible_entries)
        policy_excluded_count = total - ai_eligible_count

    status_counts = {"success": 0, "fallback": 0, "failed": 0, "not_attempted": 0}
    for entry in eligible_entries:
        status_counts[entry["analysis"]["status"]] += 1

    ai_success = status_counts["success"]
    ai_fallback = status_counts["fallback"]
    ai_failed = status_counts["failed"]
    ai_not_attempted = status_counts["not_attempted"]
    ai_attempted = ai_success + ai_fallback + ai_failed
    success_or_fallback = ai_success + ai_fallback

    if ai_eligible_count == 0 or ai_success == ai_eligible_count:
        run_status = "success"
    elif (ai_fallback > 0 or ai_failed > 0 or ai_not_attempted > 0) and success_or_fallback > 0:
        run_status = "partial"
    elif ai_attempted > 0 and success_or_fallback == 0 and ai_failed > 0:
        run_status = "failed"
    elif ai_not_attempted == ai_eligible_count:
        run_status = "not_attempted"
    else:
        # 上記のいずれにも一致しない組み合わせは想定していないが、
        # 安全側としてpartial扱いにする
        run_status = "partial"

    result = {
        "status": run_status,
        "overwrite_policy": "replace",
        "total_items": total,
        "ai_attempted_count": ai_attempted,
        "ai_success_count": ai_success,
        "ai_fallback_count": ai_fallback,
        "ai_failed_count": ai_failed,
        "ai_not_attempted_count": ai_not_attempted,
    }
    if not is_legacy_input:
        result["policy_excluded_count"] = policy_excluded_count
        result["ai_eligible_count"] = ai_eligible_count
    return result


def compute_counts(article_entries):
    """BL-032: importance/urgency/categoryの各bucketは、policy.ai_eligible=True
    の記事(ai_eligible_count件)のみを対象に集計する。metadata_only相当の記事は
    「未判定」にも加算せず、集計そのものから除外する(意図的なpolicy非評価と
    AI処理の失敗を混同しない)。failed/not_attempted、またはフィールド自体が
    不正・欠落の場合はすべて「未判定」に集計する(Ticket 4以降の既存契約)。
    """
    importance_counts = {k: 0 for k in IMPORTANCE_KEYS}
    urgency_counts = {k: 0 for k in URGENCY_KEYS}
    category_counts = {k: 0 for k in CATEGORY_KEYS}

    for entry in article_entries:
        if not _entry_is_ai_eligible(entry):
            continue

        analysis = entry["analysis"]
        unattempted_or_failed = analysis["status"] in ("failed", "not_attempted")

        importance = analysis["importance"]
        if unattempted_or_failed or importance not in IMPORTANCE_VALUES:
            importance_counts["未判定"] += 1
        else:
            importance_counts[importance] += 1

        urgency = analysis.get("urgency")
        if unattempted_or_failed or urgency not in URGENCY_VALUES:
            urgency_counts["未判定"] += 1
        else:
            urgency_counts[urgency] += 1

        category = analysis.get("category")
        if unattempted_or_failed or category not in CATEGORY_VALUES:
            category_counts["未判定"] += 1
        else:
            category_counts[category] += 1

    return {
        "importance": importance_counts,
        "urgency": urgency_counts,
        "category": category_counts,
    }


def build_brief_section(brief_result, model):
    """fetch.py の build_todays_brief() の戻り値
    ({"overview":..., "important_highlights":..., "discussion_points":...,
    "check_items":..., "status":..., "error_type":..., "http_status":...}) から
    Today's Brief用のbriefオブジェクトを構築する。

    BL-021 extractive contractではbrief_result内のmodel/prompt_versionを
    composition metadataとして保存する。キーが無い旧呼び出しでは現行の
    BRIEF_MODEL/BRIEF_PROMPT_VERSIONを使う。

    brief_resultに4要素のキーが無い場合(Ticket 3時点の旧
    {"lines":...}形式など)は、.get()のデフォルトによりoverview=None・
    各配列=[]として扱う(not_attempted/failed相当の空データとして安全側に倒す)。
    """
    return {
        "status": brief_result["status"],
        "model": brief_result.get("model") or BRIEF_MODEL,
        "prompt_version": brief_result.get("prompt_version") or BRIEF_PROMPT_VERSION,
        "overview": brief_result.get("overview"),
        "important_highlights": brief_result.get("important_highlights") or [],
        "discussion_points": brief_result.get("discussion_points") or [],
        "check_items": brief_result.get("check_items") or [],
        "error_type": brief_result.get("error_type"),
    }


# ── 日次JSON全体の構築 ────────────────────────────────────────────────────

def build_daily_digest(items, brief_result, source_definitions, model, fetched_at, generated_at):
    """収集・分析結果一式から、日次JSON全体の辞書を組み立てる。
    fetched_at/generated_at: いずれもJSTのtz付きdatetime。
    """
    article_entries = [
        build_article_entry(item, source_definitions, model, fetched_at)
        for item in items
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "digest_date": generated_at.strftime("%Y-%m-%d"),
        "generated_at": generated_at.isoformat(),
        "generator": {
            "application": "security-digest",
            "model": model,
            "article_prompt_version": ARTICLE_PROMPT_VERSION,
            "brief_prompt_version": BRIEF_PROMPT_VERSION,
        },
        "run": compute_run_meta(article_entries, force_schema_version=SCHEMA_VERSION),
        "counts": compute_counts(article_entries),
        "brief": build_brief_section(brief_result, model),
        "items": article_entries,
    }


# ── 検証 ──────────────────────────────────────────────────────────────────

def validate_daily_digest(digest):
    """保存直前の日次JSONに対する最低限のスキーマ・件数整合性検証。
    不正があれば DailyJsonError を送出する(黙って無視しない)。

    BL-032: schema_version 1(レガシー)と2(現行、policy_excluded_count/
    ai_eligible_countによるAI評価対象の分離)を区別して検証する。
    過去のschema_version=1 daily JSONの読み込み(scan_daily_digest_files等)は
    この関数を経由しないため、ここでのv1分岐は主に本関数自体の後方互換性
    (将来の再検証・修復ツール等からの呼び出し)のためのものである。
    """
    schema_version = digest.get("schema_version")
    if not isinstance(schema_version, int):
        raise DailyJsonError(
            f"schema_versionが整数ではありません: {schema_version!r}"
        )
    if schema_version not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
        raise DailyJsonError(
            f"schema_versionが不正です: {schema_version!r} "
            f"(許容値: {LEGACY_SCHEMA_VERSION}, {SCHEMA_VERSION})"
        )

    digest_date = digest.get("digest_date")
    if not isinstance(digest_date, str) or not DIGEST_DATE_RE.fullmatch(digest_date):
        raise DailyJsonError(f"digest_dateがYYYY-MM-DD形式ではありません: {digest_date!r}")

    if not digest.get("generated_at"):
        raise DailyJsonError("generated_atがありません")

    items = digest.get("items")
    if not isinstance(items, list):
        raise DailyJsonError("itemsが配列ではありません")

    run = digest.get("run") or {}
    total_items = run.get("total_items")
    if total_items != len(items):
        raise DailyJsonError(
            f"run.total_items({total_items!r})とitems件数({len(items)})が一致しません"
        )

    if schema_version == LEGACY_SCHEMA_VERSION:
        ai_denominator = total_items
    else:
        policy_excluded_count = run.get("policy_excluded_count")
        ai_eligible_count = run.get("ai_eligible_count")
        if not isinstance(policy_excluded_count, int) or policy_excluded_count < 0:
            raise DailyJsonError(
                f"run.policy_excluded_countが不正です: {policy_excluded_count!r}"
            )
        if not isinstance(ai_eligible_count, int) or ai_eligible_count < 0:
            raise DailyJsonError(f"run.ai_eligible_countが不正です: {ai_eligible_count!r}")
        if policy_excluded_count + ai_eligible_count != total_items:
            raise DailyJsonError(
                f"run.policy_excluded_count({policy_excluded_count})+"
                f"run.ai_eligible_count({ai_eligible_count})がtotal_items"
                f"({total_items})と一致しません"
            )
        ai_denominator = ai_eligible_count

    ai_sum = (
        run.get("ai_success_count", 0) + run.get("ai_fallback_count", 0)
        + run.get("ai_failed_count", 0) + run.get("ai_not_attempted_count", 0)
    )
    if ai_sum != ai_denominator:
        raise DailyJsonError(
            f"AI各件数の合計({ai_sum})が{'total_items' if schema_version == LEGACY_SCHEMA_VERSION else 'ai_eligible_count'}"
            f"({ai_denominator})と一致しません"
        )

    if run.get("status") not in VALID_RUN_STATUSES:
        raise DailyJsonError(
            f"run.statusが不正です: {run.get('status')!r} (許容値: {sorted(VALID_RUN_STATUSES)})"
        )

    counts = digest.get("counts") or {}
    counts_denominator = total_items if schema_version == LEGACY_SCHEMA_VERSION else ai_denominator
    for key in ("importance", "urgency", "category"):
        bucket = counts.get(key) or {}
        bucket_sum = sum(bucket.values())
        if bucket_sum != counts_denominator:
            raise DailyJsonError(
                f"counts.{key}の合計({bucket_sum})が{counts_denominator}と一致しません"
            )

    seen_ids = set()
    for i, item in enumerate(items):
        item_id = item.get("id")
        if not item_id:
            raise DailyJsonError(f"items[{i}].idが空です")
        if item_id in seen_ids:
            raise DailyJsonError(f"items[{i}].idが重複しています: {item_id!r}")
        seen_ids.add(item_id)

        if not item.get("source_id"):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): source_idが空です")

        if schema_version == SCHEMA_VERSION:
            policy = item.get("policy")
            if not isinstance(policy, dict):
                raise DailyJsonError(f"items[{i}] (id={item_id!r}): policyが存在しません")
            if policy.get("configured_mode") not in CONTENT_USAGE_MODES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.configured_modeが不正です: "
                    f"{policy.get('configured_mode')!r}"
                )
            if policy.get("effective_mode") not in CONTENT_USAGE_MODES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.effective_modeが不正です: "
                    f"{policy.get('effective_mode')!r}"
                )
            if not isinstance(policy.get("ai_eligible"), bool):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.ai_eligibleがboolではありません: "
                    f"{policy.get('ai_eligible')!r}"
                )
            if policy.get("ai_eligible") != is_ai_eligible_content_usage_mode(
                policy.get("effective_mode")
            ):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.ai_eligibleがeffective_modeと矛盾しています"
                )
            downgrade_reason = policy.get("downgrade_reason")
            if downgrade_reason is not None and downgrade_reason not in DOWNGRADE_REASONS:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.downgrade_reasonが不正です: "
                    f"{downgrade_reason!r}"
                )

            # BL-032: policy.attribution_urlは、Archive再生成時にsource_definitions
            # の後日変更へ左右されないための生成時snapshotである。全v2 entryで
            # None|strのみ許容し(型不正は暗黙のdefaultで補わない)、URL依存
            # attribution(現状ncscのみ)を要するsourceでai_eligible=trueの
            # 場合は、安全なhttp(s) URLとして存在することを必須とする(欠落・
            # 不正なsnapshotのまま保存することを許さない)。
            attribution_url = policy.get("attribution_url")
            if attribution_url is not None and not isinstance(attribution_url, str):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): policy.attribution_urlが"
                    f"None/strではありません: {attribution_url!r}"
                )
            if (
                policy.get("ai_eligible")
                and policy.get("effective_mode") == "structured_open"
                and item.get("source_id") in STRUCTURED_OPEN_ATTRIBUTION_URL_SOURCE_IDS
                and not is_safe_attribution_url(attribution_url)
            ):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): source_id="
                    f"{item.get('source_id')!r}はpolicy.attribution_urlに安全な"
                    f"http(s) URLのsnapshotが必要ですが、欠落または不正です: "
                    f"{attribution_url!r}"
                )

        analysis = item.get("analysis")
        if not isinstance(analysis, dict):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): analysisが存在しません")

        if analysis.get("status") not in VALID_ANALYSIS_STATUSES:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.statusが不正です: "
                f"{analysis.get('status')!r} (許容値: {sorted(VALID_ANALYSIS_STATUSES)})"
            )

        # Ticket 4: category/importance/urgency/tagsは、値が設定されている場合のみ
        # 許容値内であることを確認する(nullは常に許容。success/fallback/failed/
        # not_attemptedいずれの状態でも起こり得るため、statusでは分岐しない)。
        category = analysis.get("category")
        if category is not None and category not in CATEGORY_VALUES:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.categoryが不正です: {category!r}"
            )

        importance = analysis.get("importance")
        if importance is not None and importance not in IMPORTANCE_VALUES:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.importanceが不正です: {importance!r}"
            )

        urgency = analysis.get("urgency")
        if urgency is not None and urgency not in URGENCY_VALUES:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.urgencyが不正です: {urgency!r}"
            )

        tags = analysis.get("tags", [])
        if not isinstance(tags, list):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): analysis.tagsが配列ではありません")
        if len(tags) > MAX_TAGS:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.tagsが{MAX_TAGS}件を超えています: {tags!r}"
            )
        if len(set(tags)) != len(tags):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): analysis.tagsに重複があります: {tags!r}")
        invalid_tags = [t for t in tags if t not in TAG_ALLOWLIST]
        if invalid_tags:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.tagsに許可外の値があります: {invalid_tags!r}"
            )

        # Ticket 12a: facts(CVE/CVSS/KEVファクト)の最低限の構造検証。
        # 値の意味(nvd.status等)まではここでは検証せず、構造・型だけを確認する。
        facts = item.get("facts")
        if not isinstance(facts, dict):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): factsが存在しません")
        cves = facts.get("cves")
        if not isinstance(cves, list):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): facts.cvesが配列ではありません")
        for j, cve_fact in enumerate(cves):
            if not isinstance(cve_fact, dict) or not cve_fact.get("cve_id"):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].cve_idが不正です: {cve_fact!r}"
                )

            cve_id = cve_fact["cve_id"]
            if not isinstance(cve_id, str) or not FACTS_CVE_ID_RE.fullmatch(cve_id):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].cve_idがCVE形式ではありません: {cve_id!r}"
                )

            nvd = cve_fact.get("nvd")
            if not isinstance(nvd, dict):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].nvdがオブジェクトではありません: {nvd!r}"
                )
            if nvd.get("status") not in VALID_NVD_STATUSES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].nvd.statusが不正です: "
                    f"{nvd.get('status')!r} (許容値: {sorted(VALID_NVD_STATUSES)})"
                )
            if nvd.get("retrieval") not in VALID_FACTS_RETRIEVAL_VALUES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].nvd.retrievalが不正です: "
                    f"{nvd.get('retrieval')!r} (許容値: {sorted(VALID_FACTS_RETRIEVAL_VALUES)})"
                )

            kev = cve_fact.get("kev")
            if not isinstance(kev, dict):
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].kevがオブジェクトではありません: {kev!r}"
                )
            if kev.get("status") not in VALID_KEV_STATUSES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].kev.statusが不正です: "
                    f"{kev.get('status')!r} (許容値: {sorted(VALID_KEV_STATUSES)})"
                )
            if kev.get("retrieval") not in VALID_FACTS_RETRIEVAL_VALUES:
                raise DailyJsonError(
                    f"items[{i}] (id={item_id!r}): facts.cves[{j}].kev.retrievalが不正です: "
                    f"{kev.get('retrieval')!r} (許容値: {sorted(VALID_FACTS_RETRIEVAL_VALUES)})"
                )

    # Ticket 8: Today's Brief (4要素) の最低限の検証。
    # この検証は保存直前(save_daily_digest)にのみ適用され、scan_daily_digest_files()
    # による既存日次JSONの走査(index再構築)では呼び出されないため、Ticket 3時点の
    # 旧brief形式のファイルがディスク上に残っていても、それらの読み込みには影響しない。
    brief = digest.get("brief")
    if not isinstance(brief, dict):
        raise DailyJsonError("briefがオブジェクトではありません")

    brief_status = brief.get("status")
    if brief_status not in VALID_BRIEF_STATUSES:
        raise DailyJsonError(
            f"brief.statusが不正です: {brief_status!r} (許容値: {sorted(VALID_BRIEF_STATUSES)})"
        )

    if not isinstance(brief.get("prompt_version"), str) or not brief.get("prompt_version"):
        raise DailyJsonError(f"brief.prompt_versionが文字列ではありません: {brief.get('prompt_version')!r}")

    overview = brief.get("overview")
    if overview is not None and not isinstance(overview, str):
        raise DailyJsonError(f"brief.overviewが文字列でもnullでもありません: {overview!r}")

    brief_list_specs = (
        ("important_highlights", BRIEF_MAX_HIGHLIGHTS),
        ("discussion_points", BRIEF_MAX_DISCUSSION_POINTS),
        ("check_items", BRIEF_MAX_CHECK_ITEMS),
    )
    for key, max_items in brief_list_specs:
        values = brief.get(key)
        if not isinstance(values, list):
            raise DailyJsonError(f"brief.{key}が配列ではありません: {values!r}")
        if len(values) > max_items:
            raise DailyJsonError(f"brief.{key}が{max_items}件を超えています: {len(values)}件")
        for i, v in enumerate(values):
            if not isinstance(v, str) or not v.strip():
                raise DailyJsonError(f"brief.{key}[{i}]が空でない文字列ではありません: {v!r}")

    if brief_status == "success":
        if not overview or not overview.strip():
            raise DailyJsonError("brief.status=successですが、brief.overviewが空です")
    else:
        # failed/not_attempted時は、前日流用や固定一般論の混入を防ぐため、
        # overview=null・各配列=[]であることを明示的に要求する。
        if overview is not None:
            raise DailyJsonError(
                f"brief.status={brief_status!r}ですが、brief.overviewがnullではありません: {overview!r}"
            )
        for key, _ in brief_list_specs:
            if brief.get(key):
                raise DailyJsonError(
                    f"brief.status={brief_status!r}ですが、brief.{key}が空配列ではありません: {brief.get(key)!r}"
                )

    return True


def validate_daily_digest_for_archive_read(digest):
    """Archive読込・再生成専用のschema-version-awareなvalidator(BL-032)。

    validate_daily_digest()(保存直前専用、Ticket 8時点のコメントどおり
    scan_daily_digest_files()等の既存日次JSON走査からは経由されない前提)を
    Archive生成の読込前チェックにもそのまま流用すると、schema v1(レガシー)の
    実在ファイルへ現行の閾値(例: BRIEF_MAX_CHECK_ITEMS)・enum値・
    fieldの有無を遡及適用してしまい、生成当時は正当だった実データ
    (例: 昔のBrief件数上限で保存されたcheck_items)がArchive生成対象から
    誤って除外される。

    * schema v2(現行)は、保存直前と完全に同じstrict validation
      (validate_daily_digest()、NCSC attribution snapshot検証を含む)を
      そのまま適用する――現行生成物に対する検証は一切緩めない。
    * schema v1(レガシー)は、現在の閾値・enum・field構成を遡及的に
      適用せず、安全にHTMLへ描画するための最低限の構造だけを検証する:
      トップレベル型、digest_dateが実在する暦日であること、items配列と
      その要素がdictであること、brief各fieldの型(overviewはstr/null、
      important_highlights/discussion_points/check_itemsはlist/null、
      list要素はstr)、および archive_summary_from_digest() が参照する
      run(dict/null、total_itemsはbool以外の0以上int/null)・
      counts(dict/null、counts.importance[dict/null]、
      counts.importance["高"]はbool以外の0以上int/null)の型(round 6)。
      件数の相互整合性・enum値・件数上限は引き続き適用しない。
    """
    schema_version = digest.get("schema_version")
    if not isinstance(schema_version, int):
        raise DailyJsonError(f"schema_versionが整数ではありません: {schema_version!r}")
    if schema_version not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
        raise DailyJsonError(
            f"schema_versionが不正です: {schema_version!r} "
            f"(許容値: {LEGACY_SCHEMA_VERSION}, {SCHEMA_VERSION})"
        )

    if schema_version == SCHEMA_VERSION:
        validate_daily_digest(digest)
        return

    digest_date = digest.get("digest_date")
    if not isinstance(digest_date, str) or not DIGEST_DATE_RE.fullmatch(digest_date):
        raise DailyJsonError(f"digest_dateがYYYY-MM-DD形式ではありません: {digest_date!r}")
    try:
        datetime.date.fromisoformat(digest_date)
    except ValueError as e:
        raise DailyJsonError(f"digest_dateが実在する暦日ではありません: {digest_date!r}") from e
    if not digest.get("generated_at"):
        raise DailyJsonError("generated_atがありません")

    items = digest.get("items")
    if not isinstance(items, list):
        raise DailyJsonError("itemsが配列ではありません")
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise DailyJsonError(f"items[{i}]がオブジェクトではありません")

    # BL-032 (round 6): schema v1のrun/countsは、現行の件数整合性・enum
    # (validate_daily_digest()相当)は遡及適用しないが、archive_summary_from_digest()
    # 等の下流処理が前提とする最低限の型(dict / 非boolのint / 0以上)だけは
    # ここで保証する。欠落・nullは既存fallback(run.get("total_items") or
    # len(items)等)が安全なため、値そのものが存在する場合のみ検証する。
    run = digest.get("run")
    if run is not None:
        if not isinstance(run, dict):
            raise DailyJsonError(f"runがオブジェクトでもnullでもありません: {run!r}")
        total_items = run.get("total_items")
        if total_items is not None and (
            isinstance(total_items, bool)
            or not isinstance(total_items, int)
            or total_items < 0
        ):
            raise DailyJsonError(
                f"run.total_itemsが0以上の整数でもnullでもありません: {total_items!r}"
            )

    counts = digest.get("counts")
    if counts is not None:
        if not isinstance(counts, dict):
            raise DailyJsonError(f"countsがオブジェクトでもnullでもありません: {counts!r}")
        importance = counts.get("importance")
        if importance is not None:
            if not isinstance(importance, dict):
                raise DailyJsonError(
                    f"counts.importanceがオブジェクトでもnullでもありません: {importance!r}"
                )
            high_count = importance.get("高")
            if high_count is not None and (
                isinstance(high_count, bool)
                or not isinstance(high_count, int)
                or high_count < 0
            ):
                raise DailyJsonError(
                    f"counts.importance['高']が0以上の整数でもnullでもありません: {high_count!r}"
                )

    brief = digest.get("brief")
    if brief is not None and not isinstance(brief, dict):
        raise DailyJsonError(f"briefがオブジェクトでもnullでもありません: {brief!r}")
    if isinstance(brief, dict):
        overview = brief.get("overview")
        if overview is not None and not isinstance(overview, str):
            raise DailyJsonError(f"brief.overviewが文字列でもnullでもありません: {overview!r}")
        for key in ("important_highlights", "discussion_points", "check_items"):
            values = brief.get(key)
            if values is None:
                continue
            if not isinstance(values, list):
                raise DailyJsonError(f"brief.{key}が配列でもnullでもありません: {values!r}")
            for i, v in enumerate(values):
                if not isinstance(v, str):
                    raise DailyJsonError(f"brief.{key}[{i}]が文字列ではありません: {v!r}")


def validate_index(index):
    """data/index.json 保存前の最低限の検証。"""
    if not isinstance(index.get("schema_version"), int):
        raise DailyJsonError(
            f"index.json: schema_versionが整数ではありません: {index.get('schema_version')!r}"
        )

    digests = index.get("digests")
    if not isinstance(digests, list):
        raise DailyJsonError("index.json: digestsが配列ではありません")

    seen_dates = set()
    for i, d in enumerate(digests):
        date = d.get("digest_date")
        if not date:
            raise DailyJsonError(f"index.json: digests[{i}].digest_dateがありません")
        if date in seen_dates:
            raise DailyJsonError(f"index.json: digest_dateが重複しています: {date!r}")
        seen_dates.add(date)

    return True


# ── 原子的な保存 ──────────────────────────────────────────────────────────

def atomic_write_json(path, data, validator=None):
    """一時ファイル経由でJSONを原子的に保存する。
    1. 保存先と同じディレクトリに一時ファイルを作成
    2. UTF-8でJSONを書き込む(ensure_ascii=False, indent=2, 末尾改行あり)
    3. 一時ファイルをjson.load()で再読込
    4. validatorが指定されていれば、再読込したデータで検証
    5. os.replace()で本番ファイルへ原子的に置換
    6. 失敗時は一時ファイルを削除
    7. 例外は黙って無視せず送出する(呼び出し元は本番ファイルが未変更のまま失敗を検知できる)
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path_str = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_path_str)

    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

        with tmp_path.open("r", encoding="utf-8") as f:
            reloaded = json.load(f)

        if validator is not None:
            validator(reloaded)

        os.replace(str(tmp_path), str(path))
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def save_daily_digest(digest, data_dir):
    path = Path(data_dir) / f"{digest['digest_date']}.json"
    atomic_write_json(path, digest, validator=validate_daily_digest)
    return path


def save_index(data_dir, generated_at):
    index = build_index(data_dir, generated_at)
    path = Path(data_dir) / "index.json"
    atomic_write_json(path, index, validator=validate_index)
    return path


# ── index.json の再構築 ───────────────────────────────────────────────────

def scan_daily_digest_files(data_dir):
    """data/配下の日次JSON(YYYY-MM-DD.json)を走査し、digest_date降順の
    indexエントリ一覧を返す。一時ファイル・index.json自体は対象外。
    不正な既存日次JSONを検出した場合は、対象ファイルが分かるエラーを送出する
    (黙って無視しない)。
    """
    data_dir = Path(data_dir)
    if not data_dir.exists():
        return []

    entries = []
    for path in sorted(data_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        if not DAILY_FILENAME_RE.fullmatch(path.name):
            continue  # 一時ファイル等、日次JSON以外の命名は対象外

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise DailyJsonError(f"{path} を読み込めません: {e}") from e

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise DailyJsonError(f"{path} のJSON解析に失敗しました: {e}") from e

        if not isinstance(data, dict):
            raise DailyJsonError(f"{path}: トップレベルがオブジェクトではありません")
        if "schema_version" not in data:
            raise DailyJsonError(f"{path}: schema_versionがありません")
        if "digest_date" not in data:
            raise DailyJsonError(f"{path}: digest_dateがありません")
        if not data.get("generated_at"):
            raise DailyJsonError(f"{path}: generated_atが欠落しています")

        run = data.get("run") or {}
        counts = data.get("counts") or {}

        entries.append({
            "digest_date": data["digest_date"],
            "path": f"data/{path.name}",
            "generated_at": data["generated_at"],
            "total_items": run.get("total_items", 0),
            "high_count": (counts.get("importance") or {}).get("高", 0),
            "ai_run_status": run.get("status"),
            "archive_path": None,
        })

    entries.sort(key=lambda e: e["digest_date"], reverse=True)
    return entries


def build_index(data_dir, generated_at):
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": generated_at.isoformat(),
        "digests": scan_daily_digest_files(data_dir),
    }


# ── 統合エントリポイント ──────────────────────────────────────────────────

def generate_and_save_daily_digest(
    items, brief_result, source_definitions, model, fetched_at, generated_at, data_dir=None,
):
    """日次JSON(data/YYYY-MM-DD.json)を構築・保存し、続けてdata/index.jsonを
    再構築・保存する。保存した日次JSONの辞書を返す。"""
    data_dir = Path(data_dir) if data_dir is not None else DATA_DIR

    digest = build_daily_digest(items, brief_result, source_definitions, model, fetched_at, generated_at)
    save_daily_digest(digest, data_dir)
    save_index(data_dir, generated_at)
    return digest
