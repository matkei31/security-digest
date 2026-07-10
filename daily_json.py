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
import urllib.parse
from pathlib import Path

# ── パス ──────────────────────────────────────────────────────────────────
# 実行時のカレントディレクトリに依存させず、このファイルの配置場所を基準にする。
REPOSITORY_ROOT = Path(__file__).resolve().parent
DATA_DIR = REPOSITORY_ROOT / "data"

# ── バージョン・スキーマ定数(一元管理) ───────────────────────────────────────
SCHEMA_VERSION = 1
ARTICLE_PROMPT_VERSION = "article-analysis-v1"
BRIEF_PROMPT_VERSION = "executive-summary-v1"
CATEGORY_VERSION = "v1"

VALID_RUN_STATUSES = {"success", "partial", "failed", "not_attempted"}
VALID_ANALYSIS_STATUSES = {"success", "fallback", "failed", "not_attempted"}
VALID_BRIEF_STATUSES = {"success", "failed", "not_attempted"}
VALID_ERROR_TYPES = {
    "rate_limit", "quota_exceeded", "billing_or_balance", "schema_parse_error",
    "network_error", "api_error", "unknown",
    "resource_exhausted", "permission_denied",
}

IMPORTANCE_KEYS = ("高", "中", "低", "未判定")
URGENCY_KEYS = ("本日確認", "今週確認", "参考", "未判定")
CATEGORY_KEYS = (
    "脆弱性・パッチ", "攻撃・脅威動向", "インシデント", "規制・ガバナンス",
    "クラウド・サプライチェーン", "AI・新技術リスク", "その他", "未判定",
)

JST = datetime.timezone(datetime.timedelta(hours=9))

DAILY_FILENAME_RE = re.compile(r"\d{4}-\d{2}-\d{2}\.json")
DIGEST_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


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

def parse_date_to_jst(date_string):
    """RSS/API由来の日付文字列を、タイムゾーン情報を保持したままJSTへ正規化する。
    解析できない場合、またはオフセット情報がなく正確な日時を特定できない場合はNoneを返す。
    fetch.pyのparse_date()(ソート・カットオフ判定用、tzinfoを破棄する実装)とは別関数であり、
    既存のRSS取得・フィルタロジックには一切影響しない。
    """
    if not date_string:
        return None
    s = date_string.strip()

    # 明示的にUTCを示すサフィックス(Z / GMT / UTC)
    utc_suffix_formats = (
        "%Y-%m-%dT%H:%M:%SZ",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S UTC",
    )
    for fmt in utc_suffix_formats:
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).astimezone(JST)
        except ValueError:
            continue

    # オフセット付き形式(%z)はstrptimeがそのままtzinfoを設定する
    offset_formats = (
        "%a, %d %b %Y %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M%z",
    )
    for fmt in offset_formats:
        try:
            dt = datetime.datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                continue
            return dt.astimezone(JST)
        except ValueError:
            continue

    # 日付のみ(時刻・オフセットなし)は正確な日時を特定できないためNone
    return None


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
        "category": None,
        "category_version": CATEGORY_VERSION,
        "category_reason": None,
        "tags": [],
        "importance": analysis["importance"] if analysis else None,
        "urgency": None,
        "summary": analysis["summary"] if analysis else None,
        "financial_impact": analysis["financial_impact"] if analysis else None,
        "recommended_actions": analysis["recommended_actions"] if analysis else [],
        "reason": None,
        "error_type": meta.get("error_type"),
        "http_status": meta.get("http_status"),
    }


SOURCES_WITH_SHARED_URL = {"cisa_kev"}
"""記事ごとに個別のURLを持たず、全件が同一の固定リンクを共有するsource_id。
CISA KEVは各記事の"link"がCISAの一覧ページ固定URLであり、記事間で重複するため、
IDの一意性をcanonical_urlに依存できない(compute_article_idはこの集合に含まれる
source_idについてはcanonical_urlを使わず、フォールバック方式のみを使用する)。"""


def build_article_entry(item, source_definitions, model, fetched_at):
    """収集済みの1記事(item)から、日次JSON用の記事オブジェクトを構築する。
    fetched_at: 収集処理完了直後の共通JST時刻(datetime、tz付き)。
    """
    source_meta = resolve_source_meta(item["source"], source_definitions)

    raw_title = item.get("raw_title") or ""
    raw_excerpt = build_raw_excerpt(item.get("raw_summary"))

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

    rule_flags = []
    if source_meta["source_id"] == "cisa_kev":
        rule_flags.append("kev_entry")

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

        "analysis": build_analysis_section(item, model),
    }


# ── run / counts / brief ─────────────────────────────────────────────────

def compute_run_meta(article_entries):
    total = len(article_entries)
    status_counts = {"success": 0, "fallback": 0, "failed": 0, "not_attempted": 0}
    for entry in article_entries:
        status_counts[entry["analysis"]["status"]] += 1

    ai_success = status_counts["success"]
    ai_fallback = status_counts["fallback"]
    ai_failed = status_counts["failed"]
    ai_not_attempted = status_counts["not_attempted"]
    ai_attempted = ai_success + ai_fallback + ai_failed
    success_or_fallback = ai_success + ai_fallback

    if total == 0 or ai_success == total:
        run_status = "success"
    elif (ai_fallback > 0 or ai_failed > 0 or ai_not_attempted > 0) and success_or_fallback > 0:
        run_status = "partial"
    elif ai_attempted > 0 and success_or_fallback == 0 and ai_failed > 0:
        run_status = "failed"
    elif ai_not_attempted == total:
        run_status = "not_attempted"
    else:
        # 上記のいずれにも一致しない組み合わせは想定していないが、
        # 安全側としてpartial扱いにする
        run_status = "partial"

    return {
        "status": run_status,
        "overwrite_policy": "replace",
        "total_items": total,
        "ai_attempted_count": ai_attempted,
        "ai_success_count": ai_success,
        "ai_fallback_count": ai_fallback,
        "ai_failed_count": ai_failed,
        "ai_not_attempted_count": ai_not_attempted,
    }


def compute_counts(article_entries):
    importance_counts = {k: 0 for k in IMPORTANCE_KEYS}
    urgency_counts = {k: 0 for k in URGENCY_KEYS}
    category_counts = {k: 0 for k in CATEGORY_KEYS}

    for entry in article_entries:
        analysis = entry["analysis"]
        importance = analysis["importance"]
        if analysis["status"] in ("failed", "not_attempted") or importance not in ("高", "中", "低"):
            importance_counts["未判定"] += 1
        else:
            importance_counts[importance] += 1

        # Ticket 3ではurgency/categoryをGeminiから生成しないため、常に未判定に集計する
        urgency_counts["未判定"] += 1
        category_counts["未判定"] += 1

    return {
        "importance": importance_counts,
        "urgency": urgency_counts,
        "category": category_counts,
    }


def build_brief_section(exec_result, model):
    """fetch.py の build_executive_summary() の戻り値
    ({"lines":..., "status":..., "error_type":..., "http_status":...}) から
    Today's Brief用のbriefオブジェクトを構築する。"""
    return {
        "status": exec_result["status"],
        "model": model,
        "prompt_version": BRIEF_PROMPT_VERSION,
        "overview": None,
        "important_highlights": exec_result["lines"] or [],
        "discussion_points": [],
        "check_items": [],
        "error_type": exec_result.get("error_type"),
    }


# ── 日次JSON全体の構築 ────────────────────────────────────────────────────

def build_daily_digest(items, exec_result, source_definitions, model, fetched_at, generated_at):
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
        "run": compute_run_meta(article_entries),
        "counts": compute_counts(article_entries),
        "brief": build_brief_section(exec_result, model),
        "items": article_entries,
    }


# ── 検証 ──────────────────────────────────────────────────────────────────

def validate_daily_digest(digest):
    """保存直前の日次JSONに対する最低限のスキーマ・件数整合性検証。
    不正があれば DailyJsonError を送出する(黙って無視しない)。
    """
    if not isinstance(digest.get("schema_version"), int):
        raise DailyJsonError(
            f"schema_versionが整数ではありません: {digest.get('schema_version')!r}"
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

    ai_sum = (
        run.get("ai_success_count", 0) + run.get("ai_fallback_count", 0)
        + run.get("ai_failed_count", 0) + run.get("ai_not_attempted_count", 0)
    )
    if ai_sum != total_items:
        raise DailyJsonError(
            f"AI各件数の合計({ai_sum})がtotal_items({total_items})と一致しません"
        )

    if run.get("status") not in VALID_RUN_STATUSES:
        raise DailyJsonError(
            f"run.statusが不正です: {run.get('status')!r} (許容値: {sorted(VALID_RUN_STATUSES)})"
        )

    counts = digest.get("counts") or {}
    for key in ("importance", "urgency", "category"):
        bucket = counts.get(key) or {}
        bucket_sum = sum(bucket.values())
        if bucket_sum != total_items:
            raise DailyJsonError(
                f"counts.{key}の合計({bucket_sum})がtotal_items({total_items})と一致しません"
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

        analysis = item.get("analysis")
        if not isinstance(analysis, dict):
            raise DailyJsonError(f"items[{i}] (id={item_id!r}): analysisが存在しません")

        if analysis.get("status") not in VALID_ANALYSIS_STATUSES:
            raise DailyJsonError(
                f"items[{i}] (id={item_id!r}): analysis.statusが不正です: "
                f"{analysis.get('status')!r} (許容値: {sorted(VALID_ANALYSIS_STATUSES)})"
            )

    return True


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
    items, exec_result, source_definitions, model, fetched_at, generated_at, data_dir=None,
):
    """日次JSON(data/YYYY-MM-DD.json)を構築・保存し、続けてdata/index.jsonを
    再構築・保存する。保存した日次JSONの辞書を返す。"""
    data_dir = Path(data_dir) if data_dir is not None else DATA_DIR

    digest = build_daily_digest(items, exec_result, source_definitions, model, fetched_at, generated_at)
    save_daily_digest(digest, data_dir)
    save_index(data_dir, generated_at)
    return digest
