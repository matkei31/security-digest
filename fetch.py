#!/usr/bin/env python3
"""
Security Digest — サイバーセキュリティニュースを収集してindex.htmlを生成する
"""

import sys, json, datetime, time, re, os
import urllib.request, urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

import daily_json

# ── 設定 ────────────────────────────────────────────────────────────────────

MAX_PER_FEED = 3
DAYS_BACK    = 1

GEMINI_MODEL = "gemini-2.5-flash"

JST = datetime.timezone(datetime.timedelta(hours=9))

NAMESPACES = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc":   "http://purl.org/dc/elements/1.1/",
    "rss1": "http://purl.org/rss/1.0/",
}

CACHE_PATH = Path(__file__).parent / "docs" / "translate_cache.json"

# ── ソース定義 (source_definitions.json) ─────────────────────────────────────
# ソース関連の設定(RSS_FEEDS・SOURCE_COLORS・TRUSTED_CYBER_SOURCES等)の正本は
# source_definitions.json に一元化されている。以下はそれを読み込み・検証し、
# 既存コードが期待する形（RSS_FEEDS/SOURCE_COLORS/TRUSTED_CYBER_SOURCES）に
# 変換する互換レイヤー。

SOURCE_DEFINITIONS_PATH = Path(__file__).resolve().parent / "source_definitions.json"

VALID_SOURCE_TYPES = {
    "規制・監督", "政府・公的機関", "CERT・注意喚起", "業界基準・フレームワーク",
    "脅威インテリジェンス", "ベンダー情報", "報道・メディア", "その他",
}
VALID_SOURCE_TIERS = {"Tier 1", "Tier 2", "Tier 3"}
VALID_PLANNED_PHASES = {"Phase 1", "Phase 2", "Phase 3", "保留"}
VALID_COLLECTION_FREQUENCIES = {"daily", "weekly", "manual"}
# 現状定義されている収集方法はいずれもURL必須(将来、URL不要な方式を
# 追加する場合はここから除外する)
VALID_COLLECTION_METHODS = {"rss", "cisa_kev_json", "nist_nvd_json"}
URL_REQUIRED_COLLECTION_METHODS = set(VALID_COLLECTION_METHODS)

REQUIRED_SOURCE_FIELDS = (
    "id", "name", "url", "collection_method", "language",
    "source_type", "source_tier", "enabled", "planned_phase",
    "activation_condition", "collection_frequency", "color",
    "trusted_cyber_source", "notes",
)


class SourceDefinitionError(Exception):
    """source_definitions.json の読み込み・検証エラー"""


def _validate_source_entry(entry, index):
    where = f"sources[{index}]"
    if not isinstance(entry, dict):
        raise SourceDefinitionError(f"{where}: オブジェクト(dict)ではありません")

    missing = [f for f in REQUIRED_SOURCE_FIELDS if f not in entry]
    if missing:
        raise SourceDefinitionError(
            f"{where} (id={entry.get('id', '?')!r}): 必須項目が欠落しています: {', '.join(missing)}"
        )

    sid = entry["id"]

    if not isinstance(entry["enabled"], bool):
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): enabled は bool である必要があります (実際: {entry['enabled']!r})"
        )

    if not isinstance(entry["trusted_cyber_source"], bool):
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): trusted_cyber_source は bool である必要があります "
            f"(実際: {entry['trusted_cyber_source']!r})"
        )

    if entry["source_type"] not in VALID_SOURCE_TYPES:
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): source_type が不正です: {entry['source_type']!r} "
            f"(許容値: {sorted(VALID_SOURCE_TYPES)})"
        )

    if entry["source_tier"] not in VALID_SOURCE_TIERS:
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): source_tier が不正です: {entry['source_tier']!r} "
            f"(許容値: {sorted(VALID_SOURCE_TIERS)})"
        )

    if entry["planned_phase"] not in VALID_PLANNED_PHASES:
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): planned_phase が不正です: {entry['planned_phase']!r} "
            f"(許容値: {sorted(VALID_PLANNED_PHASES)})"
        )

    if entry["collection_frequency"] not in VALID_COLLECTION_FREQUENCIES:
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): collection_frequency が不正です: {entry['collection_frequency']!r} "
            f"(許容値: {sorted(VALID_COLLECTION_FREQUENCIES)})"
        )

    if entry["collection_method"] not in VALID_COLLECTION_METHODS:
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): collection_method が不正です: {entry['collection_method']!r} "
            f"(許容値: {sorted(VALID_COLLECTION_METHODS)})"
        )

    if entry["collection_method"] in URL_REQUIRED_COLLECTION_METHODS and not entry.get("url"):
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): collection_method={entry['collection_method']!r} はURLが必須です"
        )

    # CISA KEV固有: fetch_cisa_kev()は記事表示用の固定リンクとしてdisplay_urlを
    # 必要とする。enabled=trueで実際に取得される場合のみ必須とする。
    if sid == "cisa_kev" and entry["enabled"] and not entry.get("display_url"):
        raise SourceDefinitionError(
            f"{where} (id={sid!r}): enabled=true の場合、display_url が必須です"
        )


def load_source_definitions(path=None):
    """source_definitions.json を読み込み・検証し、source定義のリストを返す。
    読み込み・解析・検証のいずれかに失敗した場合は SourceDefinitionError を送出する
    (黙って空リストにフォールバックしない)。
    """
    path = path or SOURCE_DEFINITIONS_PATH

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SourceDefinitionError(
            f"source_definitions.json を読み込めません ({path}): {e}"
        ) from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SourceDefinitionError(
            f"source_definitions.json のJSON解析に失敗しました ({path}): "
            f"{e.msg} (line {e.lineno}, column {e.colno})"
        ) from e

    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise SourceDefinitionError(
            f"source_definitions.json の形式が不正です: "
            f"トップレベルに 'sources' 配列が必要です ({path})"
        )

    sources = data["sources"]
    seen_ids = {}
    seen_names = {}

    for i, entry in enumerate(sources):
        _validate_source_entry(entry, i)

        sid = entry["id"]
        name = entry["name"]

        if sid in seen_ids:
            raise SourceDefinitionError(
                f"sources[{i}]: id が重複しています: {sid!r} "
                f"(sources[{seen_ids[sid]}] と重複)"
            )
        seen_ids[sid] = i

        if name in seen_names:
            raise SourceDefinitionError(
                f"sources[{i}]: name が重複しています: {name!r} "
                f"(sources[{seen_names[name]}] と重複)"
            )
        seen_names[name] = i

    return sources


def build_rss_feeds(sources):
    """source定義から、既存コードが期待する RSS_FEEDS 相当の
    [(表示名, URL, 言語), ...] を生成する(collection_method=rss かつ enabled=trueのみ、
    定義順を維持)。"""
    return [
        (s["name"], s["url"], s["language"])
        for s in sources
        if s["collection_method"] == "rss" and s["enabled"]
    ]


def build_source_colors(sources):
    """source定義から、既存コードが期待する SOURCE_COLORS 相当の
    {表示名: 色コード} を生成する(enabled有無に関わらず全ソース分)。"""
    return {s["name"]: s["color"] for s in sources}


def build_trusted_cyber_sources(sources):
    """source定義から、既存コードが期待する TRUSTED_CYBER_SOURCES 相当の
    表示名の集合を生成する。"""
    return {s["name"] for s in sources if s["trusted_cyber_source"]}


def get_source_definition(sources, source_id):
    """idでsource定義を1件検索する。見つからなければNone。"""
    for s in sources:
        if s["id"] == source_id:
            return s
    return None


SOURCE_DEFINITIONS = load_source_definitions()

# 互換レイヤー: 既存コード(fetch_feed呼び出し・is_cyber_relevantフィルタ・
# build_htmlの表示等)は従来通りこれらの名前をそのまま参照する。
# 正本は source_definitions.json のみで、ここでの二重管理はしない。
RSS_FEEDS = build_rss_feeds(SOURCE_DEFINITIONS)
SOURCE_COLORS = build_source_colors(SOURCE_DEFINITIONS)
TRUSTED_CYBER_SOURCES = build_trusted_cyber_sources(SOURCE_DEFINITIONS)

# ── 翻訳 (Google Translate 非公式エンドポイント + キャッシュ) ────────────────

def load_cache():
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_cache(cache):
    CACHE_PATH.parent.mkdir(exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")

def translate(text, cache):
    if not text or len(text.strip()) < 4:
        return text
    key = text[:300]
    if key in cache:
        return cache[key]
    params = urllib.parse.urlencode({
        "client": "gtx", "sl": "en", "tl": "ja", "dt": "t", "q": text[:500],
    })
    req = urllib.request.Request(
        f"https://translate.googleapis.com/translate_a/single?{params}",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as res:
            data = json.loads(res.read())
            result = "".join(p[0] for p in data[0] if p[0])
            cache[key] = result
            time.sleep(0.08)
            return result
    except Exception as e:
        print(f"[WARN] 翻訳失敗: {e}", file=sys.stderr)
        return text

# ── 日付パーサー ─────────────────────────────────────────────────────────────

def parse_date(s):
    if not s:
        return None
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M%z",
        "%Y-%m-%d",
    ):
        try:
            return datetime.datetime.strptime(s.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return None

# ── RSS パーサー ──────────────────────────────────────────────────────────────

def fetch_feed(name, url, lang):
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityDigest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as res:
            data = res.read()
    except Exception as e:
        print(f"[WARN] {name}: {e}", file=sys.stderr)
        return []

    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        print(f"[WARN] {name}: XML解析エラー: {e}", file=sys.stderr)
        return []

    items = []
    tag = root.tag.lower()

    if "rss" in tag or root.find("channel") is not None:
        for item in root.findall(".//item")[:MAX_PER_FEED]:
            pub_date_raw = (item.findtext("pubDate") or
                            item.findtext("dc:date", namespaces=NAMESPACES))
            items.append({
                "title":   (item.findtext("title") or "").strip(),
                "link":    (item.findtext("link")  or "").strip(),
                "summary": (item.findtext("description") or "").strip(),
                "date":    parse_date(pub_date_raw),
                "published_at_jst": daily_json.parse_date_to_jst(pub_date_raw),
                "source": name,
                "lang":   lang,
            })
    elif "feed" in tag:
        for entry in root.findall("atom:entry", NAMESPACES)[:MAX_PER_FEED]:
            link_el = (entry.find("atom:link[@rel='alternate']", NAMESPACES)
                    or entry.find("atom:link", NAMESPACES))
            pub_date_raw = (entry.findtext("atom:updated",   namespaces=NAMESPACES) or
                            entry.findtext("atom:published", namespaces=NAMESPACES))
            items.append({
                "title":   (entry.findtext("atom:title",   namespaces=NAMESPACES) or "").strip(),
                "link":    (link_el.get("href") if link_el is not None else "").strip(),
                "summary": (entry.findtext("atom:summary", namespaces=NAMESPACES) or "").strip(),
                "date":    parse_date(pub_date_raw),
                "published_at_jst": daily_json.parse_date_to_jst(pub_date_raw),
                "source": name,
                "lang":   lang,
            })
    elif "rdf" in tag:
        # RSS 1.0 (RDF) 形式: 要素がデフォルト名前空間 (rss1) に属する
        for item in root.findall("rss1:item", NAMESPACES)[:MAX_PER_FEED]:
            pub_date_raw = item.findtext("dc:date", namespaces=NAMESPACES)
            items.append({
                "title":   (item.findtext("rss1:title",       namespaces=NAMESPACES) or "").strip(),
                "link":    (item.findtext("rss1:link",         namespaces=NAMESPACES) or "").strip(),
                "summary": (item.findtext("rss1:description",  namespaces=NAMESPACES) or "").strip(),
                "date":    parse_date(pub_date_raw),
                "published_at_jst": daily_json.parse_date_to_jst(pub_date_raw),
                "source": name,
                "lang":   lang,
            })
    return items

# ── CISA KEV (JSON) ───────────────────────────────────────────────────────────

def fetch_cisa_kev(cutoff, url, display_url, source_name):
    """url: 取得元JSON API、display_url: 記事表示用の固定リンク(全件共通)、
    source_name: item["source"]に設定する表示名。いずれもsource_definitions.json由来。
    取得・パース・フィルタのロジック自体は変更していない。
    """
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityDigest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read())
    except Exception as e:
        print(f"[WARN] {source_name}: {e}", file=sys.stderr)
        return []

    items = []
    for v in sorted(data.get("vulnerabilities", []),
                    key=lambda x: x.get("dateAdded", ""), reverse=True):
        date_added_raw = v.get("dateAdded")
        date = parse_date(date_added_raw)
        if date and date < cutoff:
            break
        items.append({
            "title":   f"{v.get('cveID','')} — {v.get('vulnerabilityName','')}",
            "link":    display_url,
            "summary": v.get("shortDescription", ""),
            "date":    date,
            "published_at_jst": daily_json.parse_date_to_jst(date_added_raw),
            "source":  source_name,
            "lang":    "en",
        })
        if len(items) >= MAX_PER_FEED:
            break
    return items

# ── NIST NVD (JSON API) ───────────────────────────────────────────────────────

def fetch_nist_nvd(cutoff, base_url, source_name):
    """base_url: 取得元JSON APIのベースURL、source_name: item["source"]に設定する表示名。
    いずれもsource_definitions.json由来。取得・パース・フィルタのロジック自体は
    変更していない。記事ごとのリンクはCVE IDからNVD詳細ページを組み立てる仕様であり
    (単一の固定リンクではないため)、従来通り関数内でテンプレート生成する。
    """
    now   = datetime.datetime.utcnow()
    start = cutoff.strftime("%Y-%m-%dT00:00:00.000")
    end   = now.strftime("%Y-%m-%dT23:59:59.000")
    url   = (
        f"{base_url}"
        f"?pubStartDate={start}&pubEndDate={end}"
        f"&resultsPerPage={MAX_PER_FEED}&cvssV3Severity=CRITICAL"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityDigest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read())
    except Exception as e:
        print(f"[WARN] {source_name}: {e}", file=sys.stderr)
        return []

    items = []
    for vuln in data.get("vulnerabilities", []):
        cve  = vuln.get("cve", {})
        cveid = cve.get("id", "")
        desc  = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        score = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = metrics[key][0]["cvssData"].get("baseScore", "")
                break
        title = f"{cveid} (CVSS {score}) — {desc[:80]}" if score else f"{cveid} — {desc[:80]}"
        published_raw = cve.get("published")
        items.append({
            "title":   title,
            "link":    f"https://nvd.nist.gov/vuln/detail/{cveid}",
            "summary": desc,
            "date":    parse_date(published_raw),
            "published_at_jst": daily_json.parse_date_to_jst(published_raw),
            "source":  source_name,
            "lang":    "en",
        })
    return items

# ── 全収集 ────────────────────────────────────────────────────────────────────
# TRUSTED_CYBER_SOURCES は source_definitions.json から生成される
# (ファイル冒頭の「ソース定義」セクション参照)。ここでの再定義はしない。


def is_cyber_relevant(item):
    text = (item.get("title", "") + " " + item.get("summary", "")).lower()
    keywords = [
        "cyber", "セキュリティ", "脆弱性", "malware", "ransomware",
        "phishing", "incident", "breach", "attack", "cve", "ゼロデイ",
        "不正アクセス", "サイバー", "情報漏洩", "標的型", "ddos", "apt",
        "threat", "exploit", "マルウェア", "フィッシング", "インシデント",
        "情報セキュリティ", "ガイドライン", "規制", "制度", "policy",
        "regulation", "compliance", "governance", "リスク"
    ]
    return any(k in text for k in keywords)


def collect_non_rss_items(cutoff, sources):
    """RSS以外の取得元(CISA KEV・NIST NVD)を、source定義のenabledに従って収集する。
    URL・表示名・有効/無効はすべてsource_definitions.json(sources)由来。
    id="cisa_kev"/"nist_nvd" はこの関数が直接参照する前提の識別子であるため、
    定義に存在しない場合は黙ってスキップせず、対象IDを含むエラーを送出する。
    """
    all_items = []

    cisa_kev_def = get_source_definition(sources, "cisa_kev")
    if cisa_kev_def is None:
        raise SourceDefinitionError(
            "collect_non_rss_items: source定義に id='cisa_kev' が見つかりません"
        )
    if cisa_kev_def["enabled"]:
        kev_items = fetch_cisa_kev(
            cutoff,
            url=cisa_kev_def["url"],
            display_url=cisa_kev_def.get("display_url") or cisa_kev_def["url"],
            source_name=cisa_kev_def["name"],
        )
        kev_status = "OK" if kev_items else "NG"
        print(f"  [{kev_status}] {cisa_kev_def['name']}: 取得 {len(kev_items)} 件")
        all_items += kev_items

    nist_nvd_def = get_source_definition(sources, "nist_nvd")
    if nist_nvd_def is None:
        raise SourceDefinitionError(
            "collect_non_rss_items: source定義に id='nist_nvd' が見つかりません"
        )
    if nist_nvd_def["enabled"]:
        nvd_items = fetch_nist_nvd(
            cutoff,
            base_url=nist_nvd_def["url"],
            source_name=nist_nvd_def["name"],
        )
        nvd_status = "OK" if nvd_items else "NG"
        print(f"  [{nvd_status}] {nist_nvd_def['name']}: 取得 {len(nvd_items)} 件")
        all_items += nvd_items

    return all_items


def collect_recent():
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=DAYS_BACK)
    all_items = []

    print("フィード別の取得状況:")
    for name, url, lang in (f for f in RSS_FEEDS if not f[1].startswith("#")):
        items = fetch_feed(name, url, lang)
        recent = [item for item in items if item["date"] is None or item["date"] >= cutoff]
        status = "OK" if items else "NG"
        print(f"  [{status}] {name}: 取得 {len(items)} 件 / 直近 {len(recent)} 件")
        all_items.extend(recent)

    all_items += collect_non_rss_items(cutoff, SOURCE_DEFINITIONS)

    all_items = [
        item for item in all_items
        if item["source"] in TRUSTED_CYBER_SOURCES or is_cyber_relevant(item)
    ]

    all_items.sort(key=lambda x: x["date"] or datetime.datetime.min, reverse=True)
    all_items = enrich_with_ai(all_items)
    return all_items

# ── HTML生成 ─────────────────────────────────────────────────────────────────

def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&#39;"))

def safe_url(url):
    """http(s) スキームのURLのみ許可する。安全ならそのURL文字列を、そうでなければNoneを返す。
    前後の空白のみ除去し、それ以外は一切加工しない（不正なURLを正規化して受理しない）。
    URL内部にASCII制御文字・空白（\\x00-\\x20）が残っている場合は、
    ブラウザがそれらを無視して解釈しスキーム偽装（例: 'java\\tscript:'）が
    成立し得るため拒否する。
    """
    if not isinstance(url, str):
        return None
    stripped = url.strip()
    if re.search(r"[\x00-\x20]", stripped):
        return None
    if stripped.lower().startswith(("http://", "https://")):
        return stripped
    return None

def strip_html(s):
    return re.sub(r"<[^>]+>", "", s).strip()


# ── Gemini AI要約 ─────────────────────────────────────────────────────────────

def normalize_ai_analysis(value):
    if not isinstance(value, dict):
        return None

    importance = str(value.get("importance", "")).strip()
    summary = str(value.get("summary", "")).strip()
    impact = str(value.get("financial_impact", "")).strip()
    actions = value.get("recommended_actions", [])

    if importance not in ("高", "中", "低") or not summary or not impact:
        return None
    if not isinstance(actions, list):
        return None

    actions = [str(action).strip() for action in actions if str(action).strip()]
    if not actions:
        return None

    return {
        "importance": importance,
        "summary": summary,
        "financial_impact": impact,
        "recommended_actions": actions[:3],
    }


def validate_tags_strict(raw_tags):
    """tagsを厳密に検証する(success判定用)。許可リスト外のタグが1つでもあれば
    Noneを返す(呼び出し側でfallback扱いにする)。重複は除去して許容し、
    除去後にMAX_TAGSを超える場合はNoneを返す。空配列は正常値として許容する。
    """
    if not isinstance(raw_tags, list):
        return None

    cleaned = []
    for t in raw_tags:
        t = str(t).strip()
        if not t:
            continue
        if t not in daily_json.TAG_ALLOWLIST:
            return None
        if t not in cleaned:
            cleaned.append(t)

    if len(cleaned) > daily_json.MAX_TAGS:
        return None

    return cleaned


def sanitize_tags_lenient(raw_tags):
    """tagsを緩く救済する(fallback用)。許可外タグ・list以外の入力は捨て、
    重複を除去し、MAX_TAGSで切り詰める。例外を投げず必ず配列を返す。
    """
    if not isinstance(raw_tags, list):
        return []

    cleaned = []
    for t in raw_tags:
        t = str(t).strip()
        if t and t in daily_json.TAG_ALLOWLIST and t not in cleaned:
            cleaned.append(t)
        if len(cleaned) >= daily_json.MAX_TAGS:
            break

    return cleaned


def normalize_article_analysis(value):
    """Ticket 4の新スキーマ(category/category_reason/urgency/reason/tagsを含む
    全項目)を厳密に検証する。1項目でも不正なら全体としてNoneを返す(success判定用)。
    既存4項目(importance/summary/financial_impact/recommended_actions)の検証は
    normalize_ai_analysis()を再利用し、重複させない。
    """
    if not isinstance(value, dict):
        return None

    core = normalize_ai_analysis(value)
    if core is None:
        return None

    category = str(value.get("category", "")).strip()
    if category not in daily_json.CATEGORY_VALUES:
        return None

    category_reason = str(value.get("category_reason", "")).strip()
    if not category_reason:
        return None

    urgency = str(value.get("urgency", "")).strip()
    if urgency not in daily_json.URGENCY_VALUES:
        return None

    reason = str(value.get("reason", "")).strip()
    if not reason:
        return None

    tags = validate_tags_strict(value.get("tags", []))
    if tags is None:
        return None

    return {
        **core,
        "category": category,
        "category_reason": category_reason,
        "urgency": urgency,
        "reason": reason,
        "tags": tags,
    }


def parse_ai_analysis(response_text):
    if not isinstance(response_text, str):
        return None

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", response_text):
        try:
            value, _ = decoder.raw_decode(response_text[match.start():])
        except json.JSONDecodeError:
            continue

        analysis = normalize_ai_analysis(value)
        if analysis:
            return analysis

    return None


def parse_article_analysis(response_text):
    """Ticket 4の新スキーマ全項目を検証するparse_ai_analysis()相当。
    success判定にのみ使用する(1項目でも不正ならNone、fallback_ai_analysis()側で
    部分的に救済する)。
    """
    if not isinstance(response_text, str):
        return None

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", response_text):
        try:
            value, _ = decoder.raw_decode(response_text[match.start():])
        except json.JSONDecodeError:
            continue

        analysis = normalize_article_analysis(value)
        if analysis:
            return analysis

    return None


def extract_partial_field(response_text, field):
    if not isinstance(response_text, str):
        return ""

    match = re.search(
        rf'"{re.escape(field)}"\s*:\s*"((?:\\.|[^"])*)',
        response_text,
        re.DOTALL,
    )
    if not match:
        return ""

    value = match.group(1).strip()
    try:
        return json.loads(f'"{value}"').strip()
    except json.JSONDecodeError:
        return value.replace(r"\n", " ").replace(r"\"", '"').strip()


def extract_partial_array(response_text, field):
    """フォールバック用: 壊れたJSON応答からfield(文字列配列)の要素を正規表現で
    抽出する。recommended_actionsの既存抽出とは異なり閉じ括弧までを対象とする
    (tags等、応答内で最後のフィールドとは限らないフィールド向け)。
    見つからない、または配列として復元できない場合は空配列を返す。
    """
    if not isinstance(response_text, str):
        return []

    match = re.search(
        rf'"{re.escape(field)}"\s*:\s*\[(.*?)\]',
        response_text,
        re.DOTALL,
    )
    if not match:
        return []

    return [
        value.strip()
        for value in re.findall(r'"((?:\\.|[^"])*)"', match.group(1))
        if value.strip()
    ]


def fallback_ai_analysis(response_text, source_text):
    """主要4項目(importance/summary/financial_impact/recommended_actions)が
    応答から安全に取得できた場合のみ、部分的な分析結果として返す(=fallback扱い)。
    いずれか1つでも取得できない場合はNoneを返し、呼び出し側でfailed扱いにする
    (コード側で「重要度は中」「一般的な確認事項」等の一般論を補完しない。
    記事に基づかない判断・定型文を作らないため)。

    category/category_reason/urgency/reason/tagsは主要4項目とは独立に、
    抽出できた分だけ緩く救済する(欠けていてもfallback自体は成立する)。
    """
    importance = extract_partial_field(response_text, "importance")
    if importance not in ("高", "中", "低"):
        importance_match = re.search(r"重要度\s*[:：]\s*([高中低])", response_text or "")
        importance = importance_match.group(1) if importance_match else ""

    summary = extract_partial_field(response_text, "summary")
    impact = extract_partial_field(response_text, "financial_impact")

    source_fields = {}
    for line in source_text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            source_fields[key.strip()] = value.strip()

    if not summary:
        plain_response = re.sub(
            r"^```(?:json)?|```$",
            "",
            (response_text or "").strip(),
            flags=re.IGNORECASE,
        ).strip()
        if plain_response and not plain_response.startswith(("{", "[")):
            summary = plain_response
        else:
            summary = source_fields.get("summary") or source_fields.get("title", "")
    summary = re.sub(r"\s+", " ", strip_html(summary)).strip()[:120]

    # recommended_actionsはTicket 4で"reason"/"tags"より前の項目になった
    # (v1では最後の項目だったため、閉じ括弧を要求しない抽出でも安全だった)。
    # 境界のないパターンのままだと後続フィールドの文字列まで誤って
    # recommended_actionsに取り込んでしまうため、extract_partial_array()で
    # 閉じ括弧までに限定して抽出する。
    actions = extract_partial_array(response_text, "recommended_actions")

    # 主要4項目はすべて応答から実際に取得できた場合のみ有効とする。
    # 1つでも欠ける場合はnormalize_ai_analysis()がNoneを返し、
    # fallback_ai_analysis()全体もNoneを返す(=failed扱いになる)。
    core = normalize_ai_analysis({
        "importance": importance,
        "summary": summary,
        "financial_impact": impact[:140] if impact else "",
        "recommended_actions": actions[:3],
    })
    if core is None:
        return None

    category = extract_partial_field(response_text, "category")
    if category not in daily_json.CATEGORY_VALUES:
        category = None

    category_reason = extract_partial_field(response_text, "category_reason").strip()[:100] or None

    urgency = extract_partial_field(response_text, "urgency")
    if urgency not in daily_json.URGENCY_VALUES:
        urgency = None

    reason = extract_partial_field(response_text, "reason").strip()[:150] or None

    tags = sanitize_tags_lenient(extract_partial_array(response_text, "tags"))

    return {
        **core,
        "category": category,
        "category_reason": category_reason,
        "urgency": urgency,
        "reason": reason,
        "tags": tags,
    }


def gemini_analyze(text):
    """戻り値: {"analysis": dict|None, "status": "success"|"fallback"|"failed",
    "error_type": str|None, "http_status": int|None}
    既存の分析データ(analysis)の中身・生成条件は変更していない。
    status/error_type/http_statusは日次JSON保存(Ticket 3)のために追加した
    メタ情報で、item["ai_analysis"]として保存される中身には影響しない。
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        # enrich_with_ai() が呼び出し前にAPIキー有無を判定しているため、
        # 実際にはこの分岐には到達しない(防御的な分岐)。
        return {"analysis": None, "status": "not_attempted", "error_type": None, "http_status": None}

    prompt = f"""
あなたは日本の金融機関のサイバーセキュリティ・IT監査部門で働くシニアアナリストです。
以下のニュース1件だけを根拠に、金融機関のサイバーセキュリティ担当者・管理者・
担当役員向けニュースブリーフとして、構造化された分析を日本語で作成してください。

# category（1記事1カテゴリ、以下7つのみ。上から優先順に判定し最初に該当したものを採用する）
1. 脆弱性・パッチ: CVE、KEV、ゼロデイ、パッチが主題
2. インシデント: 実際の侵害、漏えい、業務停止、被害事例が主題
3. 攻撃・脅威動向: 攻撃者、攻撃手法、キャンペーン、ランサムウェア、APT、脅威レポートが主題
4. 規制・ガバナンス: 法令、規制、ガイドライン、監督方針、フレームワークが主題
5. クラウド・サプライチェーン: クラウド設定、SaaS、委託先、サードパーティ、ソフトウェア供給網が主題
6. AI・新技術リスク: AI、LLM、AIエージェント、量子等が主題(記事にAIという単語が出るだけで
   このカテゴリにしない。主題を基準にする)
7. その他: 上記のいずれにも明確に当てはまらない場合のみ

# importance（高/中/低）
ニュースとしての話題性ではなく、「金融機関にとって見落としたくない度合い」で判定する。
- 高: 実際に悪用が確認されている脆弱性／CISA KEVへの追加／金融機関で利用可能性が高い
  製品・サービスの重大なセキュリティ情報／金融機関・決済・認証基盤・重要インフラ等の
  重大インシデント／金融庁・JPCERT/CC・CISA等による重要な注意喚起／金融機関の規制対応・
  監督対応・統制評価に影響し得る文書／SWIFT CSCF等、統制・評価・アテステーションに
  影響し得る重要更新／管理態勢上、明確に見落とすべきでないもの
- 中: 即時対応ではないが運用・管理態勢への示唆がある／脅威動向・攻撃手法・ベンダー
  レポートとして有用／金融機関への直接影響は不明だが今後の議論材料になる／クラウド・
  AI・IAM・サプライチェーン等の継続論点／高とするほど具体的・重大ではないが無視するには惜しい
- 低: 一般的なセキュリティ解説／マーケティング色が強い／技術的には興味深いが実務判断に
  直結しにくい／既知情報の再掲に近い／金融機関との関係を具体的に説明しにくい

以下だけを理由に高にしない: CVSSが高い／海外で話題になっている／AI関連で目新しい／
ベンダーが重大と表現している／Tier 1ソースの記事である／大企業の記事である／
技術的に高度である。source_type・source_tierは判断材料の一つに過ぎず、
Tier 1だから自動的に高、「報道・メディア」だから自動的に低、とはしない。

# urgency（本日確認/今週確認/参考）
「いつ確認・共有すべきか」で判定する。
- 本日確認: 悪用確認済み脆弱性／KEV追加／期限付き・緊急性のある注意喚起／外部公開
  システムや重要システムに影響し得る情報／インシデント対応・監視強化・パッチ状況
  確認につながる情報
- 今週確認: 規制・ガイドライン・フレームワーク更新／年次レポート・脅威レポート／
  AI・クラウド・サプライチェーン等の管理態勢上の論点／即時対応より関係者での
  把握・整理が重要な情報
- 参考: 直ちに確認・共有する必要性が低い／背景知識・一般動向として有用／実務対応や
  管理態勢への影響が限定的
自然な組み合わせ: 高×本日確認／高×今週確認／中×本日確認／中×今週確認／中×参考／低×参考。
低×本日確認は原則として避ける。ただし機械的に固定せず記事内容を優先し、
矛盾した組み合わせになる場合はreasonで明確に説明する。

# tags（以下の許可リストから最大{daily_json.MAX_TAGS}個、該当なければ空配列）
{"、".join(daily_json.TAG_ALLOWLIST)}
許可リスト外の語を作らない。類似タグを意味なく重複させない。記事に根拠がないタグを
付けない。表記(英語・日本語)を変更しない。

# summary（何が起きたか。1〜2文、日本語、200文字以内目安）
記事本文の長い引用をせず、言い換え・要約する。記事にない推測を追加しない。
金融機関への影響はここに混ぜすぎない。marketing表現をそのまま受け入れない。

# financial_impact（なぜ金融機関に関係するか。1〜2文、日本語、200文字以内目安）
金融機関との関係が不明な場合はその旨を明記する。全金融機関に影響するかのように
断定しない。利用環境やサービス採用状況によって影響が異なる場合は条件付きで書く。
根拠のない経営影響・損失額を追加しない。記事にない規制要求を捏造しない。
望ましい例: 「該当製品を利用している金融機関では、影響確認が必要になり得る。」
避ける例: 「すべての金融機関が直ちに対応しなければならない。」

# recommended_actions（金融機関として一般的に確認すべきこと。配列、1〜3件）
各要素は短い確認事項。断定的な命令ではなく確認対象を示す。各社固有のシステム構成を
決めつけない。記事に根拠がない高度な対策を追加しない。「該当する場合」「必要に応じて」
等の条件を適切に使う。単なる「注意する」「検討する」ではなく確認対象を具体化する。

# reason（importanceとurgencyの判定理由。1〜2文、150文字以内目安）
記事の具体的事実と金融機関への関係を根拠にする。「重大だから高」のような循環説明を
避ける。source_tierだけを理由にしない。importanceとurgencyの両方を説明できる内容にする。

# category_reason（categoryの判定理由。1文、100文字以内目安）
主題を根拠にする。単にカテゴリ名を言い換えるだけにしない。

# 禁止事項（すべての項目に共通）
- 記事にない事実を補わない、一般論で穴埋めしない
- 記事にない金融機関固有の利用状況を推測しない
- 全金融機関へ一律に影響すると断定しない
- 記事にない規制要求を追加しない
- 原文を長く転載しない
- ベンダーの宣伝表現を客観的事実として繰り返さない
- 被害額や影響範囲を捏造しない
- 推測が必要な場合は「記事からは確認できない」とする
- JSON以外の説明文やMarkdownを返さない
- rule_flagsのkev_entryは強い判定材料だが、その存在だけを根拠に記事にない事実を追加しない

# 例1: 高 × 本日確認（CISA KEVへの悪用確認済み脆弱性追加）
{{"category": "脆弱性・パッチ", "importance": "高", "urgency": "本日確認", "tags": ["KEV", "悪用確認済み", "パッチ"]}}

# 例2: 高 × 今週確認（SWIFT CSCFの新バージョンまたは重要改定。即時対応ではないが
統制・評価・アテステーションへの影響があり得るため）
{{"category": "規制・ガバナンス", "importance": "高", "urgency": "今週確認", "tags": ["SWIFT", "CSCF", "ガイドライン"]}}

# 例3: 中 × 今週確認（AIエージェントの新しい攻撃手法に関する調査レポート）
{{"category": "AI・新技術リスク", "importance": "中", "urgency": "今週確認", "tags": ["AI", "AIエージェント"]}}

# 例4: 低 × 参考（ベンダー製品の一般的な紹介・マーケティング記事）
{{"category": "その他", "importance": "低", "urgency": "参考", "tags": []}}

# ニュース
{text}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1200,
            "thinking_config": {
                "thinking_budget": 0
            },
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "OBJECT",
                "propertyOrdering": [
                    "category",
                    "category_reason",
                    "importance",
                    "urgency",
                    "summary",
                    "financial_impact",
                    "recommended_actions",
                    "reason",
                    "tags"
                ],
                "properties": {
                    "category": {
                        "type": "STRING",
                        "enum": list(daily_json.CATEGORY_VALUES),
                        "description": "記事の主題に基づく分類(1つ)"
                    },
                    "category_reason": {
                        "type": "STRING",
                        "description": "categoryの判定理由(1文、100文字以内目安)"
                    },
                    "importance": {
                        "type": "STRING",
                        "enum": list(daily_json.IMPORTANCE_VALUES),
                        "description": "金融機関にとって見落としたくない度合い"
                    },
                    "urgency": {
                        "type": "STRING",
                        "enum": list(daily_json.URGENCY_VALUES),
                        "description": "いつ確認・共有すべきか"
                    },
                    "summary": {
                        "type": "STRING",
                        "description": "何が起きたかの日本語要約"
                    },
                    "financial_impact": {
                        "type": "STRING",
                        "description": "なぜ金融機関に関係するか"
                    },
                    "recommended_actions": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                        "minItems": 1,
                        "maxItems": 3,
                        "description": "金融機関として一般的に確認すべきこと"
                    },
                    "reason": {
                        "type": "STRING",
                        "description": "importance/urgencyの判定理由(1〜2文、150文字以内目安)"
                    },
                    "tags": {
                        "type": "ARRAY",
                        "items": {
                            "type": "STRING",
                            "enum": list(daily_json.TAG_ALLOWLIST)
                        },
                        "maxItems": daily_json.MAX_TAGS,
                        "description": "許可リストからの補助分類(0〜5個)"
                    }
                },
                "required": [
                    "category",
                    "category_reason",
                    "importance",
                    "urgency",
                    "summary",
                    "financial_impact",
                    "recommended_actions",
                    "reason",
                    "tags"
                ]
            }
        }
    }).encode("utf-8")

    max_retries = 2
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                data = json.loads(res.read())
            parts = data["candidates"][0]["content"]["parts"]
            response_text = "".join(
                part.get("text", "")
                for part in parts
                if isinstance(part, dict)
            )
            analysis = parse_article_analysis(response_text)
            if analysis:
                return {"analysis": analysis, "status": "success", "error_type": None, "http_status": None}

            text_length = len(response_text) if isinstance(response_text, str) else 0
            fallback = fallback_ai_analysis(response_text, text)
            if fallback:
                print(
                    f"[WARN] Gemini要約: JSON解析失敗 "
                    f"(応答長: {text_length}文字)、部分応答から補完",
                    file=sys.stderr,
                )
                return {
                    "analysis": fallback, "status": "fallback",
                    "error_type": "schema_parse_error", "http_status": None,
                }

            print(
                f"[WARN] Gemini要約: JSON解析失敗 (応答長: {text_length}文字)",
                file=sys.stderr,
            )
            return {
                "analysis": None, "status": "failed",
                "error_type": "schema_parse_error", "http_status": None,
            }
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < max_retries:
                wait_seconds = 3 * (attempt + 1)
                print(
                    f"[WARN] Gemini要約: HTTP {e.code}、"
                    f"{wait_seconds}秒後に再試行 ({attempt + 1}/{max_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait_seconds)
                continue
            print(f"[WARN] Gemini要約: HTTP {e.code}", file=sys.stderr)
            return {
                "analysis": None, "status": "failed",
                "error_type": daily_json.classify_gemini_error(http_status=e.code),
                "http_status": e.code,
            }
        except Exception as e:
            print(
                f"[WARN] Gemini要約: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return {
                "analysis": None, "status": "failed",
                "error_type": daily_json.classify_gemini_error(exception=e),
                "http_status": None,
            }

    return {"analysis": None, "status": "failed", "error_type": "unknown", "http_status": None}


def enrich_with_ai(items):
    if not os.environ.get("GEMINI_API_KEY"):
        return items

    print("Geminiで重要度・要約を生成中...")
    count = 0
    attempts = 0

    for item in items:
        attempts += 1

        # enrich_with_ai()はcollect_recent()内で翻訳処理より前に呼ばれるため、
        # この時点のitem["title"]/item["summary"]は取得直後の原文そのもの
        # (raw_title/raw_excerpt相当)。翻訳後の表示用titleとは別に、既存の
        # "title"キーとしてそのまま渡しつつ、仕様上の項目名にも合わせてraw_title
        # としても渡す(この時点では両者は同一の値になる)。
        try:
            source_meta = daily_json.resolve_source_meta(item.get("source", ""), SOURCE_DEFINITIONS)
        except daily_json.DailyJsonError:
            # プロンプト入力構築のみに影響する防御的フォールバック。
            # 最終的な日次JSON保存時はdaily_json.build_article_entry()が
            # 同じ解決を行い、そちらは黙って落とさず明確なエラーを送出する。
            source_meta = None

        published_at = item.get("published_at_jst")
        published_at_str = published_at.isoformat() if published_at else "不明"

        rule_flags = (
            daily_json.compute_rule_flags(source_meta["source_id"])
            if source_meta else []
        )

        raw_title = item.get("title", "")
        text = f"""
source_name: {item.get('source', '')}
source_type: {source_meta['source_type'] if source_meta else '不明'}
source_tier: {source_meta['source_tier'] if source_meta else '不明'}
collection_method: {source_meta['collection_method'] if source_meta else '不明'}
title: {raw_title}
raw_title: {raw_title}
summary: {strip_html(item.get('summary', ''))}
published_at: {published_at_str}
url: {item.get('link', '')}
rule_flags: {json.dumps(rule_flags, ensure_ascii=False)}
"""
        result = gemini_analyze(text)

        item["ai_analysis"] = result["analysis"]
        item["ai_analysis_meta"] = {
            "status": result["status"],
            "error_type": result["error_type"],
            "http_status": result["http_status"],
            "generated_at": datetime.datetime.now(JST).isoformat(),
        }

        if result["analysis"]:
            count += 1

        time.sleep(15)

    print(f"  AI要約: {count} 件 / 試行: {attempts} 件")
    return items


# ── エグゼクティブサマリー ─────────────────────────────────────────────────────

def normalize_executive_summary(value):
    if not isinstance(value, dict):
        return None

    lines = value.get("summary_lines")
    if not isinstance(lines, list):
        return None

    lines = [str(line).strip() for line in lines if str(line).strip()][:3]
    if len(lines) < 2:
        return None

    return lines


def parse_executive_summary(response_text):
    if not isinstance(response_text, str):
        return None

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", response_text):
        try:
            value, _ = decoder.raw_decode(response_text[match.start():])
        except json.JSONDecodeError:
            continue

        lines = normalize_executive_summary(value)
        if lines:
            return lines

    return None


def gemini_executive_summary(high_items):
    """戻り値: {"lines": list[str]|None, "status": "success"|"failed"|"not_attempted",
    "error_type": str|None, "http_status": int|None}
    既存のエグゼクティブサマリー生成条件・プロンプトは変更していない。
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        # build_executive_summary() がhigh_itemsの有無で先に判定するため、
        # 実際にはこの分岐には到達しない(防御的な分岐)。
        return {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None}

    bullets = []
    for item in high_items:
        analysis = item.get("ai_analysis") or {}
        bullets.append(
            f"- source: {item.get('source', '')} / title: {item.get('title', '')} / "
            f"summary: {analysis.get('summary', '')} / "
            f"financial_impact: {analysis.get('financial_impact', '')}"
        )
    text = "\n".join(bullets)

    prompt = f"""
あなたは日本の金融機関のサイバーセキュリティ責任者です。
以下は本日、重要度「高」と判定されたセキュリティニュースの分析結果一覧です。
金融機関のサイバー担当者が出社直後にまず読む「本日のポイント」を、日本語の箇条書き2〜3行で作成してください。

記述ルール:
- 各行は1文、80文字以内で、何が起きていて、なぜ緊急なのかが分かるように具体的に書く
- 関連する複数のニュースがあれば要点をまとめてもよい
- 入力にない事実、製品利用状況、被害、期限は推測しない
- 箇条書き記号（・や-など）や見出しは付けない(呼び出し側で付与する)

重要度「高」のニュース一覧:
{text}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 500,
            "thinking_config": {
                "thinking_budget": 0
            },
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "OBJECT",
                "propertyOrdering": ["summary_lines"],
                "properties": {
                    "summary_lines": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                        "minItems": 2,
                        "maxItems": 3,
                        "description": "本日のポイント（2〜3行の箇条書き）"
                    }
                },
                "required": ["summary_lines"]
            }
        }
    }).encode("utf-8")

    max_retries = 2
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                data = json.loads(res.read())
            parts = data["candidates"][0]["content"]["parts"]
            response_text = "".join(
                part.get("text", "")
                for part in parts
                if isinstance(part, dict)
            )
            lines = parse_executive_summary(response_text)
            if lines:
                return {"lines": lines, "status": "success", "error_type": None, "http_status": None}

            print("[WARN] エグゼクティブサマリー: JSON解析失敗", file=sys.stderr)
            return {
                "lines": None, "status": "failed",
                "error_type": "schema_parse_error", "http_status": None,
            }
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < max_retries:
                wait_seconds = 3 * (attempt + 1)
                print(
                    f"[WARN] エグゼクティブサマリー: HTTP {e.code}、"
                    f"{wait_seconds}秒後に再試行 ({attempt + 1}/{max_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait_seconds)
                continue
            print(f"[WARN] エグゼクティブサマリー: HTTP {e.code}", file=sys.stderr)
            return {
                "lines": None, "status": "failed",
                "error_type": daily_json.classify_gemini_error(http_status=e.code),
                "http_status": e.code,
            }
        except Exception as e:
            print(
                f"[WARN] エグゼクティブサマリー: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return {
                "lines": None, "status": "failed",
                "error_type": daily_json.classify_gemini_error(exception=e),
                "http_status": None,
            }

    return {"lines": None, "status": "failed", "error_type": "unknown", "http_status": None}


def build_executive_summary(items):
    """戻り値: {"lines": list[str]|None, "status": "success"|"failed"|"not_attempted",
    "error_type": str|None, "http_status": int|None}
    既存のHTML表示にはこれまで通り戻り値の"lines"を渡す(呼び出し側で変更不要)。
    """
    high_items = [
        item for item in items
        if normalize_ai_analysis(item.get("ai_analysis")) is not None
        and normalize_ai_analysis(item.get("ai_analysis"))["importance"] == "高"
    ]
    if not high_items:
        return {"lines": None, "status": "not_attempted", "error_type": None, "http_status": None}

    print("エグゼクティブサマリーを生成中...")
    result = gemini_executive_summary(high_items)
    if result["lines"]:
        print(f"  エグゼクティブサマリー: {len(result['lines'])} 行")
    else:
        print("  エグゼクティブサマリー: 生成失敗")
    return result


def build_html(items, exec_summary=None):
    now      = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9)))
    date_str = now.strftime("%Y年%m月%d日 %H:%M")

    cards = []
    for item in items:
        color      = SOURCE_COLORS.get(item["source"], "#555")
        date_label = item["date"].strftime("%m/%d %H:%M") if item["date"] else ""
        raw_summary = strip_html(item["summary"])
        analysis = normalize_ai_analysis(item.get("ai_analysis"))

        if analysis:
            importance_class = {
                "高": "importance-high",
                "中": "importance-medium",
                "低": "importance-low",
            }[analysis["importance"]]
            actions_html = "".join(
                f"<li>{esc(action)}</li>"
                for action in analysis["recommended_actions"]
            )
            summary_html = f"""<div class="ai-analysis">
        <div class="importance-row">
          <span class="field-label">重要度</span>
          <span class="importance {importance_class}">{esc(analysis["importance"])}</span>
        </div>
        <section class="analysis-field">
          <h3>要約</h3>
          <p>{esc(analysis["summary"])}</p>
        </section>
        <section class="analysis-field">
          <h3>金融機関への影響</h3>
          <p>{esc(analysis["financial_impact"])}</p>
        </section>
        <section class="analysis-field">
          <h3>推奨アクション</h3>
          <ul>{actions_html}</ul>
        </section>
      </div>"""
        else:
            max_len = 120
            summary = raw_summary[:max_len]
            summary_html = (
                f'<p class="summary">{esc(summary)}'
                f'{"…" if len(raw_summary) > max_len else ""}</p>'
                if summary else ""
            )
        summary_block = f"\n      {summary_html}" if summary_html else ""

        safe_link = safe_url(item['link'])
        if safe_link:
            tag_open  = f'<a class="card" href="{esc(safe_link)}" target="_blank" rel="noopener noreferrer">'
            tag_close = "</a>"
        else:
            # http(s) 以外のスキーム（javascript: 等）はリンクタグ自体を出力しない
            tag_open  = '<div class="card">'
            tag_close = "</div>"

        cards.append(f"""
    {tag_open}
      <div class="card-meta">
        <span class="tag" style="background:{color}">{esc(item['source'])}</span>
        <span class="date">{esc(date_label)}</span>
      </div>
      <h2>{esc(item['title'])}</h2>{summary_block}
    {tag_close}""")

    cards_html = "\n".join(cards) if cards else '<p class="empty">本日の新着はありません。</p>'
    all_sources = [f for f in RSS_FEEDS if not f[1].startswith("#")] + [("CISA KEV","","")]
    sources_li = "".join(
        '<li style="background:{}">{}</li>'.format(SOURCE_COLORS.get(n, "#555"), esc(n))
        for n, *_ in all_sources
    )

    if exec_summary:
        exec_lines_html = "".join(f"<li>{esc(line)}</li>" for line in exec_summary)
        exec_summary_html = f"""<div class="exec-summary">
    <div class="exec-summary-box">
      <h2>本日のポイント（金融機関サイバー担当者向け）</h2>
      <ul>{exec_lines_html}</ul>
    </div>
  </div>"""
    else:
        exec_summary_html = ""

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🔐 Security Digest</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;padding-bottom:40px}}
    header{{background:#161b22;border-bottom:1px solid #21262d;padding:20px 16px 16px;position:sticky;top:0;z-index:10}}
    header h1{{font-size:18px;font-weight:600;letter-spacing:.02em}}
    .sub{{font-size:12px;color:#8b949e;margin-top:4px}}
    .count{{font-size:12px;color:#58a6ff;margin-top:2px}}
    .cards{{padding:12px 12px 0;display:flex;flex-direction:column;gap:10px;max-width:680px;margin:0 auto}}
    .card{{display:block;background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 16px;text-decoration:none;color:inherit;-webkit-tap-highlight-color:transparent}}
    .card:active{{background:#1c2128;border-color:#388bfd}}
    .card-meta{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
    .tag{{font-size:10px;font-weight:600;padding:2px 8px;border-radius:100px;color:#fff;white-space:nowrap}}
    .date{{font-size:11px;color:#8b949e;margin-left:auto}}
    h2{{font-size:14px;font-weight:500;line-height:1.5;color:#e6edf3}}
    .summary{{font-size:12px;color:#8b949e;line-height:1.5;margin-top:6px}}
    .ai-analysis{{margin-top:12px;padding-top:10px;border-top:1px solid #30363d;display:grid;gap:10px}}
    .importance-row{{display:flex;align-items:center;gap:8px}}
    .field-label,.analysis-field h3{{font-size:11px;font-weight:600;color:#8b949e}}
    .importance{{font-size:11px;font-weight:700;line-height:1;padding:4px 9px;border-radius:100px;color:#fff}}
    .importance-high{{background:#da3633}}
    .importance-medium{{background:#9e6a03}}
    .importance-low{{background:#238636}}
    .analysis-field p,.analysis-field li{{font-size:12px;color:#c9d1d9;line-height:1.6}}
    .analysis-field p,.analysis-field ul{{margin-top:3px}}
    .analysis-field ul{{padding-left:18px}}
    .analysis-field li+li{{margin-top:3px}}
    .empty{{text-align:center;color:#8b949e;padding:60px 0;font-size:14px}}
    .exec-summary{{max-width:680px;margin:12px auto 0;padding:0 12px}}
    .exec-summary-box{{background:#161b22;border:1px solid #9e6a03;border-radius:10px;padding:14px 16px}}
    .exec-summary-box h2{{font-size:13px;font-weight:700;color:#f0b429;margin-bottom:8px}}
    .exec-summary-box ul{{list-style:none;display:grid;gap:6px}}
    .exec-summary-box li{{font-size:13px;color:#e6edf3;line-height:1.6;padding-left:1.1em;position:relative}}
    .exec-summary-box li::before{{content:"・";position:absolute;left:0}}
    .sources{{max-width:680px;margin:20px auto 0;padding:0 12px}}
    .sources details{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:12px 16px}}
    .sources summary{{font-size:12px;color:#8b949e;cursor:pointer;list-style:none}}
    .sources summary::before{{content:"▶  ";font-size:10px}}
    details[open] summary::before{{content:"▼  "}}
    .sources ul{{margin-top:10px;list-style:none;display:flex;flex-wrap:wrap;gap:6px}}
    .sources li{{font-size:11px;padding:3px 10px;border-radius:100px;color:#fff}}
  </style>
</head>
<body>
  <header>
    <h1>🔐 Security Digest</h1>
    <div class="sub">最終更新: {esc(date_str)}</div>
    <div class="count">{esc(str(len(items)))} 件</div>
  </header>
  {exec_summary_html}
  <div class="cards">{cards_html}</div>
  <div class="sources">
    <details>
      <summary>収集元 ({esc(str(len(RSS_FEEDS)+2))}ソース)</summary>
      <ul>{sources_li}</ul>
    </details>
  </div>
</body>
</html>"""

# ── メイン ───────────────────────────────────────────────────────────────────

def main():
    out_path = Path(__file__).parent / "docs" / "index.html"
    out_path.parent.mkdir(exist_ok=True)

    print("フィードを収集中...")
    items = collect_recent()
    print(f"  {len(items)} 件取得")

    # 日次JSON(Ticket 3)向けに、翻訳で上書きされる前の原文タイトル・概要を
    # 収集直後のこの時点でスナップショットしておく(翻訳処理自体は変更しない)。
    fetched_at = datetime.datetime.now(JST)
    for item in items:
        item["raw_title"] = item["title"]
        item["raw_summary"] = item["summary"]

    time.sleep(15)
    exec_result = build_executive_summary(items)
    exec_summary = exec_result["lines"]

    cache = load_cache()
    print("タイトルを日本語に翻訳中...")
    for item in items:
        if item["lang"] == "en":
            item["title"]   = translate(item["title"],   cache)
            item["summary"] = translate(strip_html(item["summary"])[:200], cache)
    save_cache(cache)
    print(f"  翻訳キャッシュ: {len(cache)} 件")

    html = build_html(items, exec_summary)
    out_path.write_text(html, encoding="utf-8")
    print(f"  生成完了: {out_path}")

    print("日次JSONを保存中...")
    generated_at = datetime.datetime.now(JST)
    digest = daily_json.generate_and_save_daily_digest(
        items=items,
        exec_result=exec_result,
        source_definitions=SOURCE_DEFINITIONS,
        model=GEMINI_MODEL,
        fetched_at=fetched_at,
        generated_at=generated_at,
        data_dir=daily_json.DATA_DIR,
    )
    print(
        f"  日次JSON生成完了: data/{digest['digest_date']}.json "
        f"(run.status={digest['run']['status']})"
    )

if __name__ == "__main__":
    main()
