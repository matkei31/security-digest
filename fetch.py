#!/usr/bin/env python3
"""
Security Digest — サイバーセキュリティニュースを収集してindex.htmlを生成する
"""

import sys, json, datetime, time, re, os
import urllib.request, urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

# ── 設定 ────────────────────────────────────────────────────────────────────

MAX_PER_FEED = 3
DAYS_BACK    = 1

GEMINI_MODEL = "gemini-2.5-flash"

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

SOURCE_DEFINITIONS_PATH = Path(__file__).parent / "source_definitions.json"

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
            items.append({
                "title":   (item.findtext("title") or "").strip(),
                "link":    (item.findtext("link")  or "").strip(),
                "summary": (item.findtext("description") or "").strip(),
                "date":    parse_date(
                    item.findtext("pubDate") or
                    item.findtext("dc:date", namespaces=NAMESPACES)
                ),
                "source": name,
                "lang":   lang,
            })
    elif "feed" in tag:
        for entry in root.findall("atom:entry", NAMESPACES)[:MAX_PER_FEED]:
            link_el = (entry.find("atom:link[@rel='alternate']", NAMESPACES)
                    or entry.find("atom:link", NAMESPACES))
            items.append({
                "title":   (entry.findtext("atom:title",   namespaces=NAMESPACES) or "").strip(),
                "link":    (link_el.get("href") if link_el is not None else "").strip(),
                "summary": (entry.findtext("atom:summary", namespaces=NAMESPACES) or "").strip(),
                "date":    parse_date(
                    entry.findtext("atom:updated",   namespaces=NAMESPACES) or
                    entry.findtext("atom:published", namespaces=NAMESPACES)
                ),
                "source": name,
                "lang":   lang,
            })
    elif "rdf" in tag:
        # RSS 1.0 (RDF) 形式: 要素がデフォルト名前空間 (rss1) に属する
        for item in root.findall("rss1:item", NAMESPACES)[:MAX_PER_FEED]:
            items.append({
                "title":   (item.findtext("rss1:title",       namespaces=NAMESPACES) or "").strip(),
                "link":    (item.findtext("rss1:link",         namespaces=NAMESPACES) or "").strip(),
                "summary": (item.findtext("rss1:description",  namespaces=NAMESPACES) or "").strip(),
                "date":    parse_date(item.findtext("dc:date", namespaces=NAMESPACES)),
                "source": name,
                "lang":   lang,
            })
    return items

# ── CISA KEV (JSON) ───────────────────────────────────────────────────────────

def fetch_cisa_kev(cutoff):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityDigest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read())
    except Exception as e:
        print(f"[WARN] CISA KEV: {e}", file=sys.stderr)
        return []

    items = []
    for v in sorted(data.get("vulnerabilities", []),
                    key=lambda x: x.get("dateAdded", ""), reverse=True):
        date = parse_date(v.get("dateAdded"))
        if date and date < cutoff:
            break
        items.append({
            "title":   f"{v.get('cveID','')} — {v.get('vulnerabilityName','')}",
            "link":    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "summary": v.get("shortDescription", ""),
            "date":    date,
            "source":  "CISA KEV",
            "lang":    "en",
        })
        if len(items) >= MAX_PER_FEED:
            break
    return items

# ── NIST NVD (JSON API) ───────────────────────────────────────────────────────

def fetch_nist_nvd(cutoff):
    now   = datetime.datetime.utcnow()
    start = cutoff.strftime("%Y-%m-%dT00:00:00.000")
    end   = now.strftime("%Y-%m-%dT23:59:59.000")
    url   = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}&pubEndDate={end}"
        f"&resultsPerPage={MAX_PER_FEED}&cvssV3Severity=CRITICAL"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityDigest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read())
    except Exception as e:
        print(f"[WARN] NIST NVD: {e}", file=sys.stderr)
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
        items.append({
            "title":   title,
            "link":    f"https://nvd.nist.gov/vuln/detail/{cveid}",
            "summary": desc,
            "date":    parse_date(cve.get("published")),
            "source":  "NIST NVD",
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

    kev_items = fetch_cisa_kev(cutoff)
    kev_status = "OK" if kev_items else "NG"
    print(f"  [{kev_status}] CISA KEV: 取得 {len(kev_items)} 件")
    all_items += kev_items
    # all_items += fetch_nist_nvd(cutoff)

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


def fallback_ai_analysis(response_text, source_text):
    importance = extract_partial_field(response_text, "importance")
    if importance not in ("高", "中", "低"):
        importance_match = re.search(r"重要度\s*[:：]\s*([高中低])", response_text or "")
        importance = importance_match.group(1) if importance_match else "中"

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
    if not summary:
        return None

    if not impact:
        impact = (
            "金融機関への直接的な影響は情報不足のため判断できません。"
            "関連製品、業務、委託先との接点確認が必要です。"
        )

    actions = []
    actions_match = re.search(
        r'"recommended_actions"\s*:\s*\[(.*)',
        response_text or "",
        re.DOTALL,
    )
    if actions_match:
        actions = [
            value.strip()
            for value in re.findall(r'"((?:\\.|[^"])*)"', actions_match.group(1))
            if value.strip()
        ]
    if not actions:
        actions = [
            "原文と公表元の最新情報を確認する",
            "関連製品や委託先の利用有無を確認する",
        ]

    return normalize_ai_analysis({
        "importance": importance,
        "summary": summary,
        "financial_impact": impact[:140],
        "recommended_actions": actions[:3],
    })


def gemini_analyze(text):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    prompt = f"""
あなたは日本の金融機関で働く、サイバーセキュリティとIT監査のシニアアナリストです。
以下のニュースだけを根拠に、金融機関の実務担当者が短時間で判断できる分析を日本語で作成してください。

評価基準:
- 重要度「高」: 悪用確認済み、緊急対応が必要、金融サービス停止・情報漏えい・不正取引に直結し得る
- 重要度「中」: 関連製品や業務への影響確認、計画的な対応や監視強化が必要
- 重要度「低」: 一般情報、限定的な影響、直ちに対応する必要が低い

記述ルール:
- 要約は「誰が何を公表し、何が起きたか」を具体的に、120文字以内で書く
- 金融機関への影響は、該当するシステム・委託先・業務・リスクを具体的に、140文字以内で書く
- 推奨アクションは、担当者が実行できる確認・対応を優先順に1〜3件、各80文字以内で書く
- 入力にない事実、製品利用状況、被害、期限は推測しない
- 金融機関との直接的な関係が薄い場合も、その旨と確認すべき接点を明記する
- 見出し、Markdown、コードブロックは出力しない

ニュース:
{text}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 800,
            "thinking_config": {
                "thinking_budget": 0
            },
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "OBJECT",
                "propertyOrdering": [
                    "importance",
                    "summary",
                    "financial_impact",
                    "recommended_actions"
                ],
                "properties": {
                    "importance": {
                        "type": "STRING",
                        "enum": ["高", "中", "低"],
                        "description": "金融機関にとっての対応優先度"
                    },
                    "summary": {
                        "type": "STRING",
                        "description": "ニュースの具体的な日本語要約"
                    },
                    "financial_impact": {
                        "type": "STRING",
                        "description": "金融機関のシステム、業務、委託先への影響"
                    },
                    "recommended_actions": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                        "minItems": 1,
                        "maxItems": 3,
                        "description": "優先順の実務対応"
                    }
                },
                "required": [
                    "importance",
                    "summary",
                    "financial_impact",
                    "recommended_actions"
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
            analysis = parse_ai_analysis(response_text)
            if analysis:
                return analysis

            text_length = len(response_text) if isinstance(response_text, str) else 0
            fallback = fallback_ai_analysis(response_text, text)
            if fallback:
                print(
                    f"[WARN] Gemini要約: JSON解析失敗 "
                    f"(応答長: {text_length}文字)、部分応答から補完",
                    file=sys.stderr,
                )
                return fallback

            print(
                f"[WARN] Gemini要約: JSON解析失敗 (応答長: {text_length}文字)",
                file=sys.stderr,
            )
            return None
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
            return None
        except Exception as e:
            print(
                f"[WARN] Gemini要約: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return None

    return None


def enrich_with_ai(items):
    if not os.environ.get("GEMINI_API_KEY"):
        return items

    print("Geminiで重要度・要約を生成中...")
    count = 0
    attempts = 0

    for item in items:
        attempts += 1

        text = f"""
source: {item.get('source', '')}
title: {item.get('title', '')}
summary: {strip_html(item.get('summary', ''))}
link: {item.get('link', '')}
"""
        analysis = gemini_analyze(text)

        if analysis:
            item["ai_analysis"] = analysis
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
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

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
                return lines

            print("[WARN] エグゼクティブサマリー: JSON解析失敗", file=sys.stderr)
            return None
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
            return None
        except Exception as e:
            print(
                f"[WARN] エグゼクティブサマリー: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return None

    return None


def build_executive_summary(items):
    high_items = [
        item for item in items
        if normalize_ai_analysis(item.get("ai_analysis")) is not None
        and normalize_ai_analysis(item.get("ai_analysis"))["importance"] == "高"
    ]
    if not high_items:
        return None

    print("エグゼクティブサマリーを生成中...")
    lines = gemini_executive_summary(high_items)
    if lines:
        print(f"  エグゼクティブサマリー: {len(lines)} 行")
    else:
        print("  エグゼクティブサマリー: 生成失敗")
    return lines


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

    time.sleep(15)
    exec_summary = build_executive_summary(items)

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

if __name__ == "__main__":
    main()
