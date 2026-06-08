#!/usr/bin/env python3
"""
Security Digest — サイバーセキュリティニュースを収集してindex.htmlを生成する
"""

import sys, json, datetime, time, re, os
import urllib.request, urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

# ── 設定 ────────────────────────────────────────────────────────────────────

# (表示名, RSSのURL, 言語)  lang="ja" なら翻訳スキップ
RSS_FEEDS = [
    # 国内・官公庁
    ("金融庁",             "https://www.fsa.go.jp/fsaNewsListAll_rss2.xml",              "ja"),
    ("JPCERT/CC",          "https://www.jpcert.or.jp/rss/jpcert.rdf",                   "ja"),
    ("IPA",                "https://www.ipa.go.jp/security/rss/alert.rdf",              "ja"),

    # 海外・政府/標準
    ("CISA",               "https://www.cisa.gov/cybersecurity-advisories/all.xml",     "en"),
    ("NIST",               "https://www.nist.gov/news-events/news/rss.xml",             "en"),

    # ベンダ・脅威情報
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/",       "en"),
    ("Mandiant",           "https://www.mandiant.com/resources/blog/rss.xml",           "en"),
    ("CrowdStrike",        "https://www.crowdstrike.com/blog/feed/",                    "en"),
    ("Google TAG",         "https://security.googleblog.com/feeds/posts/default",       "en"),
    ("NCSC",               "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml","en"),

    # 実務系
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/",                         "en"),
    ("Dark Reading",       "https://www.darkreading.com/rss.xml",                       "en"),
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews",               "en"),
    ("Cisco Talos",        "https://blog.talosintelligence.com/rss/",                    "en"),
    ("Cloudflare",         "https://blog.cloudflare.com/rss/",                            "en"),
]
MAX_PER_FEED = 5
DAYS_BACK    = 1

MAX_AI_SUMMARIES = 3
GEMINI_MODEL = "gemini-2.5-flash"


SOURCE_COLORS = {
    "金融庁":             "#c0392b",
    "JPCERT/CC":          "#2471a3",
    "CISA":               "#1e8449",
    "CISA KEV":           "#e74c3c",
    "Microsoft Security": "#0078d4",
    "NIST NVD":           "#7d3c98",
    "Mandiant":           "#e67e22",
    "CrowdStrike":        "#cc0000",
    "Google TAG":         "#4285f4",
    "NCSC":               "#005eb8",
    "Cisco Talos":        "#6f42c1",
    "Cloudflare":         "#f38020",
}

NAMESPACES = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc":   "http://purl.org/dc/elements/1.1/",
}

CACHE_PATH = Path(__file__).parent / "docs" / "translate_cache.json"

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

def collect_recent():
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=DAYS_BACK)
    all_items = []

    for name, url, lang in (f for f in RSS_FEEDS if not f[1].startswith("#")):
        for item in fetch_feed(name, url, lang):
            if item["date"] is None or item["date"] >= cutoff:
                all_items.append(item)

    all_items += fetch_cisa_kev(cutoff)
    # all_items += fetch_nist_nvd(cutoff)

    all_items.sort(key=lambda x: x["date"] or datetime.datetime.min, reverse=True)
    all_items = enrich_with_ai(all_items)
    return all_items

# ── HTML生成 ─────────────────────────────────────────────────────────────────

def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))

def strip_html(s):
    return re.sub(r"<[^>]+>", "", s).strip()


# ── Gemini AI要約 ─────────────────────────────────────────────────────────────

def gemini_analyze(text):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return ""

    prompt = f"""
あなたは金融機関・監査・サイバーセキュリティの実務者向けアナリストです。
以下のニュースを日本語で簡潔に分析してください。

出力形式は必ず以下にしてください。

重要度: 高/中/低
要約: 100文字以内
金融機関への影響: 120文字以内
推奨アクション:
- 1つ目
- 2つ目
- 3つ目

ニュース:
{text}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 300
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            data = json.loads(res.read())
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        print(f"[WARN] Gemini要約: {e}", file=sys.stderr)
        return ""


def enrich_with_ai(items):
    if not os.environ.get("GEMINI_API_KEY"):
        return items

    print("Geminiで重要度・要約を生成中...")
    count = 0
    attempts = 0

    for item in items:
        if attempts >= MAX_AI_SUMMARIES:
            break

        attempts += 1

        text = f"""
source: {item.get('source', '')}
title: {item.get('title', '')}
summary: {strip_html(item.get('summary', ''))}
link: {item.get('link', '')}
"""
        analysis = gemini_analyze(text)

        if analysis:
            item["summary"] = analysis
            count += 1

        time.sleep(8)

    print(f"  AI要約: {count} 件 / 試行: {attempts} 件")
    return items



def build_html(items):
    now      = datetime.datetime.now()
    date_str = now.strftime("%Y年%m月%d日 %H:%M")

    cards = []
    for item in items:
        color      = SOURCE_COLORS.get(item["source"], "#555")
        date_label = item["date"].strftime("%m/%d %H:%M") if item["date"] else ""
        raw_summary = strip_html(item["summary"])
        is_ai_summary = "重要度:" in raw_summary and "金融機関への影響:" in raw_summary
        max_len = 700 if is_ai_summary else 120
        summary = raw_summary[:max_len]
        summary_class = "summary ai-summary" if is_ai_summary else "summary"
        summary_html = f'<p class="{summary_class}">{esc(summary)}{"…" if len(raw_summary) > max_len else ""}</p>' if summary else ""
        cards.append(f"""
    <a class="card" href="{esc(item['link'])}" target="_blank" rel="noopener">
      <div class="card-meta">
        <span class="tag" style="background:{color}">{esc(item['source'])}</span>
        <span class="date">{date_label}</span>
      </div>
      <h2>{esc(item['title'])}</h2>
      {summary_html}
    </a>""")

    cards_html = "\n".join(cards) if cards else '<p class="empty">本日の新着はありません。</p>'
    all_sources = [f for f in RSS_FEEDS if not f[1].startswith("#")] + [("CISA KEV","","")]
    sources_li = "".join(
        '<li style="background:{}">{}</li>'.format(SOURCE_COLORS.get(n, "#555"), esc(n))
        for n, *_ in all_sources
    )

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
    .empty{{text-align:center;color:#8b949e;padding:60px 0;font-size:14px}}
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
    <div class="sub">最終更新: {date_str}</div>
    <div class="count">{len(items)} 件</div>
  </header>
  <div class="cards">{cards_html}</div>
  <div class="sources">
    <details>
      <summary>収集元 ({len(RSS_FEEDS)+2}ソース)</summary>
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

    cache = load_cache()
    print("タイトルを日本語に翻訳中...")
    for item in items:
        if item["lang"] == "en":
            item["title"]   = translate(item["title"],   cache)
            item["summary"] = translate(strip_html(item["summary"])[:200], cache)
    save_cache(cache)
    print(f"  翻訳キャッシュ: {len(cache)} 件")

    html = build_html(items)
    out_path.write_text(html, encoding="utf-8")
    print(f"  生成完了: {out_path}")

if __name__ == "__main__":
    main()
