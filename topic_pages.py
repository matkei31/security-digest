#!/usr/bin/env python3
"""BL-051: Monomi Digest topic-page v0.1 generator.

This module is intentionally separate from ``fetch.py``.  The daily collector remains the
source of truth for article analysis and ordering; after ``fetch.py`` has generated the normal
site output, this module derives topic index pages from the already validated daily digests.

v0.1 does not add a new AI classification step and does not change the daily JSON schema.
Existing ARTICLE ``category`` is treated as the primary classification and existing ``tags``
are used as cross-cutting signals.  A topic is published only when it has at least five matching
articles spanning at least two digest dates.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import daily_json
import fetch


MIN_TOPIC_ARTICLES = 5
MIN_TOPIC_DATES = 2
TOPICS_DIRNAME = "topics"
TOPIC_INDEX_LABEL = "テーマから探す"
TOPIC_INDEX_PATH = "topics/"
SITEMAP_BLOCK_START = "  <!-- BEGIN topic_pages.py -->"
SITEMAP_BLOCK_END = "  <!-- END topic_pages.py -->"
TOP_NAV_LINK_HTML = '<a class="archive-link" href="topics/">テーマから探す</a>'


@dataclass(frozen=True)
class TopicDefinition:
    slug: str
    label: str
    description: str
    categories: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


TOPIC_DEFINITIONS: tuple[TopicDefinition, ...] = (
    TopicDefinition(
        slug="vulnerabilities",
        label="脆弱性・パッチ",
        description="脆弱性、実悪用、KEV、ゼロデイ、パッチ対応に関する情報。",
        categories=("脆弱性・パッチ",),
        tags=("CVE", "KEV", "ゼロデイ", "悪用確認済み", "パッチ"),
    ),
    TopicDefinition(
        slug="threats",
        label="攻撃・脅威動向",
        description="攻撃キャンペーン、脅威アクター、フィッシングなどの脅威動向。",
        categories=("攻撃・脅威動向",),
        tags=("APT", "フィッシング"),
    ),
    TopicDefinition(
        slug="incidents",
        label="インシデント",
        description="侵害、情報漏えい、業務停止など実際に発生したインシデント。",
        categories=("インシデント",),
        tags=("インシデント", "情報漏えい", "業務停止"),
    ),
    TopicDefinition(
        slug="regulation-governance",
        label="規制・ガバナンス",
        description="規制、監督、ガイドライン、業界基準やガバナンスに関する情報。",
        categories=("規制・ガバナンス",),
        tags=("規制", "ガイドライン", "監督", "DORA", "NIST", "SWIFT", "CSCF"),
    ),
    TopicDefinition(
        slug="identity-access",
        label="認証・IAM",
        description="認証、ID管理、アクセス管理に関する横断的な情報。",
        tags=("認証", "IAM"),
    ),
    TopicDefinition(
        slug="cloud-supply-chain",
        label="クラウド・サプライチェーン",
        description="クラウド、SaaS、委託先、サプライチェーンに関する情報。",
        categories=("クラウド・サプライチェーン",),
        tags=("クラウド", "SaaS", "サプライチェーン", "委託先管理"),
    ),
    TopicDefinition(
        slug="ai",
        label="AI・新技術リスク",
        description="AI、LLM、AIエージェントなど新技術に伴うサイバーリスク。",
        categories=("AI・新技術リスク",),
        tags=("AI", "LLM", "AIエージェント"),
    ),
    TopicDefinition(
        slug="ransomware",
        label="ランサムウェア",
        description="ランサムウェア攻撃、恐喝、関連インシデントを横断して確認するテーマ。",
        tags=("ランサムウェア",),
    ),
)


@dataclass(frozen=True)
class TopicArticle:
    digest_date: str
    article_index: int
    title: str
    source: str
    summary: str
    importance: str
    urgency: str
    category: str
    tags: tuple[str, ...]

    @property
    def archive_href(self) -> str:
        return f"/archive/{self.digest_date}.html#article-{self.article_index}"


@dataclass(frozen=True)
class PublishedTopic:
    definition: TopicDefinition
    articles: tuple[TopicArticle, ...]

    @property
    def article_count(self) -> int:
        return len(self.articles)

    @property
    def date_count(self) -> int:
        return len({article.digest_date for article in self.articles})

    @property
    def latest_date(self) -> str:
        return max(article.digest_date for article in self.articles)


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _format_date_ja(date_text: str) -> str:
    parsed = _dt.date.fromisoformat(date_text)
    return f"{parsed.year}年{parsed.month}月{parsed.day}日"


def _topic_matches(definition: TopicDefinition, category: str, tags: Iterable[str]) -> bool:
    tag_set = set(tags)
    return category in definition.categories or bool(tag_set.intersection(definition.tags))


def _article_from_display_item(digest_date: str, index: int, item: dict) -> TopicArticle | None:
    analysis = item.get("ai_analysis") or {}
    if not isinstance(analysis, dict):
        return None
    category = analysis.get("category")
    tags = analysis.get("tags") or []
    if not isinstance(category, str) or not isinstance(tags, list):
        return None
    tags = tuple(tag for tag in tags if isinstance(tag, str))
    title = item.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    return TopicArticle(
        digest_date=digest_date,
        article_index=index,
        title=title,
        source=str(item.get("source") or ""),
        summary=str(analysis.get("summary") or ""),
        importance=str(analysis.get("importance") or ""),
        urgency=str(analysis.get("urgency") or ""),
        category=category,
        tags=tags,
    )


def collect_topic_articles(data_dir: Path, docs_dir: Path) -> dict[str, list[TopicArticle]]:
    """Collect topic matches from the same validated, published digests used by Archive.

    Display positions are computed with ``fetch.sort_items_for_display`` so the generated
    ``#article-N`` link points at the exact card position in the daily Archive.
    """
    collected = {definition.slug: [] for definition in TOPIC_DEFINITIONS}
    published_dates = fetch.load_validated_published_digest_dates(
        data_dir=data_dir,
        docs_dir=docs_dir,
    )
    for digest_date in sorted(published_dates, reverse=True):
        digest = fetch.load_daily_digest(Path(data_dir) / f"{digest_date}.json")
        display_items = fetch.sort_items_for_display(fetch.digest_items_for_html(digest))
        for index, item in enumerate(display_items, start=1):
            article = _article_from_display_item(digest_date, index, item)
            if article is None:
                continue
            for definition in TOPIC_DEFINITIONS:
                if _topic_matches(definition, article.category, article.tags):
                    collected[definition.slug].append(article)
    return collected


def select_published_topics(collected: dict[str, Sequence[TopicArticle]]) -> tuple[PublishedTopic, ...]:
    published = []
    for definition in TOPIC_DEFINITIONS:
        articles = tuple(collected.get(definition.slug, ()))
        if len(articles) < MIN_TOPIC_ARTICLES:
            continue
        if len({article.digest_date for article in articles}) < MIN_TOPIC_DATES:
            continue
        published.append(PublishedTopic(definition=definition, articles=articles))
    return tuple(published)


def _shared_style() -> str:
    return (
        "*{box-sizing:border-box;margin:0;padding:0}\n"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans JP',sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;padding-bottom:36px}\n"
        "header{background:#161b22;border-bottom:1px solid #30363d;padding:14px 20px;position:sticky;top:0;z-index:10}\n"
        "header h1{font-size:18px;font-weight:600;color:#e6edf3}\n"
        ".sub,.topic-meta{font-size:12px;color:#8b949e;line-height:1.5}\n"
        ".topic-nav{display:flex;flex-wrap:wrap;gap:12px;margin-top:8px}\n"
        ".topic-link{color:#79c0ff;text-decoration:none;font-weight:700}\n"
        ".topic-link:hover{text-decoration:underline}\n"
        ".topic-list{max-width:680px;margin:12px auto 0;padding:0 12px;list-style:none;display:grid;gap:10px}\n"
        ".topic-item{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 16px;display:grid;gap:5px}\n"
        ".topic-item h2{font-size:14px;line-height:1.5}\n"
        ".topic-description,.topic-summary{font-size:12px;color:#c9d1d9;line-height:1.65}\n"
        ".topic-summary{margin-top:2px}\n"
        ".site-footer{max-width:680px;margin:20px auto 0;padding:0 12px}\n"
        ".analytics-notice{font-size:11px;color:#768496;line-height:1.6}\n"
        "@media(max-width:600px){header{padding:12px}.topic-list{padding:0 10px}.topic-item{padding:12px 14px}}"
    )


def _page_shell(*, title: str, description: str, canonical_url: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_esc(title)}</title>
  <meta name="description" content="{_esc(description)}">
  <link rel="canonical" href="{_esc(canonical_url)}">
  <style>
    {_shared_style()}
  </style>
</head>
<body>
{body}
  {fetch.render_analytics_footer_html()}
  {fetch.render_cloudflare_web_analytics_html()}
</body>
</html>
"""


def build_topic_index_html(published_topics: Sequence[PublishedTopic]) -> str:
    items = []
    for topic in published_topics:
        d = topic.definition
        items.append(
            f"""<li class="topic-item">
      <h2><a class="topic-link" href="/topics/{_esc(d.slug)}/">{_esc(d.label)}</a></h2>
      <div class="topic-meta">{topic.article_count}件 ・ {_esc(str(topic.date_count))}日 ・ 最新 {_esc(_format_date_ja(topic.latest_date))}</div>
      <p class="topic-description">{_esc(d.description)}</p>
    </li>"""
        )
    list_body = "\n    ".join(items) if items else (
        '<li class="topic-item"><p class="topic-description">公開条件を満たすテーマはまだありません。</p></li>'
    )
    body = f"""  <header>
    <h1>テーマから探す</h1>
    <div class="sub">既存の記事分類をもとに、複数日にまたがる主要テーマをまとめています。</div>
    <nav class="topic-nav"><a class="topic-link" href="/">最新のダイジェスト</a><a class="topic-link" href="/archive/">過去のダイジェスト</a></nav>
  </header>
  <ul class="topic-list">
    {list_body}
  </ul>"""
    return _page_shell(
        title="テーマから探す | Monomi Digest",
        description="Monomi Digestの記事を、脆弱性・インシデント・規制・認証・AIなどのテーマ別にまとめています。",
        canonical_url=fetch.public_url(TOPIC_INDEX_PATH),
        body=body,
    )


def build_topic_html(topic: PublishedTopic) -> str:
    d = topic.definition
    items = []
    for article in topic.articles:
        assessment_parts = []
        if article.importance:
            assessment_parts.append(f"重要度 {_esc(article.importance)}")
        if article.urgency:
            assessment_parts.append(f"確認目安 {_esc(article.urgency)}")
        assessment = " ・ ".join(assessment_parts)
        meta = f"{_esc(_format_date_ja(article.digest_date))} ・ {_esc(article.source)}"
        if assessment:
            meta += f" ・ {assessment}"
        summary_html = (
            f'<p class="topic-summary">{_esc(article.summary)}</p>' if article.summary else ""
        )
        items.append(
            f"""<li class="topic-item">
      <h2><a class="topic-link" href="{_esc(article.archive_href)}">{_esc(article.title)}</a></h2>
      <div class="topic-meta">{meta}</div>
      {summary_html}
    </li>"""
        )
    items_body = "\n    ".join(items)
    body = f"""  <header>
    <h1>{_esc(d.label)}</h1>
    <div class="sub">{_esc(d.description)} {topic.article_count}件を掲載。</div>
    <nav class="topic-nav"><a class="topic-link" href="/topics/">テーマ一覧</a><a class="topic-link" href="/">最新のダイジェスト</a></nav>
  </header>
  <ul class="topic-list">
    {items_body}
  </ul>"""
    return _page_shell(
        title=f"{d.label} | Monomi Digest",
        description=f"Monomi Digestで公開した{d.label}に関するサイバーセキュリティ情報をまとめています。",
        canonical_url=fetch.public_url(f"topics/{d.slug}/"),
        body=body,
    )


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fetch.atomic_write_text(path, content)


def write_topic_pages(docs_dir: Path, published_topics: Sequence[PublishedTopic]) -> None:
    topics_dir = Path(docs_dir) / TOPICS_DIRNAME
    topics_dir.mkdir(parents=True, exist_ok=True)
    _write_text(topics_dir / "index.html", build_topic_index_html(published_topics))

    published_slugs = {topic.definition.slug for topic in published_topics}
    for topic in published_topics:
        _write_text(topics_dir / topic.definition.slug / "index.html", build_topic_html(topic))

    # Remove only files/directories owned by this registry.  Unknown siblings under
    # docs/topics are never swept, so a future manually managed asset is not deleted.
    for definition in TOPIC_DEFINITIONS:
        if definition.slug in published_slugs:
            continue
        stale_dir = topics_dir / definition.slug
        if stale_dir.exists():
            shutil.rmtree(stale_dir)


def inject_top_navigation_link(index_path: Path) -> None:
    text = index_path.read_text(encoding="utf-8")
    if TOP_NAV_LINK_HTML in text:
        if text.count(TOP_NAV_LINK_HTML) != 1:
            raise RuntimeError("topic navigation link appears more than once")
        return
    marker = (
        '<div class="archive-nav-group archive-global-nav">'
        '<a class="archive-link" href="archive/index.html">過去のダイジェスト</a>'
        '</div>'
    )
    replacement = (
        '<div class="archive-nav-group archive-global-nav">'
        '<a class="archive-link" href="archive/index.html">過去のダイジェスト</a>'
        f'{TOP_NAV_LINK_HTML}'
        '</div>'
    )
    if text.count(marker) != 1:
        raise RuntimeError("top-page global navigation marker is missing or ambiguous")
    fetch.atomic_write_text(index_path, text.replace(marker, replacement, 1))


def _topic_sitemap_block(published_topics: Sequence[PublishedTopic]) -> str:
    urls = [fetch.public_url(TOPIC_INDEX_PATH)] + [
        fetch.public_url(f"topics/{topic.definition.slug}/") for topic in published_topics
    ]
    url_lines = []
    for url in urls:
        url_lines.extend(("  <url>", f"    <loc>{_esc(url)}</loc>", "  </url>"))
    return "\n".join((SITEMAP_BLOCK_START, *url_lines, SITEMAP_BLOCK_END))


def update_sitemap(sitemap_path: Path, published_topics: Sequence[PublishedTopic]) -> None:
    text = sitemap_path.read_text(encoding="utf-8")
    if SITEMAP_BLOCK_START in text or SITEMAP_BLOCK_END in text:
        if text.count(SITEMAP_BLOCK_START) != 1 or text.count(SITEMAP_BLOCK_END) != 1:
            raise RuntimeError("topic sitemap block markers are incomplete or duplicated")
        before, remainder = text.split(SITEMAP_BLOCK_START, 1)
        _, after = remainder.split(SITEMAP_BLOCK_END, 1)
        text = before.rstrip() + "\n" + after.lstrip("\n")
    closing = "</urlset>"
    if text.count(closing) != 1:
        raise RuntimeError("sitemap urlset closing tag is missing or ambiguous")
    block = _topic_sitemap_block(published_topics)
    updated = text.replace(closing, f"{block}\n{closing}", 1)
    fetch.atomic_write_text(sitemap_path, updated)


def generate_topic_outputs(data_dir: Path | None = None, docs_dir: Path | None = None) -> tuple[PublishedTopic, ...]:
    data_dir = Path(data_dir) if data_dir is not None else Path(daily_json.DATA_DIR)
    docs_dir = Path(docs_dir) if docs_dir is not None else Path(fetch.DOCS_DIR)
    collected = collect_topic_articles(data_dir, docs_dir)
    published = select_published_topics(collected)
    write_topic_pages(docs_dir, published)
    inject_top_navigation_link(docs_dir / "index.html")
    update_sitemap(docs_dir / "sitemap.xml", published)
    return published


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Monomi Digest topic pages from published daily digests")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--docs-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    published = generate_topic_outputs(data_dir=args.data_dir, docs_dir=args.docs_dir)
    summary = ", ".join(f"{topic.definition.slug}:{topic.article_count}" for topic in published) or "none"
    print(f"topic pages: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
