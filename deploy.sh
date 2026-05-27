#!/bin/bash
# RSSを取得してHTMLを生成し、GitHub Pagesにpushする

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

python3 fetch.py

git add docs/index.html
git diff --cached --quiet && { echo "変更なし。スキップ。"; exit 0; }

DATE=$(date "+%Y-%m-%d %H:%M")
git commit -m "digest: $DATE"
git push origin main

echo "✅ GitHub Pagesに公開しました。"
