#!/bin/bash
# GitHub Pagesの初期設定とlaunchdへの登録

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST="$HOME/Library/LaunchAgents/com.user.security-digest.plist"

echo "=== Security Digest セットアップ ==="
echo ""

# git初期化
if [ ! -d "$DIR/.git" ]; then
  echo "▶ Gitリポジトリを初期化..."
  cd "$DIR"
  git init
  git add .
  git commit -m "initial commit"
fi

echo ""
echo "▶ 次の手順でGitHubリポジトリを作成してください:"
echo ""
echo "  1. https://github.com/new でリポジトリを作成"
echo "     名前例: security-digest"
echo "     ※ 必ず Public にすること（GitHub Pages無料枠の条件）"
echo ""
echo "  2. Settings → Pages → Branch: main / folder: /docs → Save"
echo ""
echo "  3. リモートを追加:"
echo "     git remote add origin https://github.com/あなたのユーザー名/security-digest.git"
echo "     git push -u origin main"
echo ""
read -p "上記が完了したらEnterを押してください..."
echo ""

# HTMLを生成して初回push
echo "▶ 初回HTMLを生成してpush..."
cd "$DIR"
python3 fetch.py
git add docs/index.html
git diff --cached --quiet || git commit -m "digest: initial"
git push origin main

echo ""
echo "▶ launchdに毎朝7:30の自動実行を登録..."
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.user.security-digest</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DIR/deploy.sh</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>7</integer>
    <key>Minute</key>
    <integer>30</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>$DIR/run.log</string>
  <key>StandardErrorPath</key>
  <string>$DIR/error.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

REPO_URL=$(git remote get-url origin 2>/dev/null | sed 's/\.git$//' | sed 's/github\.com:/github.com\//')
REPO_URL="${REPO_URL/git@github.com\//https:\/\/github.com\/}"
GH_USER=$(echo "$REPO_URL" | sed 's|https://github.com/||' | cut -d/ -f1)
REPO_NAME=$(echo "$REPO_URL" | sed 's|https://github.com/||' | cut -d/ -f2)
PAGES_URL="https://${GH_USER}.github.io/${REPO_NAME}/"

echo ""
echo "✅ セットアップ完了!"
echo ""
echo "  📱 iPhoneでブックマークするURL:"
echo "     $PAGES_URL"
echo ""
echo "  毎朝7:30に自動更新されます。"
echo "  停止: launchctl unload $PLIST"
