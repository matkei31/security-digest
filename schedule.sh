#!/bin/bash
# macOS launchd に毎朝8時の自動実行を登録するスクリプト

PLIST_NAME="com.user.security-digest"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/fetch.py"

if [ -z "$LINE_NOTIFY_TOKEN" ]; then
  echo "❌ LINE_NOTIFY_TOKEN が未設定です。"
  echo ""
  echo "  1. https://notify-bot.line.me/my/ でトークンを発行"
  echo "  2. 以下を実行してから再度このスクリプトを実行してください:"
  echo ""
  echo "     export LINE_NOTIFY_TOKEN='your_token_here'"
  echo "     ./schedule.sh"
  exit 1
fi

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(which python3)</string>
    <string>${SCRIPT_PATH}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LINE_NOTIFY_TOKEN</key>
    <string>${LINE_NOTIFY_TOKEN}</string>
  </dict>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>8</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>$(dirname "$SCRIPT_PATH")/run.log</string>
  <key>StandardErrorPath</key>
  <string>$(dirname "$SCRIPT_PATH")/error.log</string>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" 2>/dev/null
launchctl load "$PLIST_PATH"

echo "✅ 毎朝8:00に自動送信するよう登録しました。"
echo "   設定ファイル: $PLIST_PATH"
echo "   ログ: $(dirname "$SCRIPT_PATH")/run.log"
echo ""
echo "今すぐテスト送信するには:"
echo "   python3 ${SCRIPT_PATH}"
echo ""
echo "停止するには:"
echo "   launchctl unload $PLIST_PATH"
