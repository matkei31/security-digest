# 🔐 Security Digest

サイバーセキュリティニュースを毎朝LINEに送る自動収集システム

## 収集元
- Bleeping Computer
- The Hacker News
- Krebs on Security
- Dark Reading
- Schneier on Security
- SecurityWeek
- CISA Alerts

## セットアップ手順

### 1. LINE Notify トークンを取得
1. https://notify-bot.line.me/my/ にアクセス（LINEアカウントでログイン）
2. 「トークンを発行する」をクリック
3. トークン名（例：`Security News`）を入力
4. 通知を送るトーク（「1:1でLINE Notifyから通知を受け取る」推奨）を選択
5. 発行されたトークンをコピー

### 2. テスト実行
```bash
cd ~/Desktop/security-digest
export LINE_NOTIFY_TOKEN='ここにトークンを貼り付け'
python3 fetch.py
```

### 3. 毎朝8時に自動送信を設定
```bash
export LINE_NOTIFY_TOKEN='ここにトークンを貼り付け'
chmod +x schedule.sh
./schedule.sh
```

## コマンド

| コマンド | 説明 |
|---------|------|
| `python3 fetch.py` | 今すぐ送信 |
| `python3 fetch.py --dry-run` | LINEに送らずプレビューだけ表示 |
| `./schedule.sh` | 毎朝8時の自動送信を登録 |
| `cat run.log` | 実行ログを確認 |

## カスタマイズ（fetch.py）

- `RSS_FEEDS` — フィードの追加・削除
- `MAX_PER_FEED` — 1ソースあたりの取得件数（デフォルト3件）
- `DAYS_BACK` — 何日前までの記事を含めるか（デフォルト1日）
- `schedule.sh` の `Hour` — 送信時刻（デフォルト8時）
