# Net Checker

Net Checker (netchecker) は、日常的なネットワーク診断・調査作業を 1 つのバイナリに集約した CLI ツールです。
ターミナル (CLI) からもブラウザ (Web UI) からも同じ機能を利用できます。

### 主な機能

- **HTTP ping**
  - HTTP/HTTPS リクエストによる Web サーバーの応答確認
  - ステータスコード・応答時間を表示
  - root 権限不要
- **ICMP ping**
  - ICMP Echo Request/Reply によるホストの到達性確認
  - 送信回数 (`-c`)、送信間隔 (`-i`)、タイムアウト (`-t`) を指定可能
  - RTT・パケットロス率を表示
  - root 権限が必要
- **traceroute**
  - ICMP ベースで宛先までのネットワーク経路をホップごとに表示
  - 各ホップの IP アドレスと RTT を表示
  - 最大ホップ数 (`-m`) を指定可能
  - root 権限が必要
- **nslookup**
  - OS のリゾルバ (`net.Resolver`) を使用した DNS 名前解決
  - A / AAAA / CNAME / MX / NS / TXT レコードをまとめて一括取得
- **dig**
  - 生の DNS パケット (UDP) を組み立てて送信する低レベルクエリ
  - UDP で応答が切り詰められた場合は TCP に自動フォールバック
  - RCode・Answer・Authority・Additional セクションを含む詳細な応答を表示
  - 対応レコードタイプ: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV
  - 問い合わせ先 DNS サーバーを `-server` で指定可能
  - 全レコードタイプの一括クエリにも対応 (Web API)
- **メール認証チェック**
  - SPF レコードの検出・パース
  - DKIM レコードの検出・パース
  - DMARC レコードの検出・パース
  - BIMI レコードの検出・パース
  - 1 コマンドで 4 種のメール認証レコードを一括チェック
- **TLS 証明書チェック**
  - 指定ホストに TLS 接続し、証明書チェーン全体を取得・検証
  - Subject、Issuer、有効期間、SAN を表示
  - 署名アルゴリズム、公開鍵情報を表示
  - TLS バージョン、暗号スイートを表示
  - 接続ポートを `-port` で指定可能 (デフォルト 443)
- **Web UI**
  - ブラウザ上のタブ切り替え UI で全機能を操作可能
  - ping と traceroute は SSE (Server-Sent Events) によるリアルタイムストリーミング表示
  - 静的ファイルを `go:embed` で埋め込んだシングルバイナリで提供
  - `--addr` でリッスンアドレスを変更可能 (デフォルト `:8080`)
  - REST API エンドポイントも利用可能

## インストール

### リリースバイナリ

[Releases](https://github.com/kidatti/netchecker/releases) ページからプラットフォームに合ったアーカイブをダウンロードして展開する。

### ソースからビルド

```bash
make build
```

## 使い方

### ping

ICMP ping (要 root):
```bash
sudo ./netchecker ping example.com
sudo ./netchecker ping -c 5 -i 0.5 -t 3 example.com
```

HTTP ping:
```bash
./netchecker ping --http https://example.com
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--http` | HTTP モードを使用 | `false` |
| `-c` | ping 回数 (0 = 無限) | `0` |
| `-i` | 間隔 (秒) | `1.0` |
| `-t` | タイムアウト (秒) | `5.0` |

### traceroute

```bash
sudo ./netchecker traceroute example.com
sudo ./netchecker traceroute -m 20 example.com
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `-m` | 最大ホップ数 | `30` |

### nslookup

```bash
./netchecker nslookup example.com
```

A/AAAA、CNAME、MX、NS、TXT レコードをまとめて取得する。

### dig

```bash
./netchecker dig example.com A
./netchecker dig example.com MX
./netchecker dig -server 1.1.1.1 example.com AAAA
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `-server` | DNS サーバーアドレス | `/etc/resolv.conf` または `8.8.8.8` |

対応レコードタイプ: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV

### tlscert

```bash
./netchecker tlscert example.com
./netchecker tlscert -port 8443 example.com
```

ホストに TLS 接続し、証明書チェーン全体の詳細情報を表示する。Subject、Issuer、有効期間、SAN、署名アルゴリズム、公開鍵情報、TLS バージョン、暗号スイートなど。

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `-port` | TLS 接続先ポート | `443` |

### Web UI

```bash
./netchecker serve
./netchecker serve --addr :3000
```

ブラウザで `http://localhost:8080` を開くと、タブ切り替え型の UI で全機能を利用可能。ping と traceroute は SSE によるリアルタイム表示。

Web 画面ではパブリック IP・国情報を表示するため、外部 API (`https://s.apiless.com/ip`) へアクセスします。

## API

Web サーバー起動時に以下のエンドポイントが利用可能:

| メソッド | パス | 説明 |
|---------|------|------|
| `GET` | `/api/ping/stream?host=...&icmp=bool` | ping (SSE) |
| `GET` | `/api/traceroute/stream?host=...` | traceroute (SSE) |
| `POST` | `/api/nslookup` | DNS lookup (JSON) |
| `POST` | `/api/dig` | DNS query (JSON) |
| `POST` | `/api/dig/all` | 全レコードタイプ一括クエリ (JSON) |
| `POST` | `/api/mailauth` | SPF/DKIM/DMARC/BIMI チェック (JSON) |
| `POST` | `/api/tlscert` | TLS 証明書チェック (JSON) |

### リクエスト例

```bash
# nslookup
curl -X POST http://localhost:8080/api/nslookup \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# dig
curl -X POST http://localhost:8080/api/dig \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","type":"MX"}'

# メール認証チェック
curl -X POST http://localhost:8080/api/mailauth \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# TLS 証明書チェック
curl -X POST http://localhost:8080/api/tlscert \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","port":"443"}'
```

## 必要な権限

| 機能 | root 権限 |
|------|----------|
| HTTP ping | 不要 |
| ICMP ping | 必要 (非特権モード失敗時) |
| traceroute | 必要 |
| nslookup | 不要 |
| dig | 不要 |
| Mail Auth | 不要 |
| TLS Cert | 不要 |
| Web UI | 不要 (ICMP/traceroute 使用時は必要) |

## ビルド

```bash
make build                    # ローカルビルド
make release VERSION=v1.0.0   # クロスコンパイル + アーカイブ (dist/ に出力)
make clean                    # ビルド成果物を削除
```

対応プラットフォーム: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64

## 依存関係

- Go 1.25+
- `golang.org/x/net` (ICMP, IPv4, DNS メッセージ)
