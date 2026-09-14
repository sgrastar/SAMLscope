# DeepSeekへの引き継ぎプロンプト

あなたは `/Users/yuta/Documents/SAMLscope` を引き継ぐ実装担当です。最初にこのファイルを含む署名付きコミットのSHAと現在のHEAD、作業ツリーの差分を記録してください。引き継ぎ後の修正は、そのコミットとの差分で追跡できるようにしてください。このコミットは作業途中の保存であり、リリース承認ではありません。

## 目的と進め方

ユーザーの依頼は「できる限り未実装の判定処理、試験条件の実装、確認経路、追加観測、個別診断を実装してください。目標は0件です。必要ない場合は、都度テストを走らせず50件くらいずつ解消したら試験してみてください。数件解決するごとに試験はしないでください。実装漏れがないよう時たまチェックしてください」です。

追加実装を進め、実製品で証拠を集めて未検証を解消してください。単体テストの条件数を増やしただけで、未検証を解消したと数えないでください。設定を代行しても設定作業がなくなったことにはなりません。設定書き込み・復元・再読み込み・ブラウザ操作・ユーザー本人の操作を区別して記録し、設定の再利用と必要操作の削減を優先してください。

ローカルの実装・検証・検証環境への反映は許可済みです。公開、push、本番リリースは今回の依頼には含まれません。既存のG1/G2承認を新しいソースの独立承認として流用しないでください。

## 必読と判定上の制約

ローカルの `AGENTS.md` と `docs/README.md`、`docs/03-test-model.md`、`docs/05-test-definition-format.md`、`docs/02-architecture.md`、`docs/11-review-log.md` を読んでください。特に以下を守ってください。

- G1保護対象 `tests/coverage.yaml`、`tests/specs.yaml`、`tests/predicates.yaml`、`tests/approvals/*` は編集禁止。
- CaseはOutcomeのみを返し、VerdictはEvaluatorが決める。送信はoutboxのみ。actionIdは決定的に生成する。
- UNKNOWN_DELIVERY、証拠欠落、試験経路不備を製品のFailedにしない。環境未整備をNOT_APPLICABLEに逃がさない。
- 承認済みvariant、linked_obligations、positive/negative controlsを満たす。ソースの存在や設定値だけでプロトコル適合を確定しない。
- Redirect署名はURLデコード前のraw queryで確認する。認証情報はRecorder投入前に除去する。
- 生成文書は生成器で更新する。文書内の数値は既存のG1マーカー規則に従う。
- ignore対象は追跡済みでもコミットしない。private/、AGENTS.md、.authrim/、.authrim_keys/、.authrim-keys/をステージに入れない。

## 現在の進捗

<!--g1-literal--> Phase 1は未完了でリリース不可。基準の未検証594件から27件を確定し、残り567件、異なるケースIDは180件。これは製品×プロファイル×ケースの延べ観測数で、単一Runの完走や適合率ではない。Phase 2はスコープ案、以降も未完了。

<!--g1-literal--> 残件内訳は、自動判定未実装102、試験条件の部分実装61、設定後の証拠確認・自己申告経路187、自己申告無効75、メタデータ観測不足71、ブラウザ/SLO観測不足20、個別診断51。詳細は `docs/26-unverified-case-inventory.md`。

製品ごとの比較は `docs/23-reference-test-comparison.md`、操作台帳は `docs/25-interaction-execution-cost.md`、実装履歴は `docs/27-additional-implementation.md`。比較はケースごとに採用Runが異なるため、最新Runの総数と混同しないこと。

<!--g1-literal--> 計測対象の追加試験では設定書き込み39回（復元込み）、製品再読み込み16回、代行ブラウザ操作17回、本人操作0回。計測以前の環境構築は未計測でありゼロではない。

## 実行環境と確認済み範囲

ローカル検証Suiteの最後の反映イメージは `samlscope:reference-key-capability-v18`。実際の起動状態はDockerで再確認すること。Suiteは18080、Keycloakは18180、Shibbolethは18280、SimpleSAMLphpは18380。実行証拠はignore対象 `build/acceptance/reference-20260914/` にあり、このコミットには含めていない。同じマシンでは参照できるが、別環境へcloneしただけでは証拠は手に入らない。

基本SLOと署名付きRedirect LogoutRequestは全製品でSuccess確認済み。Shibbolethでは暗号化NameID、複数復号鍵、両試験の同一Run証拠による設定能力確認もSuccess。KeycloakのSAMLメタデータには暗号化鍵が出ていないが、管理側には暗号化鍵providerが既に存在する。追加providerを闇雲に作らず、`keycloak-decryption-keys/diagnosis.json` を読むこと。SimpleSAMLphpの暗号化試験では誤鍵対照でもSuccessを返すため、試験の検出力不足を製品全体のFailedにしない。

Shibbolethの稼働ホームは `/opt/reference-idp`。`/opt/shibboleth-idp` も存在するが非稼働側なので取り違えない。コンテナのメインコマンドがsleepで、コンテナ再起動だけではTomcatは起動しない。既存の操作記録を確認し、対象プロセスを特定してから操作すること。

## 直前の作業途中：補助公開鍵入力

実装済み・以前のバッチでテスト済み：

- Core `SupplementalDecryptionKeys`：RSA公開鍵のみ、Run/対象entity/メタデータSHA-256/出所/記録時刻に束縛する。
- Store `SqliteSupplementalDecryptionKeys` とmigration V013：初回INSERTだけ許可、未入力も固定、Run削除に連動。
- Runner `SupplementalDecryptionKeyService`：同一再送は冪等、差し替え拒否、公開メタデータの鍵を先にして補助鍵を重複排除し合成。

引き継ぎ直前に追加し、コンパイルのみ確認したもの：

- `SupplementalDecryptionKeyRoutes`：GET `/api/runs/{id}/supplemental-decryption-keys` とPOST `.../submit`。固定フィールドを検査し、no-storeを設定。
- `SamlScopeApplication`：ルート登録と読み取り/書き込み認可の接続。
- `M1Runtime`：SINGLE_LOGOUT_IDP限定の入力スコープ、読み取り/投稿、quickCheck/startTests/startInteractiveでの入力固定。

**この接続は未完成で未デプロイです。現在の試験シナリオはまだ補助鍵を使用しません。** 次に以下をまとめて実装してください。

1. 入力APIの認可、旧Run、試験開始との競合、初期ログイン/自動実行による早すぎる固定を確認する。`withManualEvidenceWork` はローカルでは排他ロックではない。DB初回INSERTによる固定だけで全開始経路の前提が守れるか監査する。
2. APIの状態表示と画面入力を接続し、固定済み状態・出所・対象メタデータを明示する。
3. 暗号化19a/19cと設定能力19bが同一の固定済み実効鍵を使うようにする。公開メタデータを書き換えず、補助入力の出所を結果に明示する。
4. `MultipleDecryptionKeysConfigurationTestCase` は各暗号化試験の厳密な証拠集合を確認する。出所記録を足す際に証拠数や関連付けを壊さない。
5. API/シナリオ/結果の一連の接続をまとめて検証した後、実環境へ反映して再試験する。新しい実証が得られるまで未検証数を減らさない。
6. この小分野だけで終わらず、全件台帳から共通する未実装判定・fixture・追加観測を実装し続ける。

## 検証と生成コマンド

Javaは `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home` をJAVA_HOMEに指定。Pythonは `.venv/bin/python`。Gradleのキャッシュアクセスには環境の権限追加が必要な場合がある。

```sh
.venv/bin/python tools/g1_docgen.py --check
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gpg.ssh.allowedSignersFile GIT_CONFIG_VALUE_0=/private/tmp/samlscope-ci-allowed-signers .venv/bin/python tools/g1_validate.py --structural-only
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gpg.ssh.allowedSignersFile GIT_CONFIG_VALUE_0=/private/tmp/samlscope-ci-allowed-signers .venv/bin/python tools/g2_validate.py
```

<!--g1-literal--> 直前のG1生成一致・構造46/46は成功。G2は従来20/21で、G2-30の保護実装ソース差分が残る。署名付き作業コミットはこの独立承認を代替しない。過去のバッチはRunner444、Core179、Store39テスト成功だが、直前のAPI接続を含む最終全体試験ではない。引き継ぎ前の `:api:compileJava --offline` は成功。

```sh
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup
```

全件監査の `unresolved-contract-audit.json` は必要variant/対照/元resultの整合を確認する資料で、実装完了の証明ではない。`operations.jsonl` は追記し、復元や失敗した設定試行も隠さない。

## 差分と報告

引き継ぎコミットには、それ以前から作業ツリーにあったOIDC、管理画面、ユーザー管理、retention等の変更も保存されている。すべてを今回の未検証解消作業の成果として扱わず、既存変更を壊さないこと。修正箇所・理由・検証範囲・未検証の増減・設定作業量を記録し、ユーザーに日本語で報告する。リリース可能性をテスト件数や承認済みカタログの存在だけで断定しないこと。
