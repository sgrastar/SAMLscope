# 補助公開鍵の受入記録（2026-09-15）

対象は `docs/28-deepseek-handoff.md` の「直前の作業途中：補助公開鍵入力」です。基準コミットは `52e8feff9507b4bcae4e9f46152a6439ef94a4dd` で、この記録はその後の変更を対象にしています。実装・検証・検証環境への反映はローカルで実施し、公開やpushは行っていません。

## 変更した接続

| 領域 | 変更 | 検証 |
|---|---|---|
| Runner | `SupplementalDecryptionKeyService.KeySet`（公開鍵と補助鍵の出所）、`keySet`、`TestInputFixed` | 単体・競合テスト |
| 暗号化シナリオ | Suite対照鍵を除く実効鍵の選択、`decryption_key_source` の記録 | 19a/19cの鍵選択行列テスト |
| 設定能力 | 19bが同じ固定実効鍵を使用し、証拠4件×2の厳密検査を維持 | 出所記録を追加した回帰テスト |
| API | `GET/POST /api/runs/{id}/supplemental-decryption-keys` の状態・投稿、409 Conflict、no-store、認可・CSRF | API結合テストとHOSTED認可テスト |
| 画面 | Run workspaceの入力パネル（対象entity・メタデータSHA-256・固定状態・出所・記録時刻） | コンポーネント・画面テスト |
| 結果 | 公開診断 `decryption_key_source`（固定トークン `published-metadata` / `supplemental-input`） | 結果組立てと実Runのresult.json |

公開メタデータの書き換え、出所URIの取得、署名専用鍵の暗黙利用は行っていません。

## ローカル検証

<!--g1-literal--> Core 179、SAML 75、Store 39、Runner 451、Peer 13、API 86、Web 83の計926件が成功しました。G1生成文書一致と構造46/46は成功しています。

<!--g1-literal--> G2は20/21で、G2-30（保護実装ソースが署名済み承認コミットと一致しない）は未解消です。新しいソースの独立承認として過去の承認を流用していません。

固定の監査では、GETがRunを固定しないこと、同一再送が記録時刻と出所を維持すること、差し替えが409になること、開始処理が投稿済み入力を保持し、未投稿のRunには「補助鍵なし」を固定して後付けを拒否することを確認しました。20回の同時freeze/submitでも保存は「投稿鍵」または「補助鍵なし」のどちらかに一致しました。

## 実環境の再試験

使用イメージは `samlscope:reference-supplemental-v19`（digest `sha256:59a7760e2becec15c7f2854ad71011fd0a3c9bcab87a63bfe6d94f8c600bd878`）です。既定の `samlscope:reference-key-capability-v18` には補助鍵のAPI経路が含まれていないため、現在の作業ツリーからフルビルドして反映しました。

| 製品 | Run | 補助入力 | 比較したケース数 | 差分 |
|---|---|---:|---:|---|
| Keycloak | `run_YXCS140PP32WZD22SSH60HTW0M` | 管理APIのRSA-OAEP ENC公開鍵1件、出所 `http://localhost:18180/admin/realms/samlscope/keys` | 49 | 2件（19a・19cの理由コードのみ、VerdictはNOT_VERIFIEDのまま） |
| Shibboleth | `run_S3994DAQTP7WYFB6XSMJ1Q57QJ` | なし（公開メタデータの暗号化鍵2件） | 49 | 0件 |

Keycloakの変化は次のとおりです。

- `IIP-IDP19-a`: `slo.encrypted-id.key-unavailable` → `slo.encrypted-id.negative-control-failed`
- `IIP-IDP19-c`: `slo.encrypted-id.multiple-keys.key-unavailable` → `slo.encrypted-id.multiple-keys.configuration-unavailable`

補助入力が実際に適用されたことは、19aが鍵選択で止まらず、未登録鍵（Suiteの対照鍵）で暗号化したLogoutRequestを送信したことから確認できます。Keycloakはこの未登録鍵の要求も受理したため、正の試験は送信されておらず、`negative-control-failed` として未検証のままです。製品のFailed判定は追加していません。19-cは登録鍵が2件に満たないため `configuration-unavailable` です。

Shibbolethは49ケースのVerdict差分が0件で、`IIP-IDP19-a`/`19-c` は4件、`19-b` は8件の証拠でSuccessを維持しました。result.jsonには `decryption_key_source: ["published-metadata"]` が追加されています。SimpleSAMLphpは既に同種の対照不成立（`slo.encrypted-id.negative-control-failed`）のため再試験していません。

<!--g1-literal--> 未検証567件と異なるケースID 180件は変更していません。得られたのは補助入力の適用と出所記録の実証であり、Verdictを確定する新しい製品証拠ではないためです。

## 操作量

docs/25の数え方に合わせ、設定書き込み・再読み込み・ブラウザ操作・本人操作を区別します。今回の計測は2026-09-15の作業のみで、それ以前の環境構築は未計測です。

| 項目 | 回数 |
|---|---:|
| docker build | 2（初回の差分オーバーレイ、2回目のフルビルド） |
| 起動に失敗した反映試行 | 1（オーバーレイは起動時に必要なクラスが欠け、ロールバックして不採用） |
| Suiteコンテナ再作成 | 2（失敗試行とフルビルド反映。稼働イメージの変更1回） |
| 転送コンテナ再作成 | 2 |
| 製品コンテナ再起動 | 0 |
| 製品設定の書き込み | 0 |
| 製品管理APIの読み取り | 2（トークン取得と鍵一覧） |
| 補助公開鍵入力の投稿 | 1 |
| Suite Run作成 | 2 |
| preflight | 2 |
| プロトコル・ブラウザ往復の記録 | 46（Keycloak 19、Shibboleth 25、初期ログイン2） |
| 自動ブラウザ遷移 | 4（ShibbolethのSLOページ） |
| ユーザー本人の操作 | 0 |

初回のオーバーレイ試行は、基準イメージが補助鍵実装以前のストア層を持っていたため起動に失敗しました。失敗は隠さずこの記録に残し、フルビルドへ切り替えています。製品側の設定・再読み込み・本人操作は発生していません。

## 限界と残作業

- Keycloakの暗号化ケースは未検証のままです。製品が未登録鍵を拒否しないため、補助鍵を与えても正の試験まで進めません。
- フルビルドには作業ツリーの他変更（OIDC・管理画面・ユーザー管理等）も含まれます。それらは今回の成果として扱わず、SLOプロファイルの比較で回帰がないことだけを確認しています。
- G2-30は未解消で、今回の変更は独立承認を受けていません。
- 全件台帳の残り（自動判定未実装、部分実装、証拠確認経路など）は未着手です。

## 証拠の保存先

ローカル `build/acceptance/reference-20260915/` に、フルビルドログ、クラスとソースのSHA-256、Runのresult.json・report.html・transcript・操作ログ・比較結果を保存しています。このディレクトリはGit管理対象外です。
