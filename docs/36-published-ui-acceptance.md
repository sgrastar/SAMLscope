# 公開UI情報の注記判定と集合メタデータの再試験

## 確定した範囲

<!--g1-literal--> 未検証は500→490観測、異なるケースIDは164→161。Success追加1、Warning追加9、Failed追加0。全件完走やリリース承認ではない。

| ケース | Keycloak | Shibboleth | SimpleSAMLphp | 根拠 |
|---|---|---|---|---|
| IIP-MD05.f7 | Warning | Warning | Warning | 対象IdPがDescriptionを公開していない |
| IIP-MD05.f8 | Warning | Warning | Warning | 対象IdPがLogoを公開していない |
| IIP-MD05.fa | Warning | Warning | Warning | 対象IdPがInformationURLを公開していない |
| IIP-MD02.d | 今回対象外 | 今回対象外 | Success | 集合メタデータの全指定子要素数を製品自身のパーサーへ投入し、取り込んだACSへの署名付きSSO応答を実測 |

未公開の注記は承認済み `interpretation_constraints` の明示的な `satisfied_with_note` 分岐を使用する。消費側UIがないという推測やNOT_APPLICABLEへの変更ではない。公開されている文章の有用性、画像の適切な背景、URL先の比較を自動的に成功扱いしない。

## 実装と証拠

`AutoBrowserMetadataEvidenceTestCase` を `withPublishedMetadata` に接続した。Runに固定されたメタデータが単独EntityDescriptorであり、計画のentityIDと一致することを確認してから受動検査する。欠落、別entity、集合ルート、解析不能は既存の未検証経路へ戻す。通常の署名付き要求と別に発行する不正署名対照は、他の正常系証拠読取から除外した。

証拠の基点は `build/acceptance/reference-20260918/`。生成台帳へ採用する前に `verify_publisher_ui_batch.py` が原本メタデータのSHA-256・対象entityID・未公開・Run・判定を照合する。集合取込は既存のネイティブ取込検証器で原fixture、パーサー出力、設定復元、署名付き応答相関を照合する。

| 製品／試験 | Run | 証拠フォルダー |
|---|---|---|
| Keycloak 公開UI | run_J107HRR1BXY7GHBHTDDMY87308 | publisher-ui-scoped/keycloak |
| Shibboleth 公開UI | run_G7RK00MQC0WZXS14JPFQPV8NKZ | publisher-ui-scoped/shibboleth |
| SimpleSAMLphp 公開UI | run_HNDN6YMHP5NZ9AP1GHB21V3AQH | publisher-ui-scoped/simplesamlphp |
| SimpleSAMLphp 集合取込 | run_47A3XNG2QG2D7E64BDWH6XW5S3 | simplesamlphp-aggregate-import |

稼働イメージは `samlscope:reference-publisher-ui-v26`、digestは `sha256:d91fa5493d44486d3fccba02bcd632651ed778aa23afc3c1fa120525af0486c6`。

## 不採用と残課題

IIP-MD06.a1は生のRun結果がPASSでも、入れ子内の全entityについてエンドポイントと鍵を使用した証拠がないため台帳へ採用しない。今回のドライバーは製品パーサーの出力から試験対象entityのみを設定している。各entityを実際に使用するハーネスと、オラクル側の証拠充足条件の強化が必要。

最初の公開UI再試験は実行経路への接続不足で未検証のまま。その後の初回接続版は既存のUnavailableBrowserOracleTestCaseを受け付けず起動に失敗した。型制約を修正して復旧し、対象entity一致の検査を加えた最終版の新Runだけを採用した。失敗試行の証拠も保持する。

## 操作コストと検証

<!--g1-literal--> 今回はDocker build 3、Suite／転送コンテナ再作成各3（起動失敗1を含む）、Run作成7、preflight 8、tests/start 8試行（初期ログイン前の拒否1を含む）。公開UI確認の製品設定変更0、集合取込6、設定ファイル書込13（各投入・復元12とfinallyの再復元1）、本人操作0、製品再起動0。元設定のSHA-256一致で復元確認済み。

<!--g1-literal--> Runner全体の回帰テスト成功後、追加の対象entity照合・既存未実装型接続テストも成功。G1生成一致・構造46/46。G2は既存の署名済みソース差分G2-30が残り20/21であり、現在の変更が再承認済みとは扱わない。台帳監査は490観測・161ケースIDで不整合なし。
