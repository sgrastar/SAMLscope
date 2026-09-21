# Keycloak・SimpleSAMLphp の EC 署名観測

共通 EC 署名試験の実行経路を、製品自身のメタデータ取込と要求単位の署名エラーへ接続した。ケース、義務レベル、承認済み fixture は変更していない。

<!--g1-literal--> Keycloak の browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp で 4 観測を正式 PASS に確定した。未検証は 442 → 438、異なるケース ID は 154 のまま。SimpleSAMLphp の同じ 4 観測は NOT_VERIFIED を維持し、診断を具体化した。

## 元のメタデータと実際の要求

Keycloak は管理コンソールの Import client に元の fixture を渡し、製品が解釈した証明書と署名必須設定を管理 API で読み戻す。証明書が元 fixture と一致することも採用時に検査する。Suite の XML から管理 API 属性へ変換したものをメタデータ取込の根拠にはしていない。

製品内の観測プラグインが、Keycloak 自身の署名検証イベントに同じ HTTP 処理の要求 ID・原文ハッシュを付ける。メタデータ試験用の要求 ID 形式も受け付けるようにした。観測終了時に realm の設定を復元し、配置した jar のハッシュを照合して撤去し、製品の再起動を確認した。

SimpleSAMLphp はインストール済みの XML バリデータとメタデータパーサーを使用し、静的メタデータ設定へ取り込む。設定の書込・読み戻し・復元を記録する。正常 RSA 対照、正常 EC、破損 EC、通常ログインを各 Run で実行した。署名エラーは送信した要求の原文ハッシュと直接 HTTP 応答に結び付け、Cookie・認証情報・URL のセッション用クエリを保存しない。

`NativeEcSignatureEvidence` は元の証明書・SignatureMethod・Reference digest・SignatureValue を検証する。正常 EC 要求と破損 EC 要求は同じ鍵を使い、後者は Reference digest が有効で署名値だけが無効である必要がある。RSA 対照の成功応答も対象メタデータの鍵で実署名を検証する。Keycloak の正常 EC 応答についても同じ検証を行った。

## SimpleSAMLphp の結果は未検証を維持

SimpleSAMLphp は RSA 対照を受理した一方、暗号学的に正しい EC 要求に対して AuthnRequest の `NOTVALIDCERTSIGNATURE` を返した。単に HTTP エラーが出たことを根拠にしていない。元の EC 公開鍵・署名と製品固有のエラーを確認した結果を、正式結果の `ec-signature.native-valid-request-rejected` として記録した。

この拒否だけでは、別の設定でも EC を利用できないことを証明できない。`EcSignatureSupportTestCase` はこの観測を NOT_VERIFIED として確定し、対応機能の不存在や製品の FAIL/WARNING には変換しない。将来、追加証拠が揃えば同じ未検証結果から再評価できる。

<!--g1-literal--> 取り違え・欠落の負の対照は Keycloak 各 14 種、SimpleSAMLphp 各 10 種、計 96 をまとめて検査した。SimpleSAMLphp の場合も、元の診断に必要な証拠を欠く変更は `native-incomplete` に戻り、原文検証済みという診断を維持できないことを確認した。これらは解消数には加算していない。

## 実行経路の修正と操作記録

メタデータ試験ドライバーに HTTP 観測器を差し込めるようにし、正常 fixture と破損 fixture を同じドライバーで実行する。既に破損した EC fixture に別の署名改変を重ねないようにした。共通監査形式の変換を純粋関数へ分離し、製品別ドライバーを同じ Python プロセスで使った際の同名モジュール衝突を解消した。

Keycloak の最初の試行は制限環境での Chrome 起動に失敗したため、設定とプラグインを復元してからローカル Chrome を実行できる環境で再試行した。その後、通常ログインの読み戻しが ACS 集合の順序差を誤検出した。集合フィールドの比較を共通関数側で修正し、失敗記録を残したまま通常ログインを完了した。

<!--g1-literal--> Keycloak は製品コンソールによるクライアント取込・削除が各 12、通常ログイン用クライアント作成・削除が各 5（失敗した読み戻し試行を含む）。観測プラグイン配置・撤去は各 3、製品再起動 6、イベント設定書込 6。失敗試行の復元も確認した。

<!--g1-literal--> SimpleSAMLphp の設定書込はバッチ全体で 17、別途、未採用の診断用再送に伴う一時設定・復元が 2。製品再起動は 0。採用・診断に使用した全 Run の Transcript は AuthnRequest 48・Response 20、これに未採用の診断用直接再送 1 件がある。本人操作は 0。

<!--g1-literal--> Suite build・Suite 再作成・転送コンテナ再作成は各 1、receipt 配置・正式評価は各 8。全 Java/Web テストの再実行とコミットは行っていない。集約操作記録は `native-ec-products-runtime-v59/acceptance-operations.json`。

## 証拠と採用

証拠の親ディレクトリは `build/acceptance/reference-20260918/`。

- Keycloak browser_sso_idp: `keycloak-native-ec-signature-v2/observations/browser_sso_idp/`。通常ログインの完了記録は `baseline-retry/`。
- Keycloak の残るプロファイル: `keycloak-native-ec-signature-v3/observations/<profile>/`。
- SimpleSAMLphp: `simplesamlphp-native-ec-signature/<profile>/`。

各ディレクトリの `native-ec-verification.json`、原文 manifest、receipt、設定復元、`evaluation/result.json` を `verify_native_ec_acceptance.py` が照合する。今回の正式結果と未検証台帳を突き合わせ、ほかに確定済みの採用漏れがないことも確認した。

稼働イメージは `samlscope:reference-native-ec-products-v59`。Shibboleth の既存 EC 確定結果も読み戻しで維持を確認した。G2 の署名差分は引き続き別の承認課題であり、この実証をリリース承認の完了とは扱わない。
