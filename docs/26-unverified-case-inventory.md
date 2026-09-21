# 未検証項目の全件台帳

対象は前回の追加試験後に残ったNOT_VERIFIEDと、その追加再試験です。件数は製品・プロファイル・ケース単位の延べ観測数です。追加再試験の対象ケースだけ新Runの証拠を採用し、それ以外の既存証拠は保持しています。単一Runの完走・適合率ではありません。

| 再試験前 | 確定（Success / Failed / Warning） | 現在の未検証 | 未検証の異なるケースID |
|---:|---:|---:|---:|
| 594 | 197 | 397 | 144 |

## 内訳

| 原因・現在の経路 | 件数 | 次に扱う範囲 |
|---|---:|---|
| ブラウザ完了後の自動判定がない | 14 | Suite実装 |
| 一部の試験条件しか実装されていない | 56 | Suite実装 |
| 設定後の証拠確認・自己申告経路 | 139 | 設定・証拠 |
| 自己申告が無効 | 75 | 設定・証拠 |
| メタデータの追加試験・観測不足 | 32 | 試験経路確認 |
| ブラウザ・SLOの追加観測不足 | 25 | 試験経路確認 |
| 古い待機結果・再開時には期限切れ | 0 | 新Runで再試験 |
| 実行したが確定できない | 56 | 個別診断 |

### G02の確認済み条件と残条件

次は部分的な確認であり、ケース全体の確定件数には含めません。値保持・切詰めの別義務を受理条件へ追加せず、承認済み定義に従って分けています。

| 製品 | 標準文字列の確認入力数 | 拡張属性の応答入力数 | 残条件 |
|---|---:|---:|---|
| keycloak | 20 | 16 | persistent-nameid, transient-nameid, user-defined-advice-string, user-defined-attribute-value-string |
| shibboleth | 20 | 16 | persistent-nameid, transient-nameid, user-defined-advice-string, user-defined-attribute-value-string |
| simplesamlphp | 20 | 16 | persistent-nameid, transient-nameid, user-defined-advice-string, user-defined-attribute-value-string |

分類は実行結果の理由コード、interaction種別、Suiteの実装を基にしています。「試験経路確認」は実行可能を保証する分類ではありません。設定・証拠の経路も、自己申告を有効にするだけで結果を保証しません。

ECDSAケースは旧Runのブラウザ待機結果が残っていますが、現在の登録クラスはEcSignatureSupportTestCaseです。自動判定なしの分類から、メタデータ取得と署名対照の証拠不足へ変更しました。結果のVerdictと未検証総数は変更していません。現在のソース・登録箇所のSHA-256はimplementation-audit.jsonに保存します。

SP起点SLOの基本ケースIIP-IDP17-aとRedirect受理IIP-IDP18-aは、専用実装を反映した実製品再試験の証拠を採用しています。EncryptedID復号IIP-IDP19-aも再試験し、Shibbolethの成功を採用しました。Keycloakの暗号化鍵不足とSimpleSAMLphpの負の対照不成立は未検証のまま理由を更新しています。

## 説明の訂正

「大半は必要な操作が未完了」という説明では、実装のないブラウザ完了処理や部分的なfixture、無効化された証拠確認経路を操作不足にまとめてしまっていました。未検証項目を製品の失敗とは扱いませんが、全試験の実装・完走が済んでいるとも扱えません。

## 今回確認した実行経路

SLOプロファイルの3製品で既存Runの開始・再開を確認したところ、古い出力では待機中だった共通ケースがdelivery_or_response_unknownで終了していました。active-probeのFINISHEDはこの期限切れ後の状態です。新Runで正常系対照と共通試験を再実行し、追加証拠を保存しました。追加Successは5件、残りは部分実装9件と署名試験の判定保留4件でした。開始・再開APIは各製品1回、正常系・共通試験用Runは各製品1回作成しました。ここまでの製品設定変更は0回です。続けてKeycloakとSimpleSAMLphpで署名必須設定を試しましたが、正常系の開始で失敗したため採用していません。Keycloakは受信完了を確認できず、SimpleSAMLphpは補助クライアントのXML解析が失敗しました。これらを製品FAILとは判定しません。変更と復元で各製品2回の設定書き込みが発生し、復元を検証済みです。ブラウザ操作・ユーザー本人の操作は0回で、プロトコルクライアントによる実行です。

追加実装後の再試験では、公開URL未発行の注記を3製品で自動確定（Warning）し、Subject不一致をKeycloakとSimpleSAMLphpで確認（Failed）しました。これらは製品全体の適合判定ではありません。[追加実装記録](27-additional-implementation.md)を参照してください。

## 原因別の対応

### ブラウザ完了後の自動判定がない

BrowserEvidenceTestCaseは完了後にbrowser.oracle-unavailableを返す。対応する入力生成・観測・正負対照を実装する。

### 一部の試験条件しか実装されていない

approved variant全体の入力生成と観測を実装する。追加ログインだけでは完了しない。

### 設定後の証拠確認・自己申告経路

ケースの全variantと対照を実施し、結果を裏付ける証拠を収集する。現Planでは自己申告が無効。設定確認だけをSuccessにしない。

### 自己申告が無効

対象の設定・運用・実装資料を確認する。根拠を収集できた項目だけ、証拠確認を有効にした試験計画で扱う。

### メタデータの追加試験・観測不足

未取得・未使用のfixtureを確認し、対象の取込方式で追加実行する。拒否側は無応答だけで成功とせず、拒否の証明方法を確認する。

### ブラウザ・SLOの追加観測不足

要求される受信証拠を確認する。IdP起点・別ACS・追加Logoutなどの経路をSuiteが提供するか確認し、不足なら実装する。

### 古い待機結果・再開時には期限切れ

再開時にはdelivery_or_response_unknownで終了していた。新Runで正常系対照と共通試験を再実行し、元のSLO結果とは別に証拠を保存する。

### 実行したが確定できない

理由コードと正常系対照を確認し、Suite・構成・製品を切り分ける。無応答や証拠不足を製品FAILに変更しない。

## 追加再試験の製品別結果

| Test | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success | Success | Success |
| `IIP-ALG02-a-idp-01` | Success | Success | Success |
| `IIP-ALG03-a-idp-01` | Success | Success | Not verified: ec-signature.native-valid-request-rejected |
| `IIP-ALG04-a-idp-01` | Not verified: case.pending-interaction | Success | Not verified: case.pending-interaction |
| `IIP-ALG04-b-idp-01` | Success | Not verified: case.pending-interaction | Not verified: case.pending-interaction |
| `IIP-ALG06-a-idp-01` | Not verified: case.pending-interaction | Success | Not verified: case.pending-interaction |
| `IIP-ALG06-b-idp-01` | Success | Not verified: case.pending-interaction | Not verified: case.pending-interaction |
| `IIP-ALG06-c-idp-01` | Not verified: case.pending-interaction | Not verified: case.pending-interaction | Not verified: case.pending-interaction |
| `IIP-ALG06-d-idp-01` | Not verified: case.pending-interaction | Not verified: case.pending-interaction | Not verified: case.pending-interaction |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial |
| `IIP-EXT01-c-idp-01` | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial |
| `IIP-G01-a-idp-01` | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial |
| `IIP-G02-a-idp-01` | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial |
| `IIP-G03-b-idp-01` | Not verified: request.signing.unavailable | Not verified: browser_fixture_partial | Not verified: request.signing.unavailable |
| `IIP-IDP01-a-idp-01` | Not verified: configuration.attribute-name.evidence-incomplete | Success | Success |
| `IIP-IDP02-a-idp-01` | Success | Success | Success |
| `IIP-IDP03-a-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-IDP04-a-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-IDP04-b-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-IDP06-a-idp-01` | Success | Success | Success |
| `IIP-IDP06-b-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Success |
| `IIP-IDP08-a-idp-01` | Failed (Product) | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） |
| `IIP-IDP09-a-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Success |
| `IIP-IDP11-a-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-IDP12-c-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP17-a-idp-01` | Success | Success | Success |
| `IIP-IDP17-aa-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-al-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP17-b-idp-01` | Success | Success | Failed (Product) |
| `IIP-IDP17-b1-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-IDP17-b2-idp-01` | Success | Success | Not verified: slo.async.feedback.unrecognized |
| `IIP-IDP17-c-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP17-n-idp-01` | Not verified（今回の再試験対象外） | Not verified: slo.identifier.strong-match-unobservable | Not verified（今回の再試験対象外） |
| `IIP-IDP17-r-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP17-s-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP17-u-idp-01` | Not verified（今回の再試験対象外） | Not verified: slo.not-on-or-after.correlation-unavailable | Not verified（今回の再試験対象外） |
| `IIP-IDP17-x-idp-01` | Success | Success | Failed (Product) |
| `IIP-IDP17-y-idp-01` | Failed (Product) | Warning | Warning |
| `IIP-IDP17-z-idp-01` | Failed (Product) | Warning | Warning |
| `IIP-IDP18-a-idp-01` | Success | Success | Success |
| `IIP-IDP18-b-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP18-c-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP18-d-idp-01` | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable | Not verified: browser.oracle-unavailable |
| `IIP-IDP19-a-idp-01` | Not verified: slo.encrypted-id.key-unavailable | Success | Not verified: slo.encrypted-id.negative-control-failed |
| `IIP-IDP19-b-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-IDP19-c-idp-01` | Not verified: slo.encrypted-id.multiple-keys.key-unavailable | Success | Not verified: slo.encrypted-id.multiple-keys.configuration-unavailable |
| `IIP-MD02-c-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD02-d-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Success |
| `IIP-MD03-a-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD03-b-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD04-a-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD04-b-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD04-c-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-a2-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-a3-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Not verified: case.pending-interaction |
| `IIP-MD05-a4-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD05-a5-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD05-ad-idp-01` | Not verified（今回の再試験対象外） | Success | Success |
| `IIP-MD05-ae-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-am-idp-01` | Not verified（今回の再試験対象外） | Warning | Not verified（今回の再試験対象外） |
| `IIP-MD05-an-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-ao-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-as-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-c-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-e5-idp-01` | Success | Success | Success |
| `IIP-MD05-e7-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-e8-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified: metadata.algorithms.intersection-evidence-incomplete |
| `IIP-MD05-e9-idp-01` | Not verified: metadata.algorithms.local-policy-unverified | Success | Not verified: metadata.algorithms.local-policy-unverified |
| `IIP-MD05-ea-idp-01` | Not verified: metadata.algorithms.local-policy-unverified | Success | Not verified: metadata.algorithms.local-policy-unverified |
| `IIP-MD05-eb-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD05-f7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f8-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f9-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD05-fa-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ff-idp-01` | Success | Success | Success |
| `IIP-MD05-fi-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-g-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD06-a1-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Success |
| `IIP-MD06-a5-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD06-a7-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-MD06-a8-idp-01` | Success | Success | Success |
| `IIP-MD06-a9-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD07-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD07-b-idp-01` | Not verified（今回の再試験対象外） | Success | Success |
| `IIP-MD12-a-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD12-b-idp-01` | Failed (Product) | Not verified（今回の再試験対象外） | Success |
| `IIP-MD12-c-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-MD12-d-idp-01` | Failed (Product) | Not verified（今回の再試験対象外） | Success |
| `IIP-SSO01-an-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-SSO01-cz-idp-01` | Not verified（今回の再試験対象外） | Not verified（今回の再試験対象外） | Not verified: saml.subject-principal.undetermined |
| `IIP-SSO01-g-idp-01` | Success | Success | Not verified（今回の再試験対象外） |
| `IIP-SSO01-ga-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-SSO01-gb-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-SSO01-gc-idp-01` | Not verified（今回の再試験対象外） | Failed (Product) | Not verified（今回の再試験対象外） |
| `IIP-SSO01-gi-idp-01` | Success | Not verified（今回の再試験対象外） | Success |
| `IIP-SSO01-gj-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-SSO01-k-idp-01` | Not verified（今回の再試験対象外） | Success | Not verified（今回の再試験対象外） |
| `IIP-SSO01-z-idp-01` | Warning | Warning | Not verified（今回の再試験対象外） |
| `IIP-SSO04-a-idp-01` | Success | Success | Success |
| `IIP-SSO07-b-idp-01` | Failed (Product) | Not verified: browser_fixture_partial | Failed (Product) |

## ケース単位の一覧

製品列には未検証が残るプロファイルを記載します。同じケースに複数の理由がある場合は原因列に併記します。—は今回の未検証集合にないことを示し、製品全体のPASSを意味しません。

| Test | Keycloak | Shibboleth | SimpleSAMLphp | 原因 |
|---|---|---|---|---|
| `IIP-ALG03-a-idp-01` | — | — | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | 実行したが確定できない |
| `IIP-ALG04-a-idp-01` | — | — | ecp_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-ALG04-b-idp-01` | — | — | ecp_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-ALG06-b-idp-01` | — | — | browser_sso_idp、ecp_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-ALG06-c-idp-01` | — | — | browser_sso_idp、ecp_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-ALG06-d-idp-01` | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-ALG07-a-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | 自己申告が無効 |
| `IIP-ALG08-a-idp-01` | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-ALG08-b-idp-01` | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-ALG08-c-idp-01` | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | 自己申告が無効 |
| `IIP-EXT01-b-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | 一部の試験条件しか実装されていない |
| `IIP-EXT01-c-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | 一部の試験条件しか実装されていない |
| `IIP-G01-a-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | 一部の試験条件しか実装されていない |
| `IIP-G02-a-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 一部の試験条件しか実装されていない |
| `IIP-G02-c-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-G03-b-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 実行したが確定できない / 一部の試験条件しか実装されていない |
| `IIP-IDP01-a-idp-01` | browser_sso_idp | — | — | 実行したが確定できない |
| `IIP-IDP03-a-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP04-a-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP04-b-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP05-a-idp-01` | browser_sso_idp | — | — | 実行したが確定できない |
| `IIP-IDP06-b-idp-01` | browser_sso_idp | browser_sso_idp | — | 実行したが確定できない |
| `IIP-IDP08-a-idp-01` | — | browser_sso_idp | — | 実行したが確定できない |
| `IIP-IDP10-d-idp-01` | browser_sso_idp | — | — | 実行したが確定できない |
| `IIP-IDP11-a-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP12-b-idp-01` | browser_sso_idp | browser_sso_idp | — | 実行したが確定できない |
| `IIP-IDP12-d-idp-01` | — | browser_sso_idp | — | 実行したが確定できない |
| `IIP-IDP12-e-idp-01` | browser_sso_idp | — | — | 実行したが確定できない |
| `IIP-IDP12-f-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 実行したが確定できない |
| `IIP-IDP16-a-idp-01` | ecp_idp | ecp_idp | ecp_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP17-ab-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 自己申告が無効 |
| `IIP-IDP17-b2-idp-01` | — | — | single_logout_idp | 実行したが確定できない |
| `IIP-IDP17-c-idp-01` | single_logout_idp | — | single_logout_idp | 実行したが確定できない |
| `IIP-IDP17-n-idp-01` | single_logout_idp | — | — | ブラウザ・SLOの追加観測不足 |
| `IIP-IDP17-r-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 実行したが確定できない |
| `IIP-IDP17-s-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 実行したが確定できない |
| `IIP-IDP17-u-idp-01` | single_logout_idp | — | — | ブラウザ・SLOの追加観測不足 |
| `IIP-IDP18-c-idp-01` | single_logout_idp | — | single_logout_idp | 実行したが確定できない |
| `IIP-IDP18-d-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 実行したが確定できない |
| `IIP-IDP19-a-idp-01` | single_logout_idp | — | single_logout_idp | 実行したが確定できない |
| `IIP-IDP19-b-idp-01` | single_logout_idp | — | single_logout_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP19-c-idp-01` | single_logout_idp | — | single_logout_idp | 実行したが確定できない |
| `IIP-IDP20-a-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-IDP21-a-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | 自己申告が無効 |
| `IIP-MD01-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD02-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD02-b-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD02-d-idp-01` | metadata_idp | — | — | メタデータの追加試験・観測不足 |
| `IIP-MD03-a-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD03-b-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD03-c-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD03-d-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD04-a-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD04-b-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD04-c-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-a1-idp-01` | metadata_idp | metadata_idp | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-a2-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-a3-idp-01` | metadata_idp | metadata_idp | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-a8-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-ac-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-ad-idp-01` | metadata_idp | — | — | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-af-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-ah-idp-01` | metadata_idp | metadata_idp | metadata_idp | 実行したが確定できない |
| `IIP-MD05-am-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-an-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-ao-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-ap-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-aq-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-ar-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-as-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-av-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-aw-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-b-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-c-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-c1-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-c2-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-c3-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-c5-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD05-c6-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD05-c7-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD05-cd-idp-01` | metadata_idp | — | metadata_idp | メタデータの追加試験・観測不足 |
| `IIP-MD05-d-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-d1-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-e-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-e7-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-e8-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 / 実行したが確定できない |
| `IIP-MD05-e9-idp-01` | metadata_idp | — | metadata_idp | 実行したが確定できない |
| `IIP-MD05-ea-idp-01` | metadata_idp | — | metadata_idp | 実行したが確定できない |
| `IIP-MD05-f-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD05-f5-idp-01` | metadata_idp | metadata_idp | metadata_idp | 一部の試験条件しか実装されていない |
| `IIP-MD05-f9-idp-01` | metadata_idp | — | metadata_idp | ブラウザ完了後の自動判定がない |
| `IIP-MD05-fb-idp-01` | metadata_idp | metadata_idp | metadata_idp | ブラウザ完了後の自動判定がない |
| `IIP-MD05-fg-idp-01` | metadata_idp | metadata_idp | metadata_idp | 一部の試験条件しか実装されていない |
| `IIP-MD05-fh-idp-01` | metadata_idp | metadata_idp | metadata_idp | ブラウザ完了後の自動判定がない |
| `IIP-MD05-fj-idp-01` | metadata_idp | metadata_idp | metadata_idp | ブラウザ完了後の自動判定がない |
| `IIP-MD06-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-a1-idp-01` | metadata_idp | — | — | メタデータの追加試験・観測不足 |
| `IIP-MD06-a2-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-a3-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-a5-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-a6-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-a7-idp-01` | metadata_idp | — | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-ab-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-b-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-MD06-c-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD07-b-idp-01` | metadata_idp | — | — | 設定後の証拠確認・自己申告経路 |
| `IIP-MD09-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD09-b-idp-01` | metadata_idp | metadata_idp | metadata_idp | 自己申告が無効 |
| `IIP-MD11-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-ae-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-ak-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 実行したが確定できない |
| `IIP-SSO01-al-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-cz-idp-01` | — | — | browser_sso_idp | 実行したが確定できない |
| `IIP-SSO01-d-idp-01` | browser_sso_idp | — | browser_sso_idp | 実行したが確定できない |
| `IIP-SSO01-de-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-dy-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-e-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-ea-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-eb-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 一部の試験条件しか実装されていない |
| `IIP-SSO01-ec-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-ed-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-ee-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO01-em-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 実行したが確定できない |
| `IIP-SSO01-ep-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO01-f-idp-01` | browser_sso_idp | — | browser_sso_idp | 実行したが確定できない |
| `IIP-SSO01-fp-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | ブラウザ完了後の自動判定がない |
| `IIP-SSO01-fr-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-g-idp-01` | — | — | browser_sso_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO01-ga-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-gb-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-gc-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-gd-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-gj-idp-01` | browser_sso_idp | — | browser_sso_idp | 設定後の証拠確認・自己申告経路 |
| `IIP-SSO01-i2-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 一部の試験条件しか実装されていない |
| `IIP-SSO01-k-idp-01` | browser_sso_idp | — | — | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO01-z-idp-01` | — | — | browser_sso_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO03-b-idp-01` | browser_sso_idp | — | browser_sso_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO05-a-idp-01` | — | browser_sso_idp | — | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO05-a1-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO05-a2-idp-01` | — | browser_sso_idp | browser_sso_idp | ブラウザ・SLOの追加観測不足 |
| `IIP-SSO05-a3-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 一部の試験条件しか実装されていない |
| `IIP-SSO05-a8-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | 自己申告が無効 |
| `IIP-SSO07-b-idp-01` | — | browser_sso_idp | — | 一部の試験条件しか実装されていない |

## 判定不能の分類（診断）

Verdictは変更せず、未検証の理由だけを分類します。feature-absentは公開メタデータ等から機能の不在を確認済みのもの、role-inapplicableはロール上消費されないvariant、evidence-form-mismatchは承認済み証拠形式との不一致、operator-attestation-availableは運用者証言で確認可能、suite-observation-gapはSuite実装で解消可能です。

| 診断 | 件数 | 意味 | 表示案 |
|---|---:|---|---|
| `suite-observation-gap` | 258 | Suite側の観測・実行経路が未接続 | Suite側の実装で解消可能なNot verified |
| `operator-attestation-available` | 77 | 自己申告または運用者証言で確認可能 | 運用者証言（ケースごとに1回答）で確認可能。現在のPlanは自己申告無効 |
| `evidence-form-mismatch` | 27 | 承認済み判定条件が要求する証拠形式と製品応答が不一致 | 証拠形式が承認済み条件と一致しないためNot verified（要件解釈の再確認が必要） |
| `role-inapplicable` | 24 | ロール上、対象が消費しない成果物を要求するvariant | IdPロールでは消費されないvariantのため実行対象外（対象外であることは判定済み） |
| `feature-absent` | 11 | 製品が機能として公開していない（公開メタデータ等から確認済み） | この製品は機能として提供していないため、この試験は実行できません（skipped相当） |

### feature-absent

`IIP-MD05-f9-idp-01`, `IIP-MD05-fb-idp-01`, `IIP-MD05-fh-idp-01`, `IIP-MD05-fj-idp-01`


### role-inapplicable

`IIP-EXT01-b-idp-01`, `IIP-EXT01-c-idp-01`


### evidence-form-mismatch

`IIP-G03-b-idp-01`, `IIP-IDP05-a-idp-01`, `IIP-IDP08-a-idp-01`, `IIP-IDP10-d-idp-01`, `IIP-IDP12-b-idp-01`, `IIP-IDP12-d-idp-01`, `IIP-IDP12-e-idp-01`, `IIP-IDP12-f-idp-01`, `IIP-IDP19-a-idp-01`, `IIP-IDP19-c-idp-01`, `IIP-MD05-ah-idp-01`, `IIP-SSO01-ak-idp-01`, `IIP-SSO01-d-idp-01`, `IIP-SSO01-em-idp-01`, `IIP-SSO01-f-idp-01`


### operator-attestation-available

`IIP-ALG07-a-idp-01`, `IIP-ALG08-c-idp-01`, `IIP-G02-c-idp-01`, `IIP-IDP06-b-idp-01`, `IIP-IDP17-ab-idp-01`, `IIP-IDP21-a-idp-01`, `IIP-MD05-c5-idp-01`, `IIP-MD05-c6-idp-01`, `IIP-MD05-c7-idp-01`, `IIP-MD06-c-idp-01`, `IIP-MD09-a-idp-01`, `IIP-MD09-b-idp-01`, `IIP-SSO01-al-idp-01`, `IIP-SSO01-de-idp-01`, `IIP-SSO01-dy-idp-01`, `IIP-SSO01-e-idp-01`, `IIP-SSO01-ea-idp-01`, `IIP-SSO01-ec-idp-01`, `IIP-SSO01-ed-idp-01`, `IIP-SSO01-ee-idp-01`, `IIP-SSO05-a1-idp-01`, `IIP-SSO05-a8-idp-01`


### suite-observation-gap

`IIP-ALG03-a-idp-01`, `IIP-ALG04-a-idp-01`, `IIP-ALG04-b-idp-01`, `IIP-ALG06-b-idp-01`, `IIP-ALG06-c-idp-01`, `IIP-ALG06-d-idp-01`, `IIP-ALG08-a-idp-01`, `IIP-ALG08-b-idp-01`, `IIP-G01-a-idp-01`, `IIP-G02-a-idp-01`, `IIP-G03-b-idp-01`, `IIP-IDP01-a-idp-01`, `IIP-IDP03-a-idp-01`, `IIP-IDP04-a-idp-01`, `IIP-IDP04-b-idp-01`, `IIP-IDP11-a-idp-01`, `IIP-IDP16-a-idp-01`, `IIP-IDP17-b2-idp-01`, `IIP-IDP17-c-idp-01`, `IIP-IDP17-n-idp-01`, `IIP-IDP17-r-idp-01`, `IIP-IDP17-s-idp-01`, `IIP-IDP17-u-idp-01`, `IIP-IDP18-c-idp-01`, `IIP-IDP18-d-idp-01`, `IIP-IDP19-b-idp-01`, `IIP-IDP19-c-idp-01`, `IIP-IDP20-a-idp-01`, `IIP-MD01-a-idp-01`, `IIP-MD02-a-idp-01`, `IIP-MD02-b-idp-01`, `IIP-MD02-d-idp-01`, `IIP-MD03-a-idp-01`, `IIP-MD03-b-idp-01`, `IIP-MD03-c-idp-01`, `IIP-MD03-d-idp-01`, `IIP-MD04-a-idp-01`, `IIP-MD04-b-idp-01`, `IIP-MD04-c-idp-01`, `IIP-MD05-a-idp-01`, `IIP-MD05-a1-idp-01`, `IIP-MD05-a2-idp-01`, `IIP-MD05-a3-idp-01`, `IIP-MD05-a8-idp-01`, `IIP-MD05-ac-idp-01`, `IIP-MD05-ad-idp-01`, `IIP-MD05-af-idp-01`, `IIP-MD05-ah-idp-01`, `IIP-MD05-am-idp-01`, `IIP-MD05-an-idp-01`, `IIP-MD05-ao-idp-01`, `IIP-MD05-ap-idp-01`, `IIP-MD05-aq-idp-01`, `IIP-MD05-ar-idp-01`, `IIP-MD05-as-idp-01`, `IIP-MD05-av-idp-01`, `IIP-MD05-aw-idp-01`, `IIP-MD05-b-idp-01`, `IIP-MD05-c-idp-01`, `IIP-MD05-c1-idp-01`, `IIP-MD05-c2-idp-01`, `IIP-MD05-c3-idp-01`, `IIP-MD05-cd-idp-01`, `IIP-MD05-d-idp-01`, `IIP-MD05-d1-idp-01`, `IIP-MD05-e-idp-01`, `IIP-MD05-e7-idp-01`, `IIP-MD05-e8-idp-01`, `IIP-MD05-e9-idp-01`, `IIP-MD05-ea-idp-01`, `IIP-MD05-f-idp-01`, `IIP-MD05-f5-idp-01`, `IIP-MD05-fg-idp-01`, `IIP-MD06-a-idp-01`, `IIP-MD06-a1-idp-01`, `IIP-MD06-a2-idp-01`, `IIP-MD06-a3-idp-01`, `IIP-MD06-a5-idp-01`, `IIP-MD06-a6-idp-01`, `IIP-MD06-a7-idp-01`, `IIP-MD06-ab-idp-01`, `IIP-MD06-b-idp-01`, `IIP-MD07-b-idp-01`, `IIP-MD11-a-idp-01`, `IIP-SSO01-ae-idp-01`, `IIP-SSO01-cz-idp-01`, `IIP-SSO01-eb-idp-01`, `IIP-SSO01-ep-idp-01`, `IIP-SSO01-fp-idp-01`, `IIP-SSO01-fr-idp-01`, `IIP-SSO01-g-idp-01`, `IIP-SSO01-ga-idp-01`, `IIP-SSO01-gb-idp-01`, `IIP-SSO01-gc-idp-01`, `IIP-SSO01-gd-idp-01`, `IIP-SSO01-gj-idp-01`, `IIP-SSO01-i2-idp-01`, `IIP-SSO01-k-idp-01`, `IIP-SSO01-z-idp-01`, `IIP-SSO03-b-idp-01`, `IIP-SSO05-a-idp-01`, `IIP-SSO05-a2-idp-01`, `IIP-SSO05-a3-idp-01`, `IIP-SSO07-b-idp-01`


## 証拠

ローカルの `build/acceptance/reference-20260914/remaining-audit/inventory.json` に現在の全未検証観測のRun、ケースID、理由コード、試験条件、対照、次の作業、元result.jsonのSHA-256を保存しています。追加再試験の全結果は `retest-delta.json`、変更前の集合は `baseline.json` に保存しています。元の結果や承認済みケース定義は変更していません。

実装確認: `BrowserEvidenceTestCase`、`IdpExecutableBrowserFixtureScenarioTestCase`、`ApprovedConfigCaseRegistry`、`AttestedOutcomeTestCase`。ケースごとの条件は `tests/cases.yaml` を参照しています。

台帳生成時に、全未検証観測の承認済み条件・正負対照と元result.jsonのRun・SHA-256・Verdict・理由コードを照合します。不一致があれば生成を失敗させます。ケース単位の全条件・variantグループ・前提・解釈制約は `unresolved-contract-audit.json` に保存します。この監査の成功は判定実装の完了を意味しません。

再生成: `.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit`。
