# Reference IdP テスト比較と失敗原因

2026-09-14、ローカル検証。対象は各製品のIdP機能。製品全体の適合認証や公開済みの不具合報告ではありません。構成・版・証拠の詳細は [実行記録](21-reference-execution-record.md) を参照してください。

この表は `dev/reference-acceptance/generate_comparison.py` で実測の `result.json` から生成します。過去の結果や承認済みの判定定義を書き換えず、Suite・設定に起因する誤判定を別表示にしています。

- **Success**: 評価結果がPASS。単にSAMLのSuccess応答が返ったという意味ではありません。異常な要求を適切に拒否した場合もSuccessです。
- **Failed (Product)**: 下記の構成・試験範囲で、要求される動作と製品からの応答が一致しません。原因は製品側の動作または機能不足です。あらゆる構成で発生する、あるいはセキュリティ侵害が成立するという意味ではありません。
- **Not verified (Suite / Configuration)**: 製品の失敗とは確定できないもの。Successにも集計しません。
- **Warning**: EvaluatorによるWARNING。SHOULD/MAYの区別を保持するため、Failedへ変換しません。
- **Not verified / Not observable / Indeterminate / Not run**: 未検証・観測不能・判定不能・当該Runに存在しないテスト。N/Aとは区別します。

## 原因の切り分け

| 対象 | テスト／現象 | 原因と結論 | 根拠 |
|---|---|---|---|
| Keycloak、SimpleSAMLphp | `IIP-SSO01-fk` | Product: 署名対象の一部または全部を除外するXPath変換を受け入れる | 署名必須設定、正常署名の対照、除外変換の各要求を確認。HTTP-POSTのXML署名であり、外側のRedirect署名による保護ではない。署名生成の正負対照テストも再実行済み。Core §5.4.4。 |
| Keycloak、SimpleSAMLphp | `IIP-SSO07-b` | Product: 要求したSubjectと異なる識別子をSuccessで返す | 通常要求の正常系対照の後、persistent Subjectを明示した要求を送信。NameIDPolicyによるFormat変更指定はなく、要求・応答のInResponseToは一致。Keycloakは復号後に照合済み。Core §3.4.1.4のstrong matchに反する。観測した条件の違反であり、ケースの全条件を実行済みという意味ではない。 |
| SimpleSAMLphp | `IIP-SSO01-ag` | Product: XML Destination不一致でもSuccess | 正しいDestinationの対照に加え、ホスト・パス・IdPを変えた要求で再現。HTTP送信先自体は登録済みIdP。Core §3.2.1。 |
| Shibboleth | `IIP-SSO05-b2` | Product: transient NameIDがXML IDの字句規則を満たさない | 復号後に `+`、`/`、`=` を確認。既定のCryptoTransientIdGeneratorという構成を含む結果。Core §§1.3.4、8.3.8。識別子の生値は掲載しない。 |
| SimpleSAMLphp | `IIP-SSO05-a`、`IIP-IDP10-d` | Product: persistent要求にtransientを返す | 要求Formatと復号後NameID Formatの直接比較。正常系が動作する構成で再現。Core §3.4.1.4。 |
| Keycloak、SimpleSAMLphp | `IIP-IDP10-b` | Product: 未知の別SP修飾子等をエラーにせず受理する | 要求された別SPと返却識別子のスコープが一致しない。同一SPの修飾子省略 [S1] とは別の現象。Core §3.4.1.1。 |
| SimpleSAMLphp | `IIP-IDP05-a`、`IIP-IDP08-a` | Product: 未対応の要求／exact AuthnContext条件を満たさずSuccess | 正常系対照あり。未知のNameID Formatや認証コンテキスト要求に既定値で応答。Passiveの全副ケースが失敗したという意味ではない。Core §§3.3.2.2.1、3.4.1.1、3.4.1.4。 |
| Keycloak、Shibboleth | `IIP-IDP17-t` | Product: セッション権威によるLogoutRequestにNotOnOrAfterがない | IdP起点の実ブラウザ操作で受信したLogoutRequest属性を確認。後続のブラウザ完了表示とは独立した観測。Core §3.7.3.2。 |
| SimpleSAMLphp | `IIP-IDP17-m` | Product: HTTP-POST LogoutRequestに署名がない | 実際の受信バインディングとXMLを確認。NotOnOrAfterは存在するため、期限欠落とは区別。Core §3.7、Bindings §3.5。 |
| Keycloak、SimpleSAMLphp | `IIP-IDP15-a` | Product/profile: SAML-EC GeneratedKeyが返らない | PAOS登録を修正した後もSessionKey試験へのSOAP SuccessにGeneratedKeyがない。同じ試験でShibbolethは鍵の両コピー・暗号化検査を通過。通常のECP全体の失敗とは区別する。SAML-EC §5.3.1と承認済みIIP-IDP15.a。 |
| Keycloak | `IIP-IDP10-d` [S1] | Suite: 同じSPの修飾子省略を文字列不一致としてFAILにする | Core §§8.3.7–8.3.8には省略規則がある。採用済みRunにはNOT_VERIFIEDへの保留修正を適用。variant `v-e2c03ed209` の原文再照合・署名再承認と限定条件下の省略許可実装は専用ブランチで完了。新定義の実Run未採用のため、表は保留を維持する。 |
| SimpleSAMLphp | `IIP-IDP06-a/b` [S2] | Suite: 時刻精度差による誤FAIL | 認証時刻が進んでも、秒精度のAuthnInstantが小数付きIssueInstantより前として扱われた。報告精度内の順序はNOT_VERIFIEDとし、秒・ミリ秒精度の回帰対照で検証。許容クロックスキューの独自閾値は追加していない。 |
| Keycloak | `IIP-IDP12-a` [C1] | Configuration: ACS indexの登録が不完全 | 入力metadataにはindex 1があるが、native importerの生成したクライアントにそのACS URLがない。完全登録下の製品のindex処理を評価した証拠ではないため、旧FAILを製品の失敗と扱わない。 |
| 各製品 | メタデータcampaign後の待機継続 | Suite: 相関した応答を受けてもWAITING_BROWSERのまま | 相関したmetadata応答で待機を解除する修正。未相関応答は解除しない。Shibboleth再実行で追加baselineなしにCOMPLETED・tests/start成功を確認。 |
| ECP診断 | SOAP応答が取得できない場合のGeneratedKey違反 | Suite: 応答の欠測を違反として扱う | NOT_VERIFIEDへ修正。実際に取得した応答中の鍵欠落と区別。HTTP 303だった古いSimpleSAMLphp診断Runは比較表に採用しない。 |
| Shibboleth SLO | Suiteの中継POSTがiframeで動作できない | Suite: frame-ancestors 'none' | 登録済みIdPのSLO応答先オリジンだけを許可。修正後はShibbolethの監査記録でLogoutResponse・Successの受信を確認。管理画面の埋め込み許可は変更していない。 |
| Shibboleth SLO | 中継後も画面にLogout failedが残る | **未確定: ブラウザ完了表示の相互運用** | IdPはHTTP 200・JSONのSuccessを返すが、in-app browserのiframeはSuite URLに残る。Chrome比較は接続側による自動操作停止で未完了。実画面には拡張UIが見当たらず、停止理由と画面の不一致は未解決。SLO全体を修正済み／Successとは記載しない。 |

署名任意だった旧構成の `IIP-SSO01-ai/aj` は、KeycloakとSimpleSAMLphpを署名必須にした比較ではSuccessです。この構成差を、Suiteの誤判定や署名検証全体の無条件な製品不具合としてまとめません。

根拠文書: [SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)、[SAML Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)、[SAML-EC draft v16](https://www.ietf.org/archive/id/draft-ietf-kitten-sasl-saml-ec-16.txt)。SAML-ECはこの版のドラフトを参照する承認済みプロファイルの結果であり、通常のSAML Coreに新しいMUSTを追加していません。

## 修正と検証の状態

ForceAuthnの精度判定、ECP欠測処理、metadata待機解除、SLOの対象オリジン限定CSP、NameID省略時の誤FAIL抑止を実装しました。署名生成・シナリオの正負対照、および変更箇所のRunner／Peer／API回帰テストが成功しています。ForceAuthn、NameID省略、metadata、SLO応答到達は修正イメージで実際に再実行しました。

元の検証イメージに今回変更したクラスだけを重ねて検証しており、作業ツリーにあった別件のOIDC／管理画面変更は取り込んでいません。ソースSHA-256、イメージdigest、比較に採用したresult.jsonのSHA-256はローカルの `build/acceptance/reference-20260914/fix-verification/` に保存しています。

**承認境界:** 専用ブランチ `nameid-suite-reapproval` では、ユーザーの明示承認に基づくG1・G2承認記録の更新と署名検証が完了しました。固定済み外部検証ツールによるG1・G2検査はすべて成功しています。通常の作業ツリーには別件のOIDC／管理画面変更があり、専用ブランチとの統合は未実施です。この成功は専用ブランチの承認対象に限定され、通常の作業ツリー全体や稼働中イメージの承認を意味しません。

全プロファイルには未検証項目が残っています。表のSuccessだけから製品全体の適合を結論しないでください。

再生成: `.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914`。

## 再承認の進捗（2026-09-14）

ユーザーからNameID判定定義、G2再承認、および承認記録の更新と既存鍵による署名コミットへの明示的な許可を受領し、次のローカルコミットを作成しました。

- 定義・実装: `f4daa528174f9bffe7cccf9833b1e779001236bb`
- G1署名承認: `37d88f14e4e9`（短縮SHA）
- G2承認対象: `e3896d8bfe4ec17323c2ff12d9deb9c500e3565e`
- G2署名承認: `a26f511a6c05bddeb42fc3c35141dd6226afd7ba`

外部固定版によるG1原文照合・署名検証、G2定義・署名検証はすべて成功しました。検証ログはローカルの `build/acceptance/reference-20260914/fix-verification/reapproval/` に保存します。以前の署名操作の承認待ちは解消済みです。専用作業ツリーは `/private/tmp/samlscope-nameid-reapproval`、ブランチは `nameid-suite-reapproval` です。公開・pushは実施していません。

同一SPへの限定された応答でのNameID省略を許可する実装は正負対照テストで検証済みですが、稼働中イメージには未反映です。現在の比較表は再承認前の実行証拠を維持し、再承認だけを理由にNot verifiedをSuccessに変更していません。

## 追加の設定・操作試験

実ブラウザでの追加SSO、署名付き非暗号化Assertionの一時設定、メタデータの一括取り込み、ShibbolethのネイティブHTTP取得による追加試験を実施しました。設定変更・復元・代行操作の回数と判定の差分は [追加試験と設定・操作コスト](25-interaction-execution-cost.md) を参照してください。通常の作業ツリーや新しいNameID定義を稼働イメージへ取り込んだわけではありません。


追加実装と変更クラス限定の検証イメージによる再試験は [追加実装記録](27-additional-implementation.md) を参照してください。比較表の†はケース単位の追加証拠です。公開URL未発行のWarningをHTTPS違反とは扱いません。

G02はv10の追加試験証拠を採用しています。3製品とも正常系対照を含む37往復が成功し、標準文字列20入力・拡張属性16入力を確認しました。リテラルTAB／LFの保存XMLも照合済みです。残条件はNameIDのpersistent／transient、Advice、AttributeValueであり、全体のNot verifiedは維持しています。

SimpleSAMLphpの`IIP-IDP06-a`はv10の新Runで、要求後の再認証時刻を報告精度の曖昧さなく確認したSuccessを採用しています。省略・falseの対照は既存セッション時刻を維持し、trueだけが新しい時刻を返しました。`IIP-IDP06-b`はv9の同様に照合済みの成功証拠を採用していますが、v10の最新試行は時刻精度の曖昧さでNot verifiedでした。表にも以前のRunの証拠であることを明記しています。従来の[S2]は誤FAIL修正の経緯であり、永久にNot verifiedへ固定する注記ではありません。時刻精度による保留を再認証の失敗とは扱いません。

Shibbolethの`IIP-SSO01-fk/fu/gi`は、v8では事前生成された正常系要求がStale Requestとなり`control_failed`で終了しました。v9で要求をケース選択時に生成するよう修正した後、正常系と異常系の試行が成立し、Successを再確認しました。表にはv9の証拠を採用しています。署名の不正入力ではMessage Security Error画面とSAML応答なしをクライアントが確認した試行を含み、全入力でSAMLエラー応答が得られたという意味ではありません。送信待ち時間は保存XMLのIssueInstantとTranscriptの送信時刻を照合しました。


台帳で採用済みの追加結果は、Run・SHA-256・Verdictを照合して比較表へ反映しています。`Failed (台帳採用・原因分類未確認)`は保存済み判定の転記であり、この更新で製品への原因帰属を追加承認したものではありません。

## Not verifiedの内訳

以下は表に採用したケース結果の延べ405件。†のケースは新Runの追加証拠を採用し、それ以外の既存証拠は保持しています。単一Runの集計や全試験の再完走を意味しません。比較表で設定不足として扱い直した旧FAILは、このNOT_VERIFIED集計には含めません。

| 理由 | Keycloak | Shibboleth IdP | SimpleSAMLphp | 解消に必要なこと |
|---|---:|---:|---:|---|
| `case.pending-interaction` | 82 | 51 | 83 | 設定・受信待ちに加え、判定処理未実装の経路を含む。全件台帳を参照 |
| `attestation.interaction-disallowed` | 25 | 25 | 25 | 自己申告を無効にした構成。確認せずに申告を代行しない |
| `browser_fixture_partial` | 18 | 20 | 18 | 一部の試験だけ実行。残るvariantの証拠が不足 |
| `idp.acs-probe.inconclusive` | 3 | 3 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `ec-signature.native-valid-request-rejected` | 0 | 0 | 4 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.error-assertion.inconclusive` | 2 | 0 | 2 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `metadata.algorithms.local-policy-unverified` | 2 | 0 | 2 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.propagation.not-observed` | 2 | 0 | 2 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.signed-request.inconclusive` | 1 | 1 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.version.inconclusive` | 1 | 1 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `metadata.rsa-sha1.unobserved` | 1 | 1 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `control_failed` | 1 | 1 | 0 | 正常系対照が成立せず異常系を判定できない |
| `request.signing.unavailable` | 1 | 0 | 1 | 署名必須構成でSuiteが当該要求を署名できない |
| `slo.partial-logout.not-observed` | 1 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-request.not-observed` | 1 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-response.not-observed` | 1 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `configuration.attribute-name.evidence-incomplete` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.authn-context.inconclusive` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.error-response.inconclusive` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `idp.nameid-policy.inconclusive` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `metadata.algorithms.intersection-evidence-incomplete` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `saml.subject-principal.undetermined` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.async.feedback.unrecognized` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.key-unavailable` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.multiple-keys.configuration-unavailable` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.multiple-keys.key-unavailable` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.negative-control-failed` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.identifier.strong-match-unobservable` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.not-on-or-after.correlation-unavailable` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.partial-logout.unobserved` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.propagation.failure-induction-unavailable` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-response.unavailable` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |

Chromeと承認のブロックを解除するだけでは解消しません。自動判定やfixtureの未実装にはSuiteの実装が必要です。設定・自己申告の経路は証拠の裏付けが必要です。[全件台帳](26-unverified-case-inventory.md)にケースごとの原因と再試験を記録しています。

## テスト別比較

### browser_sso_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Success † |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G02-a-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-G02-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-G03-b-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP01-a-idp-01` | Not verified † | Success † | Success † |
| `IIP-IDP02-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP03-a-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP04-a-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP04-b-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP05-a-idp-01` | Not verified | Success | **Failed (Product)** |
| `IIP-IDP06-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP06-b-idp-01` | Not verified | Not verified | Success (prior run; latest precision not verified) † |
| `IIP-IDP06-c-idp-01` | Success | Success | Success |
| `IIP-IDP07-a-idp-01` | Success | Success | Success |
| `IIP-IDP08-a-idp-01` | **Failed (Product)** † | Not verified | **Failed (Product)** |
| `IIP-IDP09-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP09-b-idp-01` | Warning | Warning | Warning |
| `IIP-IDP10-a-idp-01` | Success | Success | Success |
| `IIP-IDP10-b-idp-01` | **Failed (Product)** | Success | **Failed (Product)** |
| `IIP-IDP10-d-idp-01` | Not verified (Suite) [S1] | Success | **Failed (Product)** |
| `IIP-IDP11-a-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP12-a-idp-01` | Not verified (Configuration) [C1] | Success | Success |
| `IIP-IDP12-b-idp-01` | Not verified | Not verified | Success |
| `IIP-IDP12-c-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP12-d-idp-01` | Success | Not verified | Success |
| `IIP-IDP12-e-idp-01` | Not verified | Success | Success |
| `IIP-IDP12-f-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-a-idp-01` | Success | Success | Success |
| `IIP-SSO01-ad-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ae-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ag-idp-01` | Success | Success | **Failed (Product)** |
| `IIP-SSO01-ah-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ai-idp-01` | Success | Success | Success |
| `IIP-SSO01-aj-idp-01` | Success | Success | Success |
| `IIP-SSO01-ak-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-al-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-an-idp-01` | Success † | Success | Success † |
| `IIP-SSO01-ao-idp-01` | Success | Success | Success |
| `IIP-SSO01-ap-idp-01` | Success | Success | Success |
| `IIP-SSO01-au-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-bk-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cc-idp-01` | Success | Success | Success |
| `IIP-SSO01-ch-idp-01` | Success | Success | Success |
| `IIP-SSO01-ci-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cj-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ck-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cl-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cm-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cn-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cy-idp-01` | Success | Success | Success |
| `IIP-SSO01-cz-idp-01` | Warning | Warning | Not verified † |
| `IIP-SSO01-d-idp-01` | Not verified | Success | Not verified |
| `IIP-SSO01-da-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-db-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-dc-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dd-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-de-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-dh-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-di-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dj-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dk-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dl-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dm-idp-01` | Success | Success | Warning |
| `IIP-SSO01-dn-idp-01` | Success | Success | Warning |
| `IIP-SSO01-do-idp-01` | Success | Success | Warning |
| `IIP-SSO01-dp-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dq-idp-01` | Warning | Success | Warning |
| `IIP-SSO01-ds-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-du-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dv-idp-01` | Success | Success | Success |
| `IIP-SSO01-dw-idp-01` | Success | Success | Success |
| `IIP-SSO01-dy-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-dz-idp-01` | Success | Success | Success |
| `IIP-SSO01-e-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ea-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-eb-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ec-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ed-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ee-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ef-idp-01` | Success | Success | Success |
| `IIP-SSO01-eg-idp-01` | Success | Success | Success |
| `IIP-SSO01-eh-idp-01` | Success | Success | Success |
| `IIP-SSO01-ei-idp-01` | Success | Success | Success |
| `IIP-SSO01-ej-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-em-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-en-idp-01` | Success | Success | Success |
| `IIP-SSO01-eo-idp-01` | Success | Success | Success |
| `IIP-SSO01-ep-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-eq-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-er-idp-01` | Success | Success | Success |
| `IIP-SSO01-es-idp-01` | Success | Success | Success |
| `IIP-SSO01-et-idp-01` | Success | Success | Success |
| `IIP-SSO01-eu-idp-01` | Success | Success | Success |
| `IIP-SSO01-ev-idp-01` | Success | Success | Success |
| `IIP-SSO01-ew-idp-01` | Success | Success | Success |
| `IIP-SSO01-ex-idp-01` | Success | Success | Success |
| `IIP-SSO01-ez-idp-01` | Success † | Success † | Warning † |
| `IIP-SSO01-f-idp-01` | Not verified | Success | Not verified |
| `IIP-SSO01-fd-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fe-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fk-idp-01` | **Failed (Product)** | Success † | **Failed (Product)** |
| `IIP-SSO01-fp-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-fr-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-fs-idp-01` | Success | Success | Success |
| `IIP-SSO01-fu-idp-01` | Warning | Success † | Warning |
| `IIP-SSO01-fv-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-g-idp-01` | Success † | Success † | Not verified |
| `IIP-SSO01-ga-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gb-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gc-idp-01` | Not verified | **Failed (Product)** † | Not verified |
| `IIP-SSO01-gd-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-gi-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-gj-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-h-idp-01` | Success | Success | Success |
| `IIP-SSO01-h1-idp-01` | Success | Success | Success |
| `IIP-SSO01-i-idp-01` | Success | Success | Success |
| `IIP-SSO01-i1-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-i2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-j-idp-01` | Success | Success | Success |
| `IIP-SSO01-k-idp-01` | Not verified | Success † | Success |
| `IIP-SSO01-k1-idp-01` | Success | Success | Success |
| `IIP-SSO01-k2-idp-01` | Success | Success | Success |
| `IIP-SSO01-l-idp-01` | Success | Success | Success |
| `IIP-SSO01-m-idp-01` | Success | Success | Success |
| `IIP-SSO01-v-idp-01` | Success | Success | Success |
| `IIP-SSO01-x-idp-01` | Success | Success | Success |
| `IIP-SSO01-z-idp-01` | Warning † | Warning † | Not verified |
| `IIP-SSO02-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-b-idp-01` | Not verified | Success | Not verified |
| `IIP-SSO04-a-idp-01` | Success † | Success † | Success † |
| `IIP-SSO05-a-idp-01` | Success | Not verified | **Failed (Product)** |
| `IIP-SSO05-a1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO05-a2-idp-01` | Success | Not verified | Not verified |
| `IIP-SSO05-a3-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO05-a8-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO05-b-idp-01` | Success | Success | Success |
| `IIP-SSO05-b1-idp-01` | Success | Success | Success |
| `IIP-SSO05-b2-idp-01` | Success | **Failed (Product)** | Success |
| `IIP-SSO07-a-idp-01` | Success | Success | Success |
| `IIP-SSO07-b-idp-01` | **Failed (Product)** † | Not verified † | **Failed (Product)** † |

### metadata_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-MD01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD02-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD02-b-idp-01` | Not verified | Success | Not verified |
| `IIP-MD02-c-idp-01` | Success † | Success | Success † |
| `IIP-MD02-d-idp-01` | Not verified | Success | Success † |
| `IIP-MD03-a-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD03-b-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD03-c-idp-01` | Not verified | Success | Not verified |
| `IIP-MD03-d-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD03-e-idp-01` | Warning | Warning | Warning |
| `IIP-MD04-a-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD04-b-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD04-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a3-idp-01` | Not verified | Not verified | Not verified † |
| `IIP-MD05-a4-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a5-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a6-idp-01` | Success | Success | Success |
| `IIP-MD05-a7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-a8-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a9-idp-01` | Success | Success | Success |
| `IIP-MD05-ab-idp-01` | Success | Success | Success |
| `IIP-MD05-ac-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ad-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-ae-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-af-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ag-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ah-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ai-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-aj-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ak-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-al-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-am-idp-01` | Not verified | Warning † | Not verified |
| `IIP-MD05-an-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-ao-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-ap-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-aq-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ar-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-as-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-at-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-au-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-av-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-aw-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c3-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-c5-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c6-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c7-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c8-idp-01` | Success | Success | Success |
| `IIP-MD05-c9-idp-01` | Success | Success | Success |
| `IIP-MD05-ca-idp-01` | Success | Success | Success |
| `IIP-MD05-cb-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-cc-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-cd-idp-01` | Not verified | Success | Not verified |
| `IIP-MD05-ce-idp-01` | Success | Success | Success |
| `IIP-MD05-d-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-d1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-d2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d5-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d8-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d9-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-e1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e5-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-e6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e7-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-e8-idp-01` | Not verified | Success † | Not verified † |
| `IIP-MD05-e9-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-ea-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-eb-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-MD05-ec-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ed-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-f1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f5-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-f7-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f8-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f9-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-fa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fb-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-fc-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fd-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fe-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ff-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-fg-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-fh-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-fi-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fj-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-fk-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-g-idp-01` | Success † | Success | Success † |
| `IIP-MD06-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-a1-idp-01` | Not verified | Success | Success † |
| `IIP-MD06-a2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-a3-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-a4-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-a5-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD06-a6-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-a7-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD06-a8-idp-01` | Success † | Success † | Success † |
| `IIP-MD06-a9-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD06-aa-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-ab-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD06-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD07-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD07-b-idp-01` | Not verified | Success † | Success † |
| `IIP-MD09-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD09-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD11-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD12-a-idp-01` | Success † | Success | Success † |
| `IIP-MD12-b-idp-01` | **Failed (Product)** † | Success | Success † |
| `IIP-MD12-c-idp-01` | Success † | Success | Success † |
| `IIP-MD12-d-idp-01` | **Failed (Product)** † | Success | Success † |

### ecp_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-IDP14-a-idp-01` | Success | Success | Success |
| `IIP-IDP14-b-idp-01` | Warning | Warning | Warning |
| `IIP-IDP15-a-idp-01` | **Failed (Product)** | Success | **Failed (Product)** |
| `IIP-IDP16-a-idp-01` | Not verified | Not verified | Not verified |

### single_logout_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-IDP17-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP17-aa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-IDP17-ab-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP17-ac-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-ai-idp-01` | Success | Success | Success |
| `IIP-IDP17-aj-idp-01` | Success | Success | Success |
| `IIP-IDP17-ak-idp-01` | Success | Success | Success |
| `IIP-IDP17-al-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP17-am-idp-01` | Success | Success | Success |
| `IIP-IDP17-an-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b-idp-01` | Success † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-b1-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-b2-idp-01` | Success † | Success † | Not verified † |
| `IIP-IDP17-b3-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-c-idp-01` | Not verified † | Warning † | Not verified † |
| `IIP-IDP17-j-idp-01` | Success | Success † | Success |
| `IIP-IDP17-k-idp-01` | Success | Success † | Success |
| `IIP-IDP17-l-idp-01` | Success | Success † | Success |
| `IIP-IDP17-m-idp-01` | Success | Success † | **Failed (Product)** |
| `IIP-IDP17-n-idp-01` | Not verified | Not verified † | Success |
| `IIP-IDP17-r-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP17-s-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP17-t-idp-01` | **Failed (Product)** | **Failed (Product)** † | Success |
| `IIP-IDP17-u-idp-01` | Not verified | Not verified † | Success |
| `IIP-IDP17-v-idp-01` | Success | Success | Success |
| `IIP-IDP17-x-idp-01` | Success † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-y-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Warning † | Warning † |
| `IIP-IDP17-z-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Warning † | Warning † |
| `IIP-IDP18-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-b-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-c-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP18-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP19-a-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP19-b-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP19-c-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP20-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP21-a-idp-01` | Not verified | Not verified | Not verified |

## 採用した実行証拠

| Profile | Product | Run | Evidence directory |
|---|---|---|---|
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QKZYJCWA259NPF6KPASGVMJATM` | `additional-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_AT0T8032SAJ8FETMM2JTMQGB7H` | `crypto-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_1CV03TRVJZJA99QCCS80R7PHSJ` | `literal-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_1CV03TRVJZJA99QCCS80R7PHSJ` | `build/acceptance/reference-20260914/literal-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QKZYJCWA259NPF6KPASGVMJATM` | `build/acceptance/reference-20260914/additional-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_9XH0Y4Z7P4JFHJTYQ3ZJKE633N` | `build/acceptance/reference-20260918/keycloak-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_AT0T8032SAJ8FETMM2JTMQGB7H` | `build/acceptance/reference-20260914/crypto-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QXEKAXFXVK2Y48CH9HJD7A5DW7` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v2/observations/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_8EC5HRA77MZWGCHCXR1DKB9ADE` | `build/acceptance/reference-20260918/keycloak-attribute-name-capability` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_EEAG5F4CFPVHYP90GGDZXB8VN4` | `build/acceptance/reference-20260918/keycloak-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_F9VD5CSM4XV01J1Q2X1BPJ6DG2` | `build/acceptance/reference-20260918/keycloak-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_JQTKB2M3V6887FKT0DF49G38QZ` | `build/acceptance/reference-20260918/keycloak-browser-chain-v75` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_ZZQH3B5136N955F9W1NAMJ4GSG` | `build/acceptance/reference-20260918/keycloak-default-acs` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_R6M9V3HBVEX0C8TX0FRT0JJTVG` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_R6M9V3HBVEX0C8TX0FRT0JJTVG` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/browser_sso_idp/evaluation` |
| browser_sso_idp | keycloak | `run_0WQJR9TGK0MC4TFTVT1AFKWDKP` | `interaction-followup/after/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_DMGDE6GB0DGZ8HTYRJPY3QY7QG` | `additional-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_BD24PBN5E7QBPNGZH12KH08X39` | `crypto-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Q6KXSR2FM4MPTWZFCBAFQNQ18P` | `literal-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_W01Y7Z2TC4N0BH3PBQZGD2RFBE` | `queue-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_YVEJ7H1J1K1161V8GY4WM3NSXF` | `integrated-implementation/shibboleth/polling-bssso` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Q6KXSR2FM4MPTWZFCBAFQNQ18P` | `build/acceptance/reference-20260914/literal-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_DMGDE6GB0DGZ8HTYRJPY3QY7QG` | `build/acceptance/reference-20260914/additional-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_VQ1J5M9J2XCT0GS0PXBBV3XZMY` | `build/acceptance/reference-20260918/shibboleth-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_BD24PBN5E7QBPNGZH12KH08X39` | `build/acceptance/reference-20260914/crypto-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_ZZKWFCJAMM46A877423CM5XP9E` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_8S5P9BVTX8CCQ770M2KHKXG5CM` | `build/acceptance/reference-20260918/shibboleth-attribute-name-capability-registry` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z43RFP9ZF0175WP18Y1FZD70P9` | `build/acceptance/reference-20260918/shibboleth-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_MC6DQMEQKWPQ66PPBEY45M5R36` | `build/acceptance/reference-20260918/shibboleth-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_J7YRDB4T4J8FXKSRXG4K7ZNJ3Q` | `build/acceptance/reference-20260918/shibboleth-nameid-omission-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_YVEJ7H1J1K1161V8GY4WM3NSXF` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling-bssso` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp | shibboleth | `run_JGADJKCN6GBGKJ68D1WP0G3GMX` | `interaction-followup/after/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TS5JTACXSDMGB9PE8Z9ZS2MP5K` | `additional-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `build/acceptance/reference-20260914/literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TS5JTACXSDMGB9PE8Z9ZS2MP5K` | `build/acceptance/reference-20260914/additional-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_NXTAXWN71DEJF02ZNAQXS4AZA8` | `build/acceptance/reference-20260918/simplesamlphp-opaque-principal-control` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_W9WFP7QB19V0Y15T0QVE7D8RHW` | `build/acceptance/reference-20260918/simplesamlphp-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `build/acceptance/reference-20260914/crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_3Q5C1SMZNZRN1PRDXP511Y9D69` | `build/acceptance/reference-20260918/simplesamlphp-native-ec-signature/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_00MKHH590BSDDG411ST76J02AD` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm128` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_30QS0MMCHGS3Q02VGHJ5VYEP9J` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm256` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_4GWY98RD670EAFJ3R8Q6V2MW52` | `build/acceptance/reference-20260918/simplesamlphp-attribute-name-capability` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_WNMZ106QK6JKRN8P6JFZQ0KNWG` | `build/acceptance/reference-20260918/simplesamlphp-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `build/acceptance/reference-20260914/literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `build/acceptance/reference-20260914/queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XKNHNHTS27D8V15RGGVWPPNWX4` | `build/acceptance/reference-20260918/simplesamlphp-default-acs` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp | simplesamlphp | `run_SJWWBQT1S24VSJGRZMSQ8TJYM4` | `interaction-followup/after/simplesamlphp/browser_sso_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J5EY454Z5ZD3J7Q89SWCFNJNHD` | `build/acceptance/reference-20260918/single-signing-key/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `build/acceptance/reference-20260914/additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation-v64` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_ASRA03EB5GQ074VCME7HESPZ6G` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/metadata_idp/evaluation` |
| metadata_idp | keycloak | `run_HEGZFSAG1WFGFCXX1XE6N1C52B` | `keycloak/metadata_idp/run2` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_N7X58HSBHWGGP8FRZFVYKNKN2F` | `build/acceptance/reference-20260918/shibboleth-md03-signature-v78/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_29FRDNMD9ET5C0F9Z336Q6SFEH` | `build/acceptance/reference-20260918/shibboleth-md03b-signature-v78b` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YW7XT8SYF0K69PK3QN8GAH1GHF` | `build/acceptance/reference-20260918/shibboleth-md04a-required-validuntil-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_KX65MPT7ZXPTDYZ5HMNXBQ6MZ5` | `build/acceptance/reference-20260918/shibboleth-md04c-boundary-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2893MAJ9X84M3TVFWRNY5CAPK4` | `build/acceptance/reference-20260918/single-signing-key/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation-am` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_ZF0TJ2HDCN7C4SRCDDZAQPG860` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v79` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6E5BWBMYHJFZS31AKS9Q1WCP72` | `build/acceptance/reference-20260918/shibboleth-intersection-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_GNBRVD9WSNFGHMXZEFN4BAH6NR` | `build/acceptance/reference-20260918/shibboleth-ui-logo-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `build/acceptance/reference-20260914/additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_M11JND1WT0CYAZVW88NRC2KW5Q` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-metadata/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp | shibboleth | `run_BMEHBBM5QAAAV41HZZX1R70QXH` | `interaction-followup/after/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_47A3XNG2QG2D7E64BDWH6XW5S3` | `build/acceptance/reference-20260918/simplesamlphp-aggregate-import` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_NTB45B0333JF88W97SGWEMZD0D` | `build/acceptance/reference-20260918/simplesamlphp-extension-points-corrected` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_816C536YJ0JK4DB1KCMG2QQNH5` | `build/acceptance/reference-20260918/single-signing-key/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z15GR24Z1AWTH8DX9ZFZYPQSEK` | `build/acceptance/reference-20260918/simplesamlphp-intersection-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `build/acceptance/reference-20260914/additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_F6BGNRP76J1E734N9MRDC3YT2X` | `build/acceptance/reference-20260918/simplesamlphp-metadata-fixture-v67` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GCKEAFAXQGR18R5RJ38SJ8SVP6` | `build/acceptance/reference-20260918/simplesamlphp-native-ec-signature/metadata_idp/evaluation` |
| metadata_idp | simplesamlphp | `run_YVZ8AB57K11T5XRZNEYVHMPQ1Z` | `interaction-followup/after/simplesamlphp/metadata_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_9CQ4T26CJT03AJ9A3ZT7XDM6AW` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_BCJDFCFSWYMHVSESDMZCMBNAKA` | `build/acceptance/reference-20260918/keycloak-producer-algorithms-ecp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp | keycloak | `run_H38KM96SRSD9ESW4B0JQ0RV5JC` | `keycloak/ecp_idp/run5` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_HM0CRTNVGD9Q1PT31P112N28AQ` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp | shibboleth | `run_4E2YMVJR6DPW196YFMWX4V9DN3` | `shibboleth/ecp_idp/run4` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_YBQ5KZHHAY9GV4BC84766X8M1W` | `build/acceptance/reference-20260918/simplesamlphp-native-ec-signature/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp | simplesamlphp | `run_KNM1G6JW0H7MYS6RT0FQX69EK5` | `simplesamlphp/ecp_idp/run6` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W2DFV6VZDAB4S8GN6GAYNQ45MM` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_Z8TR4WMEEQS682CHEM598836MT` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_18b` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp | keycloak | `run_J5SM20CM8MH8BG894VXA2N4BFM` | `keycloak/single_logout_idp/browser2` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_MCZRYHMCFBJ227206Y8YC3XCST` | `slo-encrypted-id-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_7NEJ4R0ZV980M9YJSQEXPADWKQ` | `slo-multiple-keys-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_T8A6A9QZFF5QVYTCK1AFQJZ4RZ` | `key-capability-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_PXFNTJDBJJR8GE88XWPKK0T0HC` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_target_logout` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_RJ0XT9P3SJ4FY20NSDDZB5DRD2` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_PXFNTJDBJJR8GE88XWPKK0T0HC` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_target_logout` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_PXFNTJDBJJR8GE88XWPKK0T0HC` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_target_logout` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_TRBVRX88B7VW14KRS3JFQ3RFKQ` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_18b` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_MCZRYHMCFBJ227206Y8YC3XCST` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_T8A6A9QZFF5QVYTCK1AFQJZ4RZ` | `build/acceptance/reference-20260914/key-capability-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_7NEJ4R0ZV980M9YJSQEXPADWKQ` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_0NKMWAVB7T7DF1RFMQH2VDPD82` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_0NKMWAVB7T7DF1RFMQH2VDPD82` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/single_logout_idp/evaluation` |
| single_logout_idp | shibboleth | `run_23TFJH7Y8APXAWCX58004A9FGG` | `shibboleth/single_logout_idp/browser5` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_19PV7S56N3H0DDENCD1K6GGK61` | `slo-multiple-keys-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_678YKQGJPRK6ENEX8STV7VCMJ8` | `build/acceptance/reference-20260918/simplesamlphp-native-ec-signature/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KPBMMV9KFCC5438QRXT8MTZ2AA` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_18b` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_19PV7S56N3H0DDENCD1K6GGK61` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp | simplesamlphp | `run_DVCVA0CEB6PRZGXWWMV4AKMR1K` | `simplesamlphp/single_logout_idp/browser2` |
