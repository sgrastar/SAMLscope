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
| Shibboleth | `IIP-SSO07-b` | Product: 既知Subjectの要求と異なる識別子をSuccessで返す | 既知principalのnative auditと正常系対照を閉じ、同じ要求に相関する署名・復号済み応答の識別子を照合した。異なるNameIDPolicyによる例外はなく、修飾子の省略だけを失敗理由にはしていない。保存済みG02原本を再利用した観測反例であり、ケース全条件の完走や他の構成への一般化を意味しない。 |
| Keycloak | `IIP-MD05-b` | Product: schema上有効なEndpointType拡張をnative取込で拒否する | 製品自身のconverterへ元の署名fixtureを渡し、外部名前空間の子要素を含む入力の拒否と、同じ鍵・URLの拡張なし対照の受理を実測した。固定native parserの再実行、通常の取込・署名SSO、真のschema不正対照、設定復元を照合した。観測したvariantの違反であり、全メタデータ型の実行済みとはしていない。 |
| SimpleSAMLphp | `IIP-IDP04-b` | Product: 受理した属性サービスの選択指定を実応答へ反映しない | 製品自身が取り込んだ異なる要求属性を持つ二つのサービスと、両属性を返す正常対照を確認した。同じ認証セッション・固定された属性設定で、署名付き要求のindexを0・1・0へ切り替えてもUIDだけを返した。要求・応答署名、ネイティブの属性選択経路、設定復元、稼働判定器の対照を照合した観測反例であり、取込結果の欠落だけではFailedにしていない。 |
| SimpleSAMLphp | `IIP-SSO01-ag` | Product: XML Destination不一致でもSuccess | 正しいDestinationの対照に加え、ホスト・パス・IdPを変えた要求で再現。HTTP送信先自体は登録済みIdP。Core §3.2.1。 |
| Shibboleth | `IIP-SSO05-b2` | Product: transient NameIDがXML IDの字句規則を満たさない | 復号後に `+`、`/`、`=` を確認。既定のCryptoTransientIdGeneratorという構成を含む結果。Core §§1.3.4、8.3.8。識別子の生値は掲載しない。 |
| SimpleSAMLphp | `IIP-SSO05-a`、`IIP-IDP10-d` | Product: persistent要求にtransientを返す | 要求Formatと復号後NameID Formatの直接比較。正常系が動作する構成で再現。Core §3.4.1.4。 |
| Keycloak、SimpleSAMLphp | `IIP-IDP10-b` | Product: 未知の別SP修飾子等をエラーにせず受理する | 要求された別SPと返却識別子のスコープが一致しない。同一SPの修飾子省略 [S1] とは別の現象。Core §3.4.1.1。 |
| SimpleSAMLphp | `IIP-IDP05-a`、`IIP-IDP08-a` | Product: 未対応の要求／exact AuthnContext条件を満たさずSuccess | 正常系対照あり。未知のNameID Formatや認証コンテキスト要求に既定値で応答。Passiveの全副ケースが失敗したという意味ではない。Core §§3.3.2.2.1、3.4.1.1、3.4.1.4。 |
| Keycloak、Shibboleth | `IIP-IDP17-t` | Product: セッション権威によるLogoutRequestにNotOnOrAfterがない | IdP起点の実ブラウザ操作で受信したLogoutRequest属性を確認。後続のブラウザ完了表示とは独立した観測。Core §3.7.3.2。 |
| SimpleSAMLphp | `IIP-IDP17-m` | Product: HTTP-POST LogoutRequestに署名がない | 実際の受信バインディングとXMLを確認。NotOnOrAfterは存在するため、期限欠落とは区別。Core §3.7、Bindings §3.5。 |
| Keycloak 26.7.2 | `IIP-MD05-av` | Product: omitted defaultを選ばず、重複するAssertionConsumerService indexを含むmetadataを使用する | 製品自身のImport clientで4つの評価fixtureとcontrolを投入。control・explicit-first・all-falseは正しいACSへ到達したが、explicit-false後のomitted defaultはACS 1ではなくACS 0へ到達し、重複index fixtureもread-back後にSuccessを返した。開始・終了時のコンテナimage・起動時刻・実行時VERSION、一時clientの削除read-back、原本fixture、要求・応答、Suite実行JARを同一Runに束縛している。Metadata Interoperability §2.4.1。 |
| Shibboleth IdP 5.2.3 | `IIP-MD05-av` | Product: omitted defaultを選ばず、重複するAssertionConsumerService indexを含むmetadataを使用する | 製品自身のFilesystemMetadataProviderで4つの評価fixtureとcontrolを投入。control・explicit-first・all-falseは正しいACSへ到達したが、explicit-false後のomitted defaultはACS 1ではなくACS 0へ到達し、重複index fixtureもSuccessを返した。開始・終了時のコンテナimage・起動時刻・実行時VERSION、設定のバイト一致による復元、原本fixture、要求・応答、Suite実行JARを同一Runに束縛している。Metadata Interoperability §2.4.1。 |
| SimpleSAMLphp 2.5.0 | `IIP-MD05-av` | Product: 同一親要素内で重複するAssertionConsumerService indexを含むmetadataを使用する | native MDQで3つのdefault選択対照（明示true、明示false後の省略、全false）を正しいACSへ送信した後、重複index対照も取得・使用してSuccessを返した。開始・終了時のコンテナimage・起動時刻・実行時VERSIONと設定復元を同一Runに束縛している。Metadata Interoperability §2.4.1。 |
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


## 受理済み更新メタデータと暗号化ログアウトの限定反例

SimpleSAMLphp の旧 `IIP-IDP06-b-idp-01` の Success は監査撤回する。外部の再認証時刻だけでは、認証機構が内部で ForceAuthn を参照できるという承認済み義務を証明しない。元の result と transcript は保存し、原本ハッシュ・Run・参照応答・承認済み variant を照合する review qualification として未検証へ戻す。`IIP-IDP06-a-idp-01` の外部再認証判定と、別 Run の内部機構証拠は変更しない。撤回は `audit_force_authn_mechanism_evidence.py` が検証し、製品の違反を新たに割り当てるものではない。

Keycloak の `IIP-MD06-ab-idp-01` は、同じ entity・native client に対する A→B の元メタデータ取込、明示的な受理、保存設定、実装ソース、署名付き正常対照を固定した共有キャンペーンの証拠を使用する。受理済み B が広告する第2 POST ACS を、同じ B 鍵で正しく署名して要求したときの native `Invalid redirect uri` を、正常 ACS の署名付き Success と不正署名対照に対応付けた。全条件を満たす Success ではなく、承認済み `IIP-MD06.ab#v-7e4460130e` の実適用義務に対する具体的な反例を中央 Evaluator の Failed とする。他の binding・profile や全製品能力の不存在には広げない。

この Run の実際の要求は元の `IIP-MD06-a-idp-01` の共有原本のままで、AB が送信したことにはしていない。AB 自身の準備済み outbox は PENDING・transcript参照なしのまま残る。最初の v187 保存結果では既に原本に基づく再評価が完了しており、明示的な evaluate の前後は同じ結論だった。この finished case と未送信 outbox の組合せは別の Suite 診断原本に記録し、status・case_id・過去の未知配送を修正しない。

SimpleSAMLphp の `IIP-IDP19-c-idp-01` は、正常ログアウト、登録済み第2鍵による復号、登録されていない鍵による暗号化の対照を同じ native セッション・要求・応答に相関した。製品自身の parser・復号検証と実装原本を照合し、登録外鍵の暗号文を native 復号では拒否する一方、同じ実ログアウト経路が成功応答を返した限定反例を中央 Evaluator の Failed とする。汎用ブラウザ observer の対照不成立による古い NOT_VERIFIED は原本どおり残し、無応答や HTTP エラーだけから拒否能力を断定しない。追加 native 原本がない環境には今回の確定を適用しない。

<!--g1-literal--> このバッチの正式採用はFailed 2件で、未検証227→225観測、異なるケースID87は不変。配備v187の対象299テスト、G1構造46/46、G2 21/21が成功し、実行時125ファイルは配布物と一致した。Keycloak 86・Shibboleth 57・SimpleSAMLphp 82観測が残る。正式再評価と採用だけの製品設定書込・製品再起動・SAML送信・Run作成・本人操作は各0。

<!--g1-literal--> Keycloak は過去の収集3試行を共有し、設定操作15・SAML試行45・Run作成3を再利用した。今回のAB採用に重複加算しない。SimpleSAMLphp は先行失敗を含む7試行で設定書込試行33（適用19・復元14）、SAML試行40、認証入力19、Run作成7、native parser12・復号4・署名検査25。Suiteだけのprepare/abortは159、一時鍵7・一時ファイル書込14・削除14を記録した。全設定は復元済みで、一時鍵は削除、製品再起動・本人操作は各0。native helper失敗と旧汎用対照不成立は削除せず、reader修正の追加製品送信はない。

<!--g1-literal--> 実配備JAR再実行ではKeycloakの23対照と既採用a/cの全Outcome・対照を保持し、SimpleSAMLphpの不正原本38対照はすべて未検証になった。独立検証器は `verify_keycloak_supersession_counterexample_acceptance.py` と `verify_ssp_encrypted_logout_acceptance.py`。原本・正式結果・復元と操作数は `build/acceptance/reference-20261001/keycloak-native-supersession-counterexample-v187-r1/`、`ssp-encrypted-logout-native-v186-r7/` に保存し、台帳差分・配備・独立検証ログは `progress-v187.json` に記録する。比較表の原因分類は exact case・profile・reason とこの検証器の一致を必須にする。


台帳で採用済みの追加結果は、Run・SHA-256・Verdictを照合して比較表へ反映しています。`Failed (台帳採用・原因分類未確認)`は保存済み判定の転記であり、この更新で製品への原因帰属を追加承認したものではありません。

## Not verifiedの内訳

以下は表に採用したケース結果の延べ203件。†のケースは新Runの追加証拠を採用し、それ以外の既存証拠は保持しています。単一Runの集計や全試験の再完走を意味しません。比較表で設定不足として扱い直した旧FAILは、このNOT_VERIFIED集計には含めません。

| 理由 | Keycloak | Shibboleth IdP | SimpleSAMLphp | 解消に必要なこと |
|---|---:|---:|---:|---|
| `case.pending-interaction` | 34 | 14 | 33 | 設定・受信待ちに加え、判定処理未実装の経路を含む。全件台帳を参照 |
| `attestation.interaction-disallowed` | 22 | 21 | 22 | 自己申告を無効にした構成。確認せずに申告を代行しない |
| `browser_fixture_partial` | 11 | 7 | 11 | 一部の試験だけ実行。残るvariantの証拠が不足 |
| `idp.acs-probe.inconclusive` | 1 | 2 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `metadata.algorithms.local-policy-unverified` | 2 | 0 | 2 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.propagation.not-observed` | 2 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `audit.slo-async-session-failure-unproven` | 1 | 1 | 0 | IdP自身のセッション終了失敗を安全に誘導し、正常終了と失敗通知の両対照を観測する必要がある |
| `idp.error-assertion.inconclusive` | 1 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-response.not-observed` | 1 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `audit.force-authn-mechanism-access-unproven` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `audit.metadata-full-ui-controls-unproven` | 0 | 0 | 1 | 正しい配置のUIInfo・DiscoHintsを取り込み、全variantの値を製品のUIまたは実効読み戻しで確認する必要がある |
| `control_failed` | 1 | 0 | 0 | 正常系対照が成立せず異常系を判定できない |
| `idp.nameid-policy.inconclusive` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.async.feedback.unrecognized` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.key-unavailable` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.multiple-keys.key-unavailable` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.encrypted-id.negative-control-failed` | 0 | 0 | 1 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.partial-logout.not-observed` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-request.not-observed` | 1 | 0 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |
| `slo.redirect-response.unavailable` | 0 | 1 | 0 | 当該ケースの応答・対象設定・正常系対照を追加確認 |

Chromeと承認のブロックを解除するだけでは解消しません。自動判定やfixtureの未実装にはSuiteの実装が必要です。設定・自己申告の経路は証拠の裏付けが必要です。[全件台帳](26-unverified-case-inventory.md)にケースごとの原因と再試験を記録しています。

## テスト別比較

### browser_sso_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Success † |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G02-a-idp-01` | Success † | Success † | Success † |
| `IIP-G02-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-G03-b-idp-01` | Success † | Success † | Success † |
| `IIP-IDP01-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-IDP02-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP03-a-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP04-a-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP04-b-idp-01` | Not verified | Success † | **Failed (Product)** † |
| `IIP-IDP05-a-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** |
| `IIP-IDP06-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP06-b-idp-01` | Not verified | Success † | Not verified † |
| `IIP-IDP06-c-idp-01` | Success | Success | Success |
| `IIP-IDP07-a-idp-01` | Success | Success | Success |
| `IIP-IDP08-a-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** |
| `IIP-IDP09-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP09-b-idp-01` | Warning | Warning | Warning |
| `IIP-IDP10-a-idp-01` | Success | Success | Success |
| `IIP-IDP10-b-idp-01` | **Failed (Product)** | Success | **Failed (Product)** |
| `IIP-IDP10-d-idp-01` | Not verified (Suite) [S1] | Success | **Failed (Product)** |
| `IIP-IDP11-a-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-IDP12-a-idp-01` | Not verified (Configuration) [C1] | Success | Success |
| `IIP-IDP12-b-idp-01` | Success † | Success † | Success |
| `IIP-IDP12-c-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP12-d-idp-01` | Success | Not verified | Success |
| `IIP-IDP12-e-idp-01` | Success † | Success | Success |
| `IIP-IDP12-f-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-a-idp-01` | Success | Success | Success |
| `IIP-SSO01-ad-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ae-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-ag-idp-01` | Success | Success | **Failed (Product)** |
| `IIP-SSO01-ah-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ai-idp-01` | Success | Success | Success |
| `IIP-SSO01-aj-idp-01` | Success | Success | Success |
| `IIP-SSO01-ak-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-al-idp-01` | Success † | Success † | Success † |
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
| `IIP-SSO01-cz-idp-01` | Warning | Warning | Success † |
| `IIP-SSO01-d-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** † |
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
| `IIP-SSO01-em-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-en-idp-01` | Success | Success | Success |
| `IIP-SSO01-eo-idp-01` | Success | Success | Success |
| `IIP-SSO01-ep-idp-01` | Not verified | Not verified | Warning † |
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
| `IIP-SSO01-fp-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-fr-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fs-idp-01` | Success | Success | Success |
| `IIP-SSO01-fu-idp-01` | Warning | Success † | Warning |
| `IIP-SSO01-fv-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-g-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-ga-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gb-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gc-idp-01` | Not verified | **Failed (Product)** † | Not verified |
| `IIP-SSO01-gd-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-gi-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-gj-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-h-idp-01` | Success | Success | Success |
| `IIP-SSO01-h1-idp-01` | Success | Success | Success |
| `IIP-SSO01-i-idp-01` | Success | Success | Success |
| `IIP-SSO01-i1-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-i2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-j-idp-01` | Success | Success | Success |
| `IIP-SSO01-k-idp-01` | Success † | Success † | Success |
| `IIP-SSO01-k1-idp-01` | Success | Success | Success |
| `IIP-SSO01-k2-idp-01` | Success | Success | Success |
| `IIP-SSO01-l-idp-01` | Success | Success | Success |
| `IIP-SSO01-m-idp-01` | Success | Success | Success |
| `IIP-SSO01-v-idp-01` | Success | Success | Success |
| `IIP-SSO01-x-idp-01` | Success | Success | Success |
| `IIP-SSO01-z-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO02-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-b-idp-01` | Success † | Success † | Success † |
| `IIP-SSO04-a-idp-01` | Success † | Success † | Success † |
| `IIP-SSO05-a-idp-01` | Success | Success † | **Failed (Product)** |
| `IIP-SSO05-a1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO05-a2-idp-01` | Success | Success † | Success † |
| `IIP-SSO05-a3-idp-01` | Success † | Success † | Success † |
| `IIP-SSO05-a8-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO05-b-idp-01` | Success | Success | Success |
| `IIP-SSO05-b1-idp-01` | Success | Success | Success |
| `IIP-SSO05-b2-idp-01` | Success | **Failed (Product)** | Success |
| `IIP-SSO07-a-idp-01` | Success | Success | Success |
| `IIP-SSO07-b-idp-01` | **Failed (Product)** † | **Failed (Product)** † | **Failed (Product)** † |

### metadata_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-MD01-a-idp-01` | Success † | Success † | Success † |
| `IIP-MD02-a-idp-01` | Success † | Success † | Success † |
| `IIP-MD02-b-idp-01` | Success † | Success | Success † |
| `IIP-MD02-c-idp-01` | Success † | Success | Success † |
| `IIP-MD02-d-idp-01` | Not verified | Success | Success † |
| `IIP-MD03-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-c-idp-01` | **Failed (Product)** † | Success | Success † |
| `IIP-MD03-d-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-e-idp-01` | Warning | Warning | Warning |
| `IIP-MD04-a-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD04-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD04-c-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD05-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a1-idp-01` | Success † | Success † | Not verified |
| `IIP-MD05-a2-idp-01` | Success † | Success † | Not verified |
| `IIP-MD05-a3-idp-01` | Not verified | Not verified | Not verified † |
| `IIP-MD05-a4-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a5-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a6-idp-01` | Success | Success | Success |
| `IIP-MD05-a7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-a8-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a9-idp-01` | Success | Success | Success |
| `IIP-MD05-ab-idp-01` | Success | Success | Success |
| `IIP-MD05-ac-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ad-idp-01` | Warning † | Success † | Success † |
| `IIP-MD05-ae-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-af-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-ag-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ah-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-ai-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-aj-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ak-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-al-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-am-idp-01` | Not verified | Warning † | Warning † |
| `IIP-MD05-an-idp-01` | Not verified | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-MD05-ao-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-ap-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-aq-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-ar-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-as-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD05-at-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-au-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-av-idp-01` | **Failed (Product)** † | **Failed (Product)** † | **Failed (Product)** † |
| `IIP-MD05-aw-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-b-idp-01` | **Failed (Product)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-MD05-c-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-c1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c2-idp-01` | Not verified | Success † | Success † |
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
| `IIP-MD05-cd-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** † |
| `IIP-MD05-ce-idp-01` | Success | Success | Success |
| `IIP-MD05-d-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-d1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-d2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d5-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d8-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d9-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-e1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e5-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-e6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e7-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-e8-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-MD05-e9-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-ea-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-eb-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-MD05-ec-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ed-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-f1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f5-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-f7-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f8-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f9-idp-01` | Success † | Success † | Warning † |
| `IIP-MD05-fa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fb-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fc-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fd-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fe-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ff-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-fg-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fh-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fi-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fj-idp-01` | Warning † | Warning † | Success † |
| `IIP-MD05-fk-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-g-idp-01` | Success † | Success | Success † |
| `IIP-MD06-a-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-MD06-a1-idp-01` | Not verified | Success | Success † |
| `IIP-MD06-a2-idp-01` | Not verified | Success † | Success † |
| `IIP-MD06-a3-idp-01` | Warning † | Warning † | Not verified |
| `IIP-MD06-a4-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-a5-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD06-a6-idp-01` | Not verified | Success † | Success † |
| `IIP-MD06-a7-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD06-a8-idp-01` | Success † | Success † | Success † |
| `IIP-MD06-a9-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD06-aa-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-ab-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-MD06-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD06-c-idp-01` | Success † | Success † | Success † |
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
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Success † |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified | Success † | Not verified |
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
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-IDP17-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP17-aa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-IDP17-ab-idp-01` | Warning † | Warning † | Warning † |
| `IIP-IDP17-ac-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-ai-idp-01` | Success | Success | Success |
| `IIP-IDP17-aj-idp-01` | Success | Success | Success |
| `IIP-IDP17-ak-idp-01` | Success | Success | Success |
| `IIP-IDP17-al-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | Success † |
| `IIP-IDP17-am-idp-01` | Success | Success | Success |
| `IIP-IDP17-an-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b-idp-01` | Success † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-b1-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-b2-idp-01` | Not verified | Not verified | Not verified † |
| `IIP-IDP17-b3-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-c-idp-01` | Not verified † | Warning † | Warning † |
| `IIP-IDP17-j-idp-01` | Success | Success † | Success |
| `IIP-IDP17-k-idp-01` | Success | Success † | Success |
| `IIP-IDP17-l-idp-01` | Success | Success † | Success |
| `IIP-IDP17-m-idp-01` | Success | Success † | **Failed (Product)** |
| `IIP-IDP17-n-idp-01` | Success † | Success † | Success |
| `IIP-IDP17-r-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP17-s-idp-01` | Not verified † | **Failed (台帳採用・原因分類未確認)** † | Success † |
| `IIP-IDP17-t-idp-01` | **Failed (Product)** | **Failed (Product)** † | Success |
| `IIP-IDP17-u-idp-01` | Warning † | Warning † | Success |
| `IIP-IDP17-v-idp-01` | Success | Success | Success |
| `IIP-IDP17-x-idp-01` | Success † | Success † | **Failed (台帳採用・原因分類未確認)** † |
| `IIP-IDP17-y-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Warning † | Warning † |
| `IIP-IDP17-z-idp-01` | **Failed (台帳採用・原因分類未確認)** † | Warning † | Warning † |
| `IIP-IDP18-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-b-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-c-idp-01` | Not verified † | Success † | Success † |
| `IIP-IDP18-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP19-a-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP19-b-idp-01` | Not verified | Success † | Not verified |
| `IIP-IDP19-c-idp-01` | Not verified † | Success † | **Failed (Product)** † |
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
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_9NSDTT181GXXKP6FRPZ719VHH9` | `build/acceptance/reference-20260928/browser-chain-keycloak-g02-v116-retry1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_RY1Y068ZYS585CFX48MKKYP722` | `build/acceptance/reference-20260930/keycloak-g03-v129` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_3MZXNDWFZ62FNETRN75P79TVPT` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_F02RXET295Z79JB4S3HHY459B4` | `build/acceptance/reference-20261002/keycloak-authentication-identity-r2/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_1G19EET7MAD89ABAG3BSJR316N` | `build/acceptance/reference-20261002/keycloak-registered-signer-r1/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_YNYN0RZPZJCSF9A36B0BTX60HG` | `build/acceptance/reference-20261001/keycloak-native-transient-allow-create-v185-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_0536WQRK5ZEW9S20D06WDJFSWG` | `build/acceptance/reference-20261001/keycloak-native-subject-confirmation-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_0536WQRK5ZEW9S20D06WDJFSWG` | `build/acceptance/reference-20261001/keycloak-native-subject-confirmation-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_EJYK4M640FX4PJAWT2YQW6STER` | `build/acceptance/reference-20260930/post-error-binding-keycloak-v173/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_9XH0Y4Z7P4JFHJTYQ3ZJKE633N` | `build/acceptance/reference-20260918/keycloak-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_WGE123Q325NKQX590ZR0F1ZH9Y` | `build/acceptance/reference-20261001/keycloak-native-persistent-pairwise-v180-r4/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_AT0T8032SAJ8FETMM2JTMQGB7H` | `build/acceptance/reference-20260914/crypto-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_3MZXNDWFZ62FNETRN75P79TVPT` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QXEKAXFXVK2Y48CH9HJD7A5DW7` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v2/observations/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_G0J99F02Y5VAVJPWY78CNTGBJP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-v163-r4` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_G0J99F02Y5VAVJPWY78CNTGBJP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-v163-r4` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_8W6ESET9BX4VF2029FKW5JQEND` | `build/acceptance/reference-20260930/keycloak-attribute-name-capability-absence-v157` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_EEAG5F4CFPVHYP90GGDZXB8VN4` | `build/acceptance/reference-20260918/keycloak-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_T6YFS3EDNTS92F0RHS33WTZTRV` | `build/acceptance/reference-20260930/keycloak-attribute-policy-capability-absence-v159` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_T6YFS3EDNTS92F0RHS33WTZTRV` | `build/acceptance/reference-20260930/keycloak-attribute-policy-capability-absence-v159` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_E8R3MNZD0NM9S6QYGPVD3S215V` | `build/acceptance/reference-20260930/keycloak-idp05a-v127-retry1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_F9VD5CSM4XV01J1Q2X1BPJ6DG2` | `build/acceptance/reference-20260918/keycloak-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_JQTKB2M3V6887FKT0DF49G38QZ` | `build/acceptance/reference-20260918/keycloak-browser-chain-v75` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_P57XA0ZDWHSVWX8PNW01MXSVT7` | `build/acceptance/reference-20260930/keycloak-nameid-omission-probe-v2` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_YT60WQ4FCYBC6ET6HGTDZQT3RE` | `build/acceptance/reference-20260930/keycloak-idp12e-v145/evaluation-v139` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_JZWZCDA4MJ6EZ617JXKRG383K8` | `build/acceptance/reference-20260930/idp12b-keycloak-v150` |
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
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_77C08BXJSBJFG7E1G87QJ9YK6Q` | `build/acceptance/reference-20261001/shibboleth-g02-known-subject-v181-r1/reader-v181-predeployment/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CMTJ8G2DXBWJC07QW9EBT3QA2E` | `build/acceptance/reference-20260930/shibboleth-g03-v130` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20260930/shibboleth-identity-v170-r3/browser/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0M6900RHXJTXKMMGJQGKAQXTRF` | `build/acceptance/reference-20260930/terminal-http-shibboleth-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_4RK6H7SCP540PGAAVVPRPP5YKZ` | `build/acceptance/reference-20261003/shibboleth-registered-signer-r1/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0M6900RHXJTXKMMGJQGKAQXTRF` | `build/acceptance/reference-20260930/terminal-http-shibboleth-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_19E1TEPRGWZZACWS0BWFMHNFJH` | `build/acceptance/reference-20261001/shibboleth-transient-allow-create-v185-r1/reader-v186/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CVMVSDGMG1ZT5K1T7F7CNCV5F5` | `build/acceptance/reference-20261001/shibboleth-subject-confirmation-v184-r4/reader-v185/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CVMVSDGMG1ZT5K1T7F7CNCV5F5` | `build/acceptance/reference-20261001/shibboleth-subject-confirmation-v184-r4/reader-v185/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_VQ1J5M9J2XCT0GS0PXBBV3XZMY` | `build/acceptance/reference-20260918/shibboleth-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_77C08BXJSBJFG7E1G87QJ9YK6Q` | `build/acceptance/reference-20261001/shibboleth-g02-known-subject-v181-r1/subject-match-reader-v183/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_9WWCQTJR1M2ACYNYZ57HPYY48E` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_AH3YZDK6HEGQPYHZA5DT23SK5E` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/browser_sso_idp/metadata/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_ZZKWFCJAMM46A877423CM5XP9E` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z1TGHQBNQRJNXRQ5VF7QB1F7QM` | `build/acceptance/reference-20260930/shibboleth-alg08-aes-v161` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z1TGHQBNQRJNXRQ5VF7QB1F7QM` | `build/acceptance/reference-20260930/shibboleth-alg08-aes-v161` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_K56H9VMXYGKZS1117Y0V66AHYQ` | `build/acceptance/reference-20261004/shibboleth-default-algorithm-r7/reader-v217/formal` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_8S5P9BVTX8CCQ770M2KHKXG5CM` | `build/acceptance/reference-20260918/shibboleth-attribute-name-capability-registry` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z43RFP9ZF0175WP18Y1FZD70P9` | `build/acceptance/reference-20260918/shibboleth-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_MC6DQMEQKWPQ66PPBEY45M5R36` | `build/acceptance/reference-20260918/shibboleth-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20261001/shibboleth-forceauthn-mechanism-v186-r1/reader-v188/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_TY7ZVP2SPK02TT7TBC2TTZBPB7` | `build/acceptance/reference-20261002/shibboleth-authn-exact-r1/browser/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_J7YRDB4T4J8FXKSRXG4K7ZNJ3Q` | `build/acceptance/reference-20260918/shibboleth-nameid-omission-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_2DDHMXNQ7J9HCAB19F8ZPVAPPZ` | `build/acceptance/reference-20260930/idp12bd-shibboleth-v150` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_YVEJ7H1J1K1161V8GY4WM3NSXF` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling-bssso` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20261001/shibboleth-post-error-binding-v179/evaluation-terminal-http-v1` |
| browser_sso_idp | shibboleth | `run_JGADJKCN6GBGKJ68D1WP0G3GMX` | `interaction-followup/after/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TS5JTACXSDMGB9PE8Z9ZS2MP5K` | `additional-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_2HC9SHR4PRST13WH08VNRCRZXR` | `build/acceptance/reference-20260929/browser-chain-ssp-g02-v116` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_2VQYH1JSEQSH0K2WQZ425MGS5D` | `build/acceptance/reference-20260930/ssp-g03-v129` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260918/ssp-browser-chain-v2` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260918/ssp-browser-chain-v2` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_7ZHAZEFYR3SQ2ZF1H93M5BYVWH` | `build/acceptance/reference-20261001/ssp-authentication-identity-v187-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_P0KQBXB1WE72FG0GP91FV4FSC8` | `build/acceptance/reference-20261002/simplesamlphp-registered-signer-r3/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KE84Y9K3YPETNPD2WR3F4C694N` | `build/acceptance/reference-20261001/ssp-native-subject-principal-v168-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_06ZZ1WXNBV0BNEZJKHPPHN6AEB` | `build/acceptance/reference-20261004/simplesamlphp-version-mismatch-r2/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A1ETYRSEPB9Q2M0TW9X90SHE06` | `build/acceptance/reference-20261001/ssp-transient-allow-create-v183-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DNSXEDH66T55QVSQWMZVQZ4K1G` | `build/acceptance/reference-20261001/ssp-subject-confirmation-native-v178-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DNSXEDH66T55QVSQWMZVQZ4K1G` | `build/acceptance/reference-20261001/ssp-subject-confirmation-native-v178-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260930/post-error-binding-simplesamlphp-v173/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_W9WFP7QB19V0Y15T0QVE7D8RHW` | `build/acceptance/reference-20260918/simplesamlphp-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_T1KNFTYX3KNM9NX1PK0WQXP8MW` | `build/acceptance/reference-20260930/ssp-native-persistent-normal-v165-r6/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_Z1JSR2SNB3CS7R1XHEB8MJCP7H` | `build/acceptance/reference-20261001/ssp-native-persistent-pairwise-v166-r3/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `build/acceptance/reference-20260914/crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_8W6B711ANVWTPPZSS0K05PBX1M` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TC481X3D92H47146REC8ZR44EH` | `build/acceptance/reference-20260930/ssp-native-ec-v133/browser_sso_idp/evaluation-v133` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_00MKHH590BSDDG411ST76J02AD` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm128` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_30QS0MMCHGS3Q02VGHJ5VYEP9J` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm256` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_4GWY98RD670EAFJ3R8Q6V2MW52` | `build/acceptance/reference-20260918/simplesamlphp-attribute-name-capability` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_WNMZ106QK6JKRN8P6JFZQ0KNWG` | `build/acceptance/reference-20260918/simplesamlphp-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_0F3AC58K1P1MJGQJ1Q0BDVPR6M` | `build/acceptance/reference-20260930/simplesamlphp-attribute-policy-evaluation-v153` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_0F3AC58K1P1MJGQJ1Q0BDVPR6M` | `build/acceptance/reference-20260930/simplesamlphp-attribute-policy-evaluation-v153` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_69SHRHN3H4F7DJYZCFB42YGKVK` | `build/acceptance/reference-20261001/ssp-attribute-service-index-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `build/acceptance/reference-20260914/literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XKNHNHTS27D8V15RGGVWPPNWX4` | `build/acceptance/reference-20260918/simplesamlphp-default-acs` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `build/acceptance/reference-20260914/queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp | simplesamlphp | `run_SJWWBQT1S24VSJGRZMSQ8TJYM4` | `interaction-followup/after/simplesamlphp/browser_sso_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_CVF559MZJPR15Y499GZ76NFT18` | `build/acceptance/reference-20260930/keycloak-md01-native-url-v158-r7/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YA47R73Z5BYNTC6AANT6SMJZCT` | `build/acceptance/reference-20260930/keycloak-md02-native-refresh-v158-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_1TV53ZGRM98QM45SA90PSGA3QC` | `build/acceptance/reference-20260918/keycloak-md02b-v110` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Z0RC3P1PWXJFG4T4736TMBS6FV` | `build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_0FTCNNW469F5SD19BR6GT4EAAG` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158/md04c-capability-conclusion-v1` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Y3QFVC9TC07YYDRBFR08AN3C3G` | `build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/evaluation-v194` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Y3QFVC9TC07YYDRBFR08AN3C3G` | `build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/evaluation-v194` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J5EY454Z5ZD3J7Q89SWCFNJNHD` | `build/acceptance/reference-20260918/single-signing-key/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_E6QM9P3HYKM1Q40MQ1NQHS69W6` | `build/acceptance/reference-20260930/publisher-keycloak-v120/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_GF71YH0KWBTXP4ZM8C1TFEG7CS` | `build/acceptance/reference-20260930/keycloak-rsa-sha1-metadata-v152` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HX2ZP96JPC1NN5XNPH1FEFZ9GG` | `build/acceptance/reference-20260930/keycloak-default-acs-v139/evaluation-v139` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_ZDVRESFDXKV24NE5S29M2P5NVN` | `build/acceptance/reference-20261001/keycloak-native-schema-admission-v183-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_5PS5A09N019JCV0BT8DQRMNZNN` | `build/acceptance/reference-20260930/keycloak-mdiop-representation-native-v171-r5/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_CW996EM45SYJPJF4VGT54ZKTDA` | `build/acceptance/reference-20260918/keycloak-md05d-v104` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_9HE4ZZB92JHW6ZP10K44K5X7BD` | `build/acceptance/reference-20260918/keycloak-md05e-v106` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_9VMW5N633947P63NVBARN5T2EG` | `build/acceptance/reference-20260930/keycloak-intersection-capability-sha512-v167/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_82S5JH8MMJD83SPDNM6HSRTGEC` | `build/acceptance/reference-20261001/keycloak-native-ui-consumer-v178-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_6DYMRF586HQ41JC6HZZVBTHCG8` | `build/acceptance/reference-20260930/keycloak-ui-feature-absence-v155` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_60VNZAT8Y5SMSS0HVRYWXAJ947` | `build/acceptance/reference-20260918/keycloak-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_XH5YWJR5S0FX6CTTHFB3990WE1` | `build/acceptance/reference-20261003/keycloak-ui-safety-r1/evaluation-v204` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_82S5JH8MMJD83SPDNM6HSRTGEC` | `build/acceptance/reference-20261001/keycloak-native-ui-consumer-v178-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `build/acceptance/reference-20260914/additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_6DYMRF586HQ41JC6HZZVBTHCG8` | `build/acceptance/reference-20260930/keycloak-ui-feature-absence-v155` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-supersession-v177-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation-v64` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-supersession-counterexample-v187-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Z0RC3P1PWXJFG4T4736TMBS6FV` | `build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-self-contained-trust-v178-r1/evaluation-v179` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MT4QSB65RGQRC6MZKXF15KCJMS` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_ASRA03EB5GQ074VCME7HESPZ6G` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/metadata_idp/evaluation` |
| metadata_idp | keycloak | `run_HEGZFSAG1WFGFCXX1XE6N1C52B` | `keycloak/metadata_idp/run2` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2442PWPHNVJ2QDXD1TFVB1XMJ4` | `build/acceptance/reference-20260930/shibboleth-dynamic-mdq-v8/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6EZ54PE9MBPH0C78MC6VPQV5SV` | `build/acceptance/reference-20260930/shibboleth-native-refresh-v164-r1/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_N7X58HSBHWGGP8FRZFVYKNKN2F` | `build/acceptance/reference-20260918/shibboleth-md03-signature-v78/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_29FRDNMD9ET5C0F9Z336Q6SFEH` | `build/acceptance/reference-20260918/shibboleth-md03b-signature-v78b` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FFD6R6CVAPGKW17HESMFM1A68E` | `build/acceptance/reference-20260930/md03d-shibboleth-v158` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YW7XT8SYF0K69PK3QN8GAH1GHF` | `build/acceptance/reference-20260918/shibboleth-md04a-required-validuntil-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_KX65MPT7ZXPTDYZ5HMNXBQ6MZ5` | `build/acceptance/reference-20260918/shibboleth-md04c-boundary-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_0ENQCX5J2EN57TDX23AZ82Q6AF` | `build/acceptance/reference-20261001/shibboleth-entityid-uniqueness-v180-r1/reader-v181/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_EQ37Y4AX9F7H8KR0KRMPF069DP` | `build/acceptance/reference-20260918/shibboleth-md05-a1a2-v76/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2893MAJ9X84M3TVFWRNY5CAPK4` | `build/acceptance/reference-20260918/single-signing-key/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2442PWPHNVJ2QDXD1TFVB1XMJ4` | `build/acceptance/reference-20260930/publisher-shibboleth-v120b/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_M53G1T57ZXF9Q0P2GEDHWPN0EA` | `build/acceptance/reference-20261001/shibboleth-rsa-sha1-metadata-v171-r5/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation-am` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_ZF0TJ2HDCN7C4SRCDDZAQPG860` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v79` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6KGY6JFP7CEAV5JNQ6NA3N4SGS` | `build/acceptance/reference-20260918/shibboleth-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6KGY6JFP7CEAV5JNQ6NA3N4SGS` | `build/acceptance/reference-20260918/shibboleth-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_J43EG1E1PDSAGD7EXG3GYRNSHN` | `build/acceptance/reference-20261002/shibboleth-metadata-validity-r2/reader-v193/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_VG6RYQ2RN6TMS2GMFVM1QHQJ36` | `build/acceptance/reference-20260930/shibboleth-default-acs-v138/evaluation-v138` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P1KVNHQWPCRSGHZ8RN0ZXDQC3J` | `build/acceptance/reference-20260918/shibboleth-md05b-v110` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_J7GJGATXAXDTV916CXJN8RRK5Z` | `build/acceptance/reference-20260930/shibboleth-mdiop-full-v172-r2/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_MAS75FBV4PTEKZA2M1895RYPBS` | `build/acceptance/reference-20260918/shibboleth-md05c2-v105` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WYXRSA1PEQ42W6KJ1X40697112` | `build/acceptance/reference-20260918/shibboleth-md05d-v104` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_SGXSMPF0H9GDB15P8JABPQQYEY` | `build/acceptance/reference-20260918/shibboleth-md05e-v106` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XG5TCTRKY859K6HKXVB7TT53E3` | `build/acceptance/reference-20260918/shibboleth-md05e7-order-v90` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6E5BWBMYHJFZS31AKS9Q1WCP72` | `build/acceptance/reference-20260918/shibboleth-intersection-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FSF0BPRS2Z5X9WD99AYCS7GZFM` | `build/acceptance/reference-20261003/shibboleth-full-ui-r2/evaluation-v206` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_GNBRVD9WSNFGHMXZEFN4BAH6NR` | `build/acceptance/reference-20260918/shibboleth-ui-logo-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_MJ4V11GPKFJZRTNAP8EPP3MASF` | `build/acceptance/reference-20260918/shibboleth-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `build/acceptance/reference-20260914/additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_JJPW4W8GACM9DT4PKH4CG0KWC7` | `build/acceptance/reference-20261003/shibboleth-metadata-application-qualified-r1/evaluation-v213` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_77SAYK1RNYTD9E3HPTS5FQ5Q09` | `build/acceptance/reference-20261002/shibboleth-role-keys-r1/reader-v195/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2DMZGR4YBY1K2CHG4710SDP2BA` | `build/acceptance/reference-20260930/shibboleth-role-signing-http-v165-r1/refresh/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CTX8SZ9YSEJQCRQ12WF3PPH8XN` | `build/acceptance/reference-20261002/shibboleth-certificate-runtime-r1/reader-v197/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_JJPW4W8GACM9DT4PKH4CG0KWC7` | `build/acceptance/reference-20261003/shibboleth-metadata-application-qualified-r1/evaluation-v213` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_DCXY3VQPEXQF0KPGMS53PEPQCW` | `build/acceptance/reference-20260930/md06b-shibboleth-v158-r3` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_4761GW37A6K0MAJ6T640MKSY50` | `build/acceptance/reference-20261003/shibboleth-role-self-contained-trust-r2/trust-proof/reader-v204/formal` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FD05JGHS5BY07MT016TY4FADFM` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_0HDWMFK58A4V5W9BPWYABRNDRA` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/metadata_idp/metadata/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_M11JND1WT0CYAZVW88NRC2KW5Q` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-metadata/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp | shibboleth | `run_BMEHBBM5QAAAV41HZZX1R70QXH` | `interaction-followup/after/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4C0CTQG9ZE90CV3XD17XD4JGCJ` | `build/acceptance/reference-20260930/ssp-native-mdq-direct-v1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GM1SB82C8169KJ8D2T88G2WJ5S` | `build/acceptance/reference-20260930/ssp-metadata-refresh-v153` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_A0ATSTDF4W6HFC1GCYTFRXRRMR` | `build/acceptance/reference-20260918/simplesamlphp-md02b-v110` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_47A3XNG2QG2D7E64BDWH6XW5S3` | `build/acceptance/reference-20260918/simplesamlphp-aggregate-import` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HF9TAH6VHXY7RQK03JGW27XTF8` | `build/acceptance/reference-20260930/ssp-metadata-signature-v162/campaign-v3/repair-invalid-control` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HF9TAH6VHXY7RQK03JGW27XTF8` | `build/acceptance/reference-20260930/ssp-metadata-signature-v162/campaign-v3/repair-invalid-control` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HQBWWJ98N8XV9X0DFE1DNWHF03` | `build/acceptance/reference-20260930/md03d-simplesamlphp-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_35NQ5VQX5JZTEXMB4RVK37CZVY` | `build/acceptance/reference-20260930/ssp-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z4F3PP7WE9PWP284YCG5YKWANF` | `build/acceptance/reference-20260930/ssp-native-mdq-fixtures-v1/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_35NQ5VQX5JZTEXMB4RVK37CZVY` | `build/acceptance/reference-20260930/ssp-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_NTB45B0333JF88W97SGWEMZD0D` | `build/acceptance/reference-20260918/simplesamlphp-extension-points-corrected` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_816C536YJ0JK4DB1KCMG2QQNH5` | `build/acceptance/reference-20260918/single-signing-key/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_3FR2PVDMJW35XQGGGZSSG7RA9Q` | `build/acceptance/reference-20260930/publisher-ssp-v120/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_NQBNKXVWD27W94A9AGQHAP4B06` | `build/acceptance/reference-20260930/ssp-rsa-sha1-metadata-v151` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GMJJ74B3V9P264GE7CX8PTYAE3` | `build/acceptance/reference-20260918/simplesamlphp-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GMJJ74B3V9P264GE7CX8PTYAE3` | `build/acceptance/reference-20260918/simplesamlphp-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HWRD7P947XEAKED9VW9MS61BZ6` | `build/acceptance/reference-20261002/simplesamlphp-metadata-validity-r2/evaluation-v193` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z4F3PP7WE9PWP284YCG5YKWANF` | `build/acceptance/reference-20260930/ssp-native-mdq-fixtures-v1/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_08Q5460F7J5MFDXQQMT0CTGDRR` | `build/acceptance/reference-20260930/ssp-default-acs-v136/evaluation-v136` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_A1G3DYBWJDCSPBZW71DZ38R69Q` | `build/acceptance/reference-20260930/ssp-native-mdq-schema-valid-v1/evaluation-native-positive-v125` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_C13B6TD29Y7SKNF0MTVFGFQ6W1` | `build/acceptance/reference-20261001/ssp-mdiop-native-admission-v175-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KVHNHP2ZPE93WW6A154P3FH09S` | `build/acceptance/reference-20260918/simplesamlphp-md05c2-v105` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_MS5HDK610FJXD19ZR4C1YADKYW` | `build/acceptance/reference-20260918/simplesamlphp-md05d-v104` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JB9X92CZED5RV8H322VWSH1XGV` | `build/acceptance/reference-20260918/simplesamlphp-md05e-v106` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z15GR24Z1AWTH8DX9ZFZYPQSEK` | `build/acceptance/reference-20260930/ssp-intersection-capability-v165-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_VRZ5B5R8SE352EMPR4A785ZFAH` | `build/acceptance/reference-20261001/ssp-native-consent-logo-v176-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_7SZ5MMZBD5FE51KBAQP9RF772S` | `build/acceptance/reference-20261001/ssp-native-consent-uri-v181-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JSTA0B0DZX6T5ATW912F55395N` | `build/acceptance/reference-20260918/simplesamlphp-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4V2ENBJQ8C49GPVB7KJ2C28KHN` | `build/acceptance/reference-20261001/ssp-native-consent-safety-v177-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_7SZ5MMZBD5FE51KBAQP9RF772S` | `build/acceptance/reference-20261001/ssp-native-consent-uri-v181-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `build/acceptance/reference-20260914/additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_BZCE2YCRJ1J6B0S9D9KNA317F1` | `build/acceptance/reference-20261001/ssp-native-consent-ui-v172-r6/evaluation-v174` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_F6BGNRP76J1E734N9MRDC3YT2X` | `build/acceptance/reference-20260918/simplesamlphp-metadata-fixture-v67` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4FFJTY56TCQY9AKRA0BR0CC5K8` | `build/acceptance/reference-20261002/simplesamlphp-role-keys-r1/reader-v202/formal` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JKN1F8TWK7PN06HXRC848CKMGF` | `build/acceptance/reference-20261002/simplesamlphp-certificate-runtime-r2/evaluation-v200` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_PXSFEVJYKVT9QFN5AMDZB2V7J5` | `build/acceptance/reference-20260930/md06b-simplesamlphp-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4FFJTY56TCQY9AKRA0BR0CC5K8` | `build/acceptance/reference-20261002/simplesamlphp-self-contained-trust-r3/reader-v203/formal` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_QVPS2Y8MMRB22T1GW4YW5MN3K3` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_S9WN5SH11YRETN614ZTYYYA0PT` | `build/acceptance/reference-20260930/ssp-native-ec-v133/metadata_idp/evaluation-v133` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_YHD2ZJ212CAQJHBN4QVZ129E1G` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260918/simplesamlphp-md05f-v107` |
| metadata_idp | simplesamlphp | `run_YVZ8AB57K11T5XRZNEYVHMPQ1Z` | `interaction-followup/after/simplesamlphp/metadata_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_VDEDAMN49X5D6DJHF4GPJ1CA9M` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_9CQ4T26CJT03AJ9A3ZT7XDM6AW` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_BCJDFCFSWYMHVSESDMZCMBNAKA` | `build/acceptance/reference-20260918/keycloak-producer-algorithms-ecp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_NZGX1PXRJSNF8EHNXYM2ADPGDP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-ecp-v164` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_NZGX1PXRJSNF8EHNXYM2ADPGDP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-ecp-v164` |
| ecp_idp | keycloak | `run_H38KM96SRSD9ESW4B0JQ0RV5JC` | `keycloak/ecp_idp/run5` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_FSAM4VBZ8MDAFB8H24QMTWD1V9` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_5GA1YPD1SAMWK27ARM4B0AP9AS` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/ecp_idp/metadata/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_HM0CRTNVGD9Q1PT31P112N28AQ` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_E27G00G2FF6M2HGC2GT64CQ5KA` | `build/acceptance/reference-20260930/shibboleth-alg08-ecp-v162-relay-r2` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_E27G00G2FF6M2HGC2GT64CQ5KA` | `build/acceptance/reference-20260930/shibboleth-alg08-ecp-v162-relay-r2` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp | shibboleth | `run_4E2YMVJR6DPW196YFMWX4V9DN3` | `shibboleth/ecp_idp/run4` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_BJ2XCTNGK2RRGAAYGCQWQ1RVJT` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_J3V08TCY6KS3NN5CJWWSS7KN2C` | `build/acceptance/reference-20260930/ssp-native-ec-v133/ecp_idp/evaluation-v133` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_K5VQKQQHY8PMVF144RYVAYKP8G` | `build/acceptance/reference-20260929/simplesamlphp-ecp-shared-gcm128` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_VGZMD4XDTKT0T1M125F68HEBNW` | `build/acceptance/reference-20260929/simplesamlphp-ecp-shared-gcm256` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp | simplesamlphp | `run_KNM1G6JW0H7MYS6RT0FQX69EK5` | `simplesamlphp/ecp_idp/run6` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_QX707K2D5QHG7VR68206H0FB72` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W2DFV6VZDAB4S8GN6GAYNQ45MM` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_ZMKVMNSWGR5Y84J1MZ0M3CJTMK` | `build/acceptance/reference-20260930/keycloak-target-logout-absence-v158-r7/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_ZMKVMNSWGR5Y84J1MZ0M3CJTMK` | `build/acceptance/reference-20260930/keycloak-target-logout-absence-v158-r7/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_MZ1VKMF44GK8TD3H67V3D7YM5S` | `build/acceptance/reference-20261004/keycloak-slo-registered-signer-r5/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_Z8TR4WMEEQS682CHEM598836MT` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_18b` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp | keycloak | `run_J5SM20CM8MH8BG894VXA2N4BFM` | `keycloak/single_logout_idp/browser2` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_MCZRYHMCFBJ227206Y8YC3XCST` | `slo-encrypted-id-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_7NEJ4R0ZV980M9YJSQEXPADWKQ` | `slo-multiple-keys-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_T8A6A9QZFF5QVYTCK1AFQJZ4RZ` | `key-capability-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_PXFNTJDBJJR8GE88XWPKK0T0HC` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_target_logout` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_AFKPCME8CRTXMMGYVP46DNDQZN` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_VN2C6S628XPQS8B549608ZQY87` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/single_logout_idp/metadata/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_RJ0XT9P3SJ4FY20NSDDZB5DRD2` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_S9G7V5DDY23C9RPE3PWYNYKWD2` | `build/acceptance/reference-20260918/shibboleth-slo-webflow-v101` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_8N96KQNNSSG8NAK632QZRG5SCG` | `build/acceptance/reference-20261004/shibboleth-soap-slo-continuation-r5/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_67RM713GH15DD3S2X1VJ0GETZ3` | `build/acceptance/reference-20261001/shibboleth-native-slo-v178-r7/reader-v180/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_S9G7V5DDY23C9RPE3PWYNYKWD2` | `build/acceptance/reference-20260918/shibboleth-slo-webflow-v101` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_564R50AACKHVYJ2KT3THAE5WYP` | `build/acceptance/reference-20261004/shibboleth-slo-registered-signer-r2/evaluation-v224-r2` |
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
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp | shibboleth | `run_23TFJH7Y8APXAWCX58004A9FGG` | `shibboleth/single_logout_idp/browser5` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_19PV7S56N3H0DDENCD1K6GGK61` | `slo-multiple-keys-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_R3141MFT60HP3HFDQMXQ0K4P87` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_HTX2M5N1Y5AF3W2ZQZV9BX3467` | `build/acceptance/reference-20260930/ssp-native-ec-v133/single_logout_idp/evaluation-v133` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_AYKGN0WFF79RMY2SZQ0TTFRV2R` | `build/acceptance/reference-20260918/ssp-slo-propagation-v3` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_2671TXGC71MJ97JGK0AFJX3Y0D` | `build/acceptance/reference-20260930/ssp-slo-iframe-v131i` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_5WJCN84233GZCN0DGBFM67TEWQ` | `build/acceptance/reference-20261004/simplesamlphp-slo-registered-signer-r6/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KPBMMV9KFCC5438QRXT8MTZ2AA` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_18b` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_AYKGN0WFF79RMY2SZQ0TTFRV2R` | `build/acceptance/reference-20260918/ssp-slo-propagation-v3` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_1E0KV60F7802V0EECYD52V7V92` | `build/acceptance/reference-20261001/ssp-encrypted-logout-native-v186-r7/evaluation` |
| single_logout_idp | simplesamlphp | `run_DVCVA0CEB6PRZGXWWMV4AKMR1K` | `simplesamlphp/single_logout_idp/browser2` |
