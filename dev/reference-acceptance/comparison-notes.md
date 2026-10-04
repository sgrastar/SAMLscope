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
