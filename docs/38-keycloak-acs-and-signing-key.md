# Keycloak既定ACSの実証と署名鍵の一意性判定

## 台帳へ反映した結果

<!--g1-literal--> 未検証は489→485観測、異なるケースIDは161→159。追加はWarning3、Failed1、Success0。適合性の確定と、製品が成功した件数は区別する。

| ケース | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| IIP-MD05.ae：署名鍵の識別 | Warning（署名鍵が一意） | Warning（署名鍵が一意） | Warning（署名鍵が一意） |
| IIP-IDP12.c：既定ACSへの応答 | Failed（今回確認したネイティブ取込経路） | 既存結果を保持 | 既存結果を保持 |

## 署名鍵が一意である場合

承認済み定義は、候補鍵が単独なら識別の前提が自明に満たされると明記している。この分岐をTargetMetadataObservationへ追加し、既存のCONFIG実行経路に接続した。

単独EntityDescriptorの対象IdPロールにあるsigning／use省略のKeyDescriptorを検査する。証明書から取り出した公開鍵の値で重複を除く。encryption専用鍵は署名候補に加えない。署名鍵なし、複数の異なる鍵、未知の鍵表現、KeyValueとの併記、解析不能、対象ロール不在では既存の未検証経路を維持する。複数候補があるときの実署名と鍵の対応付けは今回の実装範囲外。

証拠の原本SHA-256・entityID・Run・結果を照合し、採用検証器ではJava側とは別にOpenSSLで証明書の公開鍵を抽出した。証明書名や証明書オブジェクトの等価性を一意性の根拠にしていない。

## Keycloakの差異を製品側と判定した根拠

元fixtureをKeycloak自身のImport clientへ投入し、製品が保存した設定を読み戻した後、Suiteの署名付きAuthnRequestからACS URL・index・ProtocolBindingをすべて省略して実行した。元fixtureのSHA-256、作成クライアント、要求ID、応答InResponseTo、実際の受信URLを対応付けた。

| 入力 | メタデータで選ばれるACS index | 実際の応答先index |
|---|---|---|
| 最初がisDefault=true | 0 | 0 |
| 次のACSがisDefault=true | 1 | 0 |
| すべて省略 | 0 | 0 |
| 最初がfalse、次が省略 | 1 | 0 |
| すべてfalse | 0 | 0 |
| 複数がtrue | 0 | 0 |

通常系対照は成功している。変更後fixtureの固有URLと署名鍵が実際に取り込まれ、正常な署名付き要求に応答していることを確認したため、未取込・古い設定・無応答・到達不能を違反と取り違えていない。既定indexを切り替えたときの誤応答が対象の違反であり、単なる署名失敗や設定失敗ではない。

さらに、稼働中のKeycloakから取得したkeycloak-servicesのEntityDescriptorDescriptionConverterを確認した。getServiceURLはACSのBindingが一致した最初のLocationを返し、isDefaultを参照しない。この選択が、取込後の `saml_assertion_consumer_url_post` と実応答に一致する。バイトコードだけをVerdictの根拠にせず、実測で確認した発生箇所の裏付けとして使用した。

<!--g1-literal--> 判定範囲はKeycloak 26.7.2、今回の管理コンソール経由のネイティブメタデータ取込と参照構成に限定する。他バージョン・手動設定・別取込方式へ一般化しない。IIP-MD05.avなど別の義務へ同じ結果を転記しない。

## 原本・操作記録

基点は `build/acceptance/reference-20260918/`。

| 試験 | Run | 証拠フォルダー |
|---|---|---|
| Keycloak既定ACS | run_ZZQH3B5136N955F9W1NAMJ4GSG | keycloak-default-acs |
| Keycloak署名鍵 | run_J5EY454Z5ZD3J7Q89SWCFNJNHD | single-signing-key/keycloak |
| Shibboleth署名鍵 | run_2893MAJ9X84M3TVFWRNY5CAPK4 | single-signing-key/shibboleth |
| SimpleSAMLphp署名鍵 | run_816C536YJ0JK4DB1KCMG2QQNH5 | single-signing-key/simplesamlphp |

Keycloakのfixture・UI成功・API読み戻し・削除確認・要求応答原本・ハッシュmanifest・稼働JARとクラスのハッシュを保存した。`audit_keycloak_default_acs.py` と `verify_single_signing_key_batch.py` を通過した対象結果のみ、生成器で比較表と台帳へ採用する。

<!--g1-literal--> 今回の操作はKeycloak取込7、設定書込14（クライアント作成7・削除7）、Run作成4、preflight4、Suite／転送コンテナ再作成各1、Docker build1。本人操作0、製品再起動0。作成したクライアントはすべて削除後の不存在をAPIで確認した。署名鍵の受動確認では製品設定を書き換えていない。

稼働Suiteは `samlscope:reference-single-key-v28`、digestは `sha256:1153608d19ca6901efaefd94f1fa6ce7d09ce860a3701a4c02b73d88a5750cae`。Runner全体の回帰検証は成功。G1生成一致・構造検証を実施し、G2の既存署名差分は未解消のまま扱う。
