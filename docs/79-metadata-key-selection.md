# メタデータの鍵選択・未掲載鍵の対照

## 実装状態

承認済み `IIP-MD07-b-idp-01` の条件を実行する入力を追加した。公開鍵 A/B を維持し、A の署名、B の署名、未掲載鍵 C の正しい署名を比較する。最後の条件は署名のビット破壊では代用しない。

- `MetadataService`: `multiple-signing-keys-unadvertised` を追加。メタデータには A/B のみを掲載し、要求は C で正しく署名する。メタデータ自体は A で署名する。
- polling 入力: signing / use省略 / three-key の各条件群内で基底鍵を固定し、選択する署名鍵のみを切り替える。群をまたぐ鍵は分離する。明示的な取込操作を行う比較用であり、鍵変更を更新検出の証拠にはしない。
- `MetadataServiceTest`: 各群の掲載鍵一致、メタデータ署名、C の要求署名の正常性、全掲載鍵による C の署名検証失敗を検査する回帰テストを追加。
- `MetadataKeySelectionComparison`: 元証拠を検証する内部アダプター用の比較処理。順序付き掲載鍵ハッシュ、署名鍵ハッシュ、同一 Run/entity、製品自身の取込、正常署名、壊れた署名の拒否対照、相関した製品判断、重複しない証拠参照を必須とする。
- B の拒否または C の受理を `violated` とする。A の正常系失敗、署名不成立、条件不足、掲載鍵変更、無応答・製品判断不明は `not_verified`。Verdict は返さない。
- 比較処理のテストに、先頭鍵しか試さない実装、未掲載鍵を受理する実装、別 Run、信頼鍵変更、掲載鍵を使った偽の対照、取込・署名・証拠不足を追加。
- Keycloak の native signature campaign に `--scenario metadata-key-signature`、下位 collector に `--matrix keys` を追加。既存の製品コンソール取込・署名イベント収集・削除復元経路を使用する。

## 共通観測を使う追加ケース

- `IIP-MD05-ad-idp-01`: signing 用と use 省略の各鍵で署名する条件を追加。Outcome のみを返し、SHOULD の集約は既存 Evaluator に委ねる。同じ取込・プロトコル証拠を MD07 と共有する。
- `IIP-MD07-a-idp-01`: single / pair / triple の各掲載鍵での署名を要求する。各群内で掲載鍵リストの順序と内容を固定し、署名鍵の位置を原本から確認する。
- `IIP-MD06-a7-idp-01`: KeyValue と X509Certificate を独立に検証する。KeyValue の Modulus / Exponent から公開鍵を再構成し、role 内に X509Data がないことを確認する。root 署名の証明書は同じ公開鍵であることを確認した検証用ラッパーであり、role が証明書形式だったとは扱わない。形式間では実効公開鍵を固定する。片方の正常系が成立し、もう片方が相関した native 署名拒否なら violated。両方拒否・無観測は対照不成立として not_verified。

`IIP-MD06-a8-idp-01` も同じ観測経路へ追加した。`certificate-runtime-same-key` はメタデータと異なる証明書を要求に含めるが公開鍵は同一。`certificate-runtime-other-key` はメタデータと Subject / Issuer の ASN.1 名を同一に保ちながら異なる公開鍵で正しく署名する。メタデータの鍵は条件間で固定する。reader は原本証明書の DER 相違・SubjectPublicKeyInfo 同値性・名前の同値性を確認する。同じ鍵の証明書を拒否する mutant を検出し、未掲載の別鍵を受理する対照不成立は approved treatment=control に従って not_verified とする。

各ケースに全必須条件の欠落、各署名鍵の拒否、署名鍵の使い回し、掲載鍵の切替、形式ごとの拒否を検出するテストを追加した。テストは下記のまとめた検証で実行した。

## 実機証拠との接続と残作業

`MetadataKeySelectionEvidenceFile` と CONFIG adapter を追加し、M2 registry に接続した。Run の固定メタデータ、収集完了、元 XML の SHA-256、メタデータ取得・準備・送信順、掲載鍵と署名鍵、署名と参照 digest、要求 ID / issuer / Destination / ACS、正常応答の製品署名、同期署名拒否イベント、復元済み取込記録を再照合する。受付後に receipt が変わっていないことも確認する。証拠未確認時は自動確定しない。

`export_metadata_key_receipt.py` は元 fixture と取込記録、保存済み XML、製品の HTTP / 監査記録、observer 復元を結び付け、判定を含まない receipt を作る。配置先は data directory の `metadata-key-evidence/<run>.json`。採用対象は元証拠・native receipt の結合を含む実機 replay と負の対照を実行済み。未確定ケースの完走は残る。未掲載鍵の判断は既存の証明書比較 reader と分離している。

`native_signature_campaign.py --scenario metadata-key-signature` は observer と realm の復元後に `prepare_metadata_key_evidence.py` を呼び出す。各プロファイルの Run 原本と固定 target metadata を capture し、receipt 作成結果・原本件数・不完全理由を `key-evidence-preparation.json` に保存する。既存 snapshot を上書きせず、収集状態を壊さない。runtime receipt 配置や verdict 採用は行わない。

`VerifyMetadataKeyEvidence.java` を追加した。既存原本を本番 reader / comparison へ渡して各ケースの判定を再計算し、target/run/hash/取込/署名設定/native event/HTTP/相関の変異を拒否すること、必要条件の欠落がその条件を持つケースを未検証にすることを検査する。製品結果を FAIL に固定して期待することはしない。この replay を実機収集後に実行し、検証済みケースのみを採用した。

ケースごとに必要な条件だけを reader に渡すようにした。例えば KeyValue の取込が未成立でも、原本と native 判断が揃った複数鍵ケースは独立して照合できる。exporter は条件別の不足を `conditionIssues` に保存し、他の検証可能な条件を保持する。Run / 固定 target / observer 復元 / 元証拠ハッシュの不一致は引き続き全体を拒否する。比較結果には `missing_variants` を含める。対象条件そのものの不足を無視したり、判定の分母から除外したりはしない。オフライン replay もケース単位の判定と変異対照を行い、不完全なケースを qualified_cases に含めない。

製品管理 API に証明書が一つしか見えないことだけでは、元メタデータの鍵選択に違反したと判定しない。取込元 XML の同一性を確認した上で B/C のプロトコル挙動を使用する。

入力と判定は `samlscope:reference-metadata-keys-v65` に反映済み。配布 JAR と稼働 JAR の SHA-256 一致を確認した。Keycloak の metadata_idp で一括収集・設定復元・原本 replay・正式再判定を完了した。SimpleSAMLphp も同じ native 判定経路へ接続し、`samlscope:reference-metadata-keys-v66` で正式再判定まで完了した。

## 検証と台帳

Java の本体・テストソースのコンパイルと Python 構文確認が成功。実装中は機能テストを保留し、下記の一括検証で実行した。G1 docgen 一致と構造検査に成功。G2 の既知の保護実装差分を解消したとの主張はしない。

<!--g1-literal--> 実装段階では件数を減らさず、428 観測 / 150 ケースID を維持した。実機採用後の差分は以下に記録する。

## 実機採用結果

<!--g1-literal--> 未検証は 428 → 426 観測、異なるケースIDは 150 → 149。Run は `run_DVZK14WN1W3E0SZ393MHQD42SJ`。

| Keycloak / metadata_idp | 正式判定 | 実証 |
|---|---|---|
| IIP-MD06-a8-idp-01 | Success | 異なる証明書・同じ公開鍵の署名要求を受理。同じ Subject / Issuer・異なる公開鍵の要求を同期署名イベント付きで拒否。 |
| IIP-MD07-a-idp-01 | Failed (Product) | 元メタデータを製品コンソールで取り込んだ後、pair の先頭と triple の先頭・中間の正しい署名を拒否し、末尾の鍵で受理。取込操作完了だけでは判定せず、正常対照と壊れた署名の拒否も確認。 |

<!--g1-literal--> まとめた検証は Java 32 テスト成功（SAML 20、比較 10、reader 境界 2）。既存 SIGNATURE_MODES_OPTIONAL の通常エンドポイントに対する古い期待値を修正した。失敗した試行も build 配下の checks-attempts.json に記録。実機原本の replay は確定した各ケースについて 18、合計 36 の不正証拠を拒否した。

採用は `verify_metadata_key_acceptance.py` が export 再生成一致・元証拠ハッシュ・復元記録・正式 outcome/verdict・証拠参照一致・再判定前後の transcript 不変を確認する。生成器経由で比較表と未検証台帳を更新した。G1 docgen 一致・構造検査成功。G2 は既知の G2-30 保護実装差分が残り、リリース準備完了ではない。

<!--g1-literal--> 操作は docker build 1、Suite/転送再作成 各1、製品再起動 2、observer 配置/削除 各1、realm 設定書込 2（復元込み）、コンソール取込/削除 各13、通常ログイン用クライアント作成/削除 各1、Run 作成 1、AuthnRequest 27、受信 SAML Response 12、metadata fetch 13、本人操作 0、コミット 0。全取込クライアント削除と realm/observer 復元を確認。

残る診断は MD05.ad の use 省略条件、MD06.a7 の KeyValue 条件、MD07.b の正常対照条件である。MD07.b では B が受理された一方、追加した A 正常対照が拒否されるため現実装は未検証を維持している。承認済み B/C 条件と正常対照の対応を再確認する必要がある。

## 残る条件の取込ポリシー診断

保存済みの fixture / receipt / 読み戻しを再照合した結果、KeyValue と use 省略では `AuthnRequestsSigned=true` の入力に対して製品の `saml.client.signature=false`、署名証明書属性なしが記録されていた。正負の両方に応答参照があるが、`diagnose_metadata_key_policy.py` 自体はその応答署名を検証しない。製品の適合判定には使わず、確認が止まる原因として記録する。

reader に固定トークン `native_signature_policy_disabled_after_import` と対象 variant の診断を追加した。比較結果にも各条件の native decision を出す。これら診断追加は v65 の後の未配備差分であり、台帳採用に使った判定を変更していない。MD07.b の A 対照を外して件数を減らす変更は行わず、承認済み B/C 条件だけで既知の鍵網羅問題を隠さないよう設計確認を継続する。

## SimpleSAMLphp への収集経路接続

条件リストを `metadata_key_matrix.py` に共通化し、Keycloak collector / receipt exporter / SimpleSAMLphp collector から使用する。比較条件の重複・Suite enum 登録・preloaded 登録を source と照合済み。通常 polling の control は preloaded 一覧に含めない。

`dev/simplesamlphp/metadata_key_campaign.py` を追加した。既存 EC collector の native parser / 設定読み戻し / request-bound HTTP 観測 / 設定復元を使用する。パーサー拒否や署名ポリシー不成立の場合はその入力の後続送信を行わず、前条件の設定で結果を作らない。外部の設定変更や読み戻し不一致はこの回復分岐で捕捉せず停止する。

Run `run_JBGGPXXP5664SYBAP858P9FMKD` の metadata_idp で収集完了。元設定と復元後設定の SHA-256 は一致し、公開 XML と固定 target metadata を取り出し済み。複数鍵の各鍵・use 省略では相関した正常応答を記録した。KeyValue-only は正の対照も負の対照も `UNHANDLEDEXCEPTION` の 500 となり、`native_signature_rejection` が付かないため署名値検証の証拠にならない。

`export_ssp_metadata_key_receipt.py` を追加し、native parser 出力・設定読み戻し・request-bound HTTP 観測・復元記録を判定を含まない receipt に結合した。`MetadataKeySelectionEvidenceFile` は `simplesamlphp-native-http` adapter を読み、要求 ID・URL・送信 digest・応答 status・本文 digest・観測時刻を照合する。拒否は一般的な 500 ではなく `native_signature_rejection=signature-value-invalid` を要求し、正の対照は相関した署名済み応答を要求する。製品パーサー出力と Suite の元 XML の対応は原本ハッシュで確認する。

Run `run_JBGGPXXP5664SYBAP858P9FMKD` の原本で offline replay を実行し、v66 の reader / comparison が a8・07-b・05-ad・07-a を確定、a7 を未検証のまま保持、72 の不正証拠変異を拒否することを確認した。

<!--g1-literal--> このバッチは 13 条件＋通常ログイン基準、設定書込 15（適用14・復元1）、Run 1、AuthnRequest 27、SAML Response 11、metadata fetch 13、製品再起動 0、本人操作 0。この時点では未検証 426 観測を維持。ソースの機能テストは再実行せず、Python 構文・登録監査・実収集・復元確認を実施した。

## SimpleSAMLphp の採用結果

`metadata-keys-runtime-v66`（`samlscope:reference-metadata-keys-v66`、digest `sha256:9de93eec1683349da265c921404581e6c99abe5a0eaebdf6e43163c8897a579b`）を作成し、`samlscope:reference-metadata-keys-v65` から参照 Suite と転送コンテナを再作成した。配布 JAR と稼働 JAR の SHA-256 は一致。receipt を `/data/metadata-key-evidence/run_JBGGPXXP5664SYBAP858P9FMKD.json` に配置し、read-back SHA-256 `59e9d8b1352ffcd0148bddf794bf8051f2f2d1ecc3374818b84ff9b5a8be34de` を確認した。

既存 Run の protocol-evidence を再評価し、正式 result.json は `IIP-MD06-a8-idp-01`・`IIP-MD07-b-idp-01` を Success（`metadata.keys.selection-observed`）へ更新した。`IIP-MD06-a7-idp-01` は NOT_VERIFIED のまま、`IIP-MD05-ad-idp-01`・`IIP-MD07-a-idp-01` は既存 Success のまま変更なし。再判定前後の transcript は同一（64 entry）で、Run の証拠を書き換えていない。

a7 が確定しない理由: KeyValue-only 条件では正負の対照がともに `UNHANDLEDEXCEPTION` の 500 で、`native_signature_rejection` が付かない。製品の署名値検証の証拠にならないため、承認済みの「両方拒否・無観測は対照不成立として not_verified」に従い未検証を維持する。条件を緩めて成功扱いにはしていない。

`verify_metadata_key_acceptance.py` は製品別に、export 再生成一致、原本 manifest ハッシュ、receipt 配置 read-back、復元（書込15・適用14・復元1、original/final SHA-256 一致）、操作回数（製品再起動0・本人操作0）、正式 outcome/verdict/reason、証拠参照一致、変異対照 18×確定ケース、再判定前後の transcript 不変を確認する。生成器はこの検証を通ったケースだけを台帳と比較表へ反映する。

<!--g1-literal--> 台帳は 426 → 424 観測。ケースIDは 149 のまま（a8 は Shibboleth、07-b は Keycloak と Shibboleth が未検証のため）。確定は 168 → 170。既に解決済みの 05-ad と 07-a は重複計上していない。

<!--g1-literal--> この採用バッチの操作は docker daemon 起動 1、docker build 1、Suite / 転送コンテナ再作成 各1、receipt 配置 1、protocol-evidence GET 3、evaluate POST 1、製品設定書込 0、製品再起動 0、プロトコル送信 0、本人操作 0、Run 作成 0、コミット 0。G1 docgen 一致・構造検査成功。G2 は既知の G2-30 保護実装差分が残り、リリース準備完了ではない。

## Shibboleth のネイティブ取込経路と採用結果

参照環境の Shibboleth IdP コンテナが残っていなかったため、既存の配布物（`shibboleth-identity-provider-5.2.3`）から `/opt/reference-idp` を再インストールし、`reference.properties` 相当（entityID `http://localhost:18280/idp/shibboleth`、scope `reference.invalid`、Password フロー、in-memory セッション、cookie secure）と HTPasswd 実証ユーザー、Chaining metadata provider（`suite.xml` / `preloaded.xml`）を適用した。インストーラ生成メタデータのエンドポイントが `https://localhost/...` になっていたため、公開値のみ `http://localhost:18280/...` へ修正した。Tomcat 起動設定に `-Didp.home=/opt/reference-idp` を保存し、コンテナ再起動後の復帰を確認した。復旧内容は `samlscope-reference-shibboleth-v67/environment.json` に記録した。

`signature_audit_campaign.py` に `--scenario metadata-key-signature` を追加し、監査フォーマットを一時的に `SAMLscope-signature-v1` へ切り替えて、`import_metadata_batch.py`（FilesystemMetadataProvider + Suite polling campaign）を `--continue-inconclusive` で実行した。条件群は共通の `KEY_CAMPAIGN` 13 件で、各条件につき Suite 発行の不正署名対照と正常署名要求の 2 要求を送り、要求 ID に結合した監査行 26 件を収集した。拒否が期待される `certificate-runtime-other-key` と `multiple-signing-keys-unadvertised` は正常要求が拒否されて `incomplete` のまま継続し、無応答を成功扱いしていない。

`export_shibboleth_metadata_key_receipt.py` を追加し、元XML・固定 target metadata・provider 取込記録・要求/応答・監査行・監査設定の original/configured/final・provider 復元を判定なしの receipt（`evidenceAdapter: shibboleth-audit`）へ結合した。reader は Shibboleth adapter に対し、監査フォーマット一致、監査設定が original から変更され final で復元されていること、要求 ID・SP entity・`POST`・browser profile・観測時刻の一致、拒否は `MessageAuthenticationError` かつ status 空、成功は event 空かつ `Success` を要求する。正常応答がある場合のみ応答参照と署名済み Success を要求する。

`metadata-keys-runtime-v67`（`samlscope:reference-metadata-keys-v67`、digest `sha256:c854d9a027fb3bcd8bb185218ce7ebf765b8bde5b952f2108d35b3b45d104f5c`）を作成し、配布 JAR と稼働 JAR の SHA-256 一致を確認した。Run `run_P3V3M5S01NCK0A8AX4DVR9V33M` の protocol-evidence を再評価し、正式 result.json は `IIP-MD06-a8-idp-01`・`IIP-MD07-b-idp-01` を Success（`metadata.keys.selection-observed`）へ更新した。同じ Run で `IIP-MD06-a7-idp-01` も Success だが、これは既に別 Run で採用済みのため重複計上しない。`IIP-MD05-ad-idp-01`・`IIP-MD07-a-idp-01` は既存 Success のまま変更なし。再判定前後の transcript は同一（63 entry）である。

offline replay は確定 5 ケースについて 18 の不正証拠変異（計 90）を拒否し、`verify_metadata_key_acceptance.py` は Shibboleth について export 再生成一致、原本 manifest、receipt read-back、監査/provider 両復元の original/final 一致、操作回数（製品再起動 2・本人操作 0）、正式 outcome/verdict/reason、証拠参照一致、変異対照、transcript 不変を確認する。Keycloak・SimpleSAMLphp の既存判定も再検証して回帰がないことを確認した。

<!--g1-literal--> 台帳は 424 → 422 観測、ケースIDは 149 → 148。a8 は全製品で確定し、07-b は Keycloak の未検証が残る。確定は 170 → 172。

<!--g1-literal--> このバッチの操作は docker build 1、Suite / 転送コンテナ再作成 各1、IdP 再インストール 1、製品再起動 2、監査設定書込 2（復元込み）、provider 設定書込 15（適用14・復元1）、Run 作成 1、AuthnRequest 26、監査行 26、metadata fetch 13、本人操作 0、コミット 0。監査/provider の復元と read-back を確認した。G1 docgen 一致・構造検査 46/46 成功。G2 は 20/21 で、既知の G2-30 保護実装差分が残るため、この実装差分を含むリリースには G2 の再承認が必要であり、リリース準備完了ではない。

残る診断は Keycloak MD07.b の正常対照条件、SimpleSAMLphp MD06.a7 の KeyValue 条件、Keycloak MD05.ad の use 省略条件である。Shibboleth の他 metadata ケースは、同じ filesystem provider 経路で条件群を広げられるが、承認済み条件・対照に対応する採用検証をケース群ごとに用意する必要がある。

## Shibboleth metadata 条件の追加診断（採用は保留）

同じ filesystem provider 経路で、署名検証に関わる条件（`signed-other-key-primary-keyinfo`、`xpath-identity`、`xpath-exclude-role-descriptors`、`xpath-exclude-endpoints`、`xpath-exclude-key-descriptors`、`no-key-info`）を Run `run_C7PTS9X96YKVNDKCC1MJ918579` で収集した。Run 自体は `IIP-MD03-b-idp-01` PASS、`IIP-MD05-am-idp-01` WARNING、`IIP-MD05-an-idp-01` FAIL、`IIP-MD05-ao-idp-01` PASS を出したが、いずれも台帳へ採用していない。

理由を確定するため、`unsigned`・`bad-signature`・`signed-other-key` を追加収集し、`signed-other-key-primary-keyinfo` の署名を埋め込み証明書すべてで検証した（`diagnosis.json`）。参照 IdP の `conf` には `SignatureValidation` フィルタが存在せず、メタデータ文書署名は検証されていない。`signed-other-key-primary-keyinfo` は埋め込み証明書のどれでも署名が成立しないにもかかわらず受理・使用されており、これは「metadata に埋め込まれた証明書ではなく別途設定した鍵で検証した」ことの証拠にならない。`unsigned` が受理・使用され、`IIP-MD03-a-idp-01` が Run 上 FAIL になるのも同じ前提不足による。

したがって MD03.b・MD05.am・MD05.an・MD05.ao は未検証を維持する。無応答や一般的な HTTP エラーではなく、署名検証が構成されていない状態の受理・使用を製品 FAIL や PASS に変換していない。次の解消経路は、Suite のメタデータ署名鍵を out-of-band のトラストアンカーとして参照 IdP に構成し（`SignatureValidation` メタデータフィルタ等）、同じ取込経路と Suite 発行の不正署名対照で transform / KeyInfo 条件を再実行することである。この構成と採用検証は未実装であり、ケース群をまとめて接続する必要がある。

## Runner 側の受領証 reader（originals 必須）

`MetadataSignatureVerificationEvidenceFile` は受領証の文字列を信用せず、参照された原本を Runner が読んで検証する。受領証の `configurationReadBack`・`restorationReadBack`・各負の対照の `rejectionReference` は `tx_` transcript entry を指し、Runner は `content.readDecodedSaml` で実バイトを読み、宣言 SHA-256 を照合したうえで意味内容を検査する。結合する対象は Run・`campaignId`・`targetEntityId`（対象 metadata の entityID に一致）・fixture 原本・要求/応答・設定変更/復元である。設定読み戻しは製品が out-of-band アンカーを読んだ証跡（アンカー証明書 bytes の fingerprint）と fixture 埋込 KeyInfo 証明書の不一致を、復元読み戻しは変更前後の設定バイト一致を、負の対照は対象要求に相関した製品自身の拒否 Response（top-level Requester/Responder）を要求する。したがって `restored:true`、`source` 名、日時文字列、裸のハッシュだけでは成立しない。MD05.am/an の native 拒否 receipt 経路も同じ前提で gate する。

上記は v3 reader 完成時点の境界である。その時点では製品側 originals を記録する adapter が未実装だったため、実 Run は fail-closed で未検証を維持した。現在の SimpleSAMLphp 経路は、下記の v4 native adapter と採用検証まで接続済みである。他の adapter や前提証拠の不足を、この採用だけで解消した扱いにはしない。承認済みの configuration failure semantics（`normative_capability` 欠如の VIOLATED 等）は再 gate しない。

## SimpleSAMLphp の署名・XPath・KeyInfo 原本による採用

Run `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` の証拠は `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/` に保存した。製品自身の `MDQ::getMetaData` と `SAMLParser::validateSignature` を使用し、実設定・有効設定・out-of-band アンカー・検証器ソース・署名検証結果を原本として記録する。v4 reader はこれらを実バイトから検査し、正常署名、壊れた署名、埋込鍵だけを信頼する対照、設定復元を結合する。一般的な HTTP エラーや単なる CLI パーサ受理では確定しない。

| SimpleSAMLphp / metadata_idp | 正式判定 | 実証 |
|---|---|---|
| IIP-MD03-a-idp-01 | Success | 正常文書の検証・使用と、未署名・不正署名・別鍵署名の native 拒否を確認。 |
| IIP-MD05-am-idp-01 | Warning | 内容を除外しない XPath transform を安全に受理した情報記録。 |
| IIP-MD05-an-idp-01 | Failed (Product) | RoleDescriptor・endpoint・KeyDescriptor をそれぞれ署名対象から除外した文書の署名を native 検証器が受理し、除外された設定を相関 SSO で使用した。 |
| IIP-MD05-ao-idp-01 | Success | KeyInfo を省略した署名を out-of-band アンカーで検証・使用した。 |

XPath fixture の接頭辞は `ds:XPath` 自身で宣言する `mdx` に修正した。製品の検証器が Signature を切り離して検査する経路でも namespace が保持されることを、シリアライズ後の署名と native 検証で確認した。修正前の未束縛接頭辞による PHP エラーは、製品の適合判定に採用していない。

`verify_ssp_metadata_signature_consumer_acceptance.py` は保存した production Runner JAR で署名 gate・native 拒否 reader・各ケースを再実行し、正式 result と原本・証拠参照を照合する。共通受領証は各ケースの必須条件を満たす superset として使用し、他の必須条件の欠落は未検証にする。再評価前後の transcript は不変で、製品設定の変更前・復元後の SHA-256 は一致した。

<!--g1-literal--> 完了した campaign-r3 の操作は、製品設定適用 15・復元 1、native 署名検証 15、SSO 往復 11、製品再起動 0、本人操作 0。失敗・中断した先行試行の記録は別途保存し、この成功試行の操作数に混ぜて省略しない。署名 gate の不正証拠 29、native 拒否の不正証拠 27、ケース経路の不正証拠 9 を拒否した。台帳への採用は生成器経由で行った。

## Keycloak の統一した署名検証ポリシーでの再測定

Run `run_35NM1CKB4HMDVRG01X6NSXVQN7` の原本は `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/` に保存した。元のメタデータ XML を製品コンソールで取り込み、製品の署名検証フラグだけを有効にして全条件を同じポリシーで実行した。取り込んだ鍵は追加・置換していない。正常な X509 条件の Success と、KeyValue 条件等の要求に結合した native `invalid_signature` 拒否を比較する。ポリシーが条件間で異なっていた先行試行は採用しない。

| Keycloak / metadata_idp | 正式判定 | 実証 |
|---|---|---|
| IIP-MD05-ad-idp-01 | Warning (Product) | `use` を省略した複数鍵条件で、正常対照を通る署名検証ポリシーの下でも有効署名を拒否。 |
| IIP-MD05-cd-idp-01 | Failed (Product) | X509Certificate 形式は受理し、同じ公開鍵の KeyValue 形式を native 署名検証で拒否。 |
| IIP-MD06-a5-idp-01 | Failed (Product) | 同じ鍵を異なる証明書で示す条件と KeyValue 条件を通じた鍵同一性の義務を満たさない。 |
| IIP-MD06-a7-idp-01 | Failed (Product) | KeyValue-only の有効署名を拒否し、両形式を独立に扱う義務を満たさない。 |
| IIP-MD06-a3-idp-01 | Warning | 完全な native 設定出力・起動設定・対象メタデータ・実際の通信から、今回の役割では TLS が使われていないことを確認した情報記録。 |

`verify_keycloak_native_key_policy_acceptance.py` は配置済み production Runner と検査 helper を保存し、その原本で再実行して正式判定と照合する。HTTP 構成は受領証中の空のリストから推測せず、秘密値を除いた完全な `kc.sh show-config` 出力とコンテナ起動設定から検査する。再判定前後の transcript は不変で、全取込クライアントの削除・observer の撤去・realm 設定の復元を読み戻した。

<!--g1-literal--> 不正証拠の変異対照 121 件を拒否した。失敗した先行試行を含む操作は、製品再起動 6、取込保存 26、署名ポリシー書込 16、取込クライアント削除 26、イベント設定書込 6、本人操作 0。詳細は `campaign-operation-counts.json` の試行別記録を参照する。

MD07.b は先頭鍵の正常対照を満たしていないため、引き続き未検証とする。別用途の active ENC 鍵が管理 API に見えることだけで、SAML 役割の公開鍵が欠落しているとは判定しない。今回の HTTP 構成の結果も、TLS を使う構成の検証には転用しない。

## SimpleSAMLphp の KeyValue 実行時反例

Run `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` は元 XML を製品自身のパーサへ渡し、生成した設定を適用して読み戻した。`validate.authnrequest` を同一の有効設定に保ち、同じ公開鍵を含む別証明書で正常署名を受理し、不正署名を拒否する対照を実行した。その設定のまま KeyValue-only 文書を適用すると、ネイティブ設定から鍵が消え、有効署名の要求を証明書不足として処理できなかった。

HTTP エラーだけでは結論にしない。実際の POST バイトと Suite の要求原本、直接の要求・応答の組、対象 entity、製品の設定と実行ソース、正常・不正署名対照を合わせて検査する。この反例から `IIP-MD05-cd-idp-01`・`IIP-MD06-a5-idp-01`・`IIP-MD06-a7-idp-01` を正式 Failed とした。メタデータ全般の受理を扱う `IIP-MD05-c-idp-01` へは反例を流用しない。

`verify_ssp_keyvalue_runtime_acceptance.py` は採用時の稼働 JAR と原本を使って再実行し、正式結果・証拠参照・復元を照合する。再判定前後の transcript は不変。原本は `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/` に保存している。

<!--g1-literal--> 失敗・再試行を含む全バッチは設定書込 18（適用15・復元3）、パーサ実行20（独立再生成5を含む）、プロトコル試行30、Run3、製品再起動0、本人操作0。不正証拠の対照は各ケース21、計63で未検証を維持した。

## Shibboleth の RSA-SHA1 能力原本

Run `run_M53G1T57ZXF9Q0P2GEDHWPN0EA` では、製品内の OpenSAML 署名生成器と `SignatureValidationFilter` を、実際に配置されたライブラリと資格情報で実行した。秘密鍵は製品コンテナ内に留め、公開メタデータの署名原本と、内容改変・未署名・別信頼鍵の対照を保存した。内容改変は署名値を保持したまま entityID のみを変更する。独立した XML 署名検証でも正常署名の成立と内容改変時の不成立を確認し、生成能力と検証能力を要求する `IIP-MD05-ah-idp-01` を正式 Success とした。既定設定で RSA-SHA1 を許可しているという結論には使わない。

原本は `build/acceptance/reference-20261001/shibboleth-rsa-sha1-metadata-v171-r5/`、採用検証は `verify_shibboleth_rsa_sha1_metadata_acceptance.py`。以前の試行で署名値まで消えていた内容改変対照は採用していない。その保存済み結果を上書きせず、採用取消記録と修正後の別 Run を保持した。

<!--g1-literal--> 採用試行のネイティブ実行2、コンパイル1、Run1、preflight1、製品設定書込0、製品再起動0、本人操作0。正常ログイン基準の一時設定は別記録で書込3・再読込2・通常ログイン1、原本とのバイト一致による復元済み。正式判定時の追加プロトコル送信0。不正証拠対照22を拒否した。

## メタデータ全条件の再試験

古い Shibboleth `IIP-MD05-c-idp-01` の採用は、混在 KeyValue/X509Certificate、任意証明書フィールド、用途省略・複数暗号鍵などの必須条件が揃っていなかったため取り消した。保存済み結果は履歴として保持し、台帳を生成し直して未検証へ戻す。新しい全条件試験で `multiple-encryption-keys` の要求に暗号化専用鍵を使って署名していた Suite の不整合も確認した。メタデータの内容を変えず、要求署名用の鍵と復号用の鍵を分けて修正し、製品判定には修正後の再測定を要求する。

Keycloak の Run `run_5PS5A09N019JCV0BT8DQRMNZNN` は、全必須条件の元 XML を製品自身の変換・コンソール取込経路へ渡し、保存と読み戻し、各一時クライアントの削除まで確認した。これは `IIP-MD05-c-idp-01` の表現受理の証拠であり、実行時の鍵解釈・署名検証を扱う別義務へ流用しない。設定前後のクライアント一覧と実行ポリシー原本を、試験時の順序で transcript に記録している。稼働時の Runner 原本による再実行と、正式結果・証拠参照の照合を経て Success を採用する。

<!--g1-literal--> 最終試行の一時クライアント作成19・削除19で製品設定操作38。先行試行を含めると作成49・削除49・既存ポリシー書込4で計102。製品再起動0・本人操作0。既存属性への書込0という記録を、クライアント作成・削除を含む設定操作0と読み替えない。不正証拠対照28を拒否した。

Shibboleth の新しい Run `run_J7GJGATXAXDTV916CXJN8RRK5Z` は、全必須条件のメタデータを製品の `FilesystemMetadataProvider` へ渡し、適用された SP 設定と正常署名・不正署名の実際の処理を確認した。正式評価の原本を保持したまま、Run 所有者と重複記録のガードを加えた稼働版でも判定・証拠・詳細が完全一致することを再実行で確認した。これにより `IIP-MD05-c-idp-01` の表現受理を再採用できる。部分試験の過去の採用をそのまま復活させたものではない。

<!--g1-literal--> MD05.c の診断試行と採用試行はそれぞれ設定書込21・再読込20・プロトコル送信38・再起動0・本人操作0。厳格化後の再評価は製品操作0。全19条件、欠落・別Run・重複を含む負対照21を検証した。

Shibboleth の `IIP-MD05-cd-idp-01` は、新規 Run の X509Certificate と KeyValue-only 原本を同じ条件で適用し、正常署名の受理と不正署名の拒否を確認して Success とした。他の鍵選択条件をこの試行の結果から推測せず、対象ケースだけ採用する。原本は `build/acceptance/reference-20260930/shibboleth-hintfree-keys-v172-r2/` に保存した。

<!--g1-literal--> MD05.cd の設定書込7・再読込4・製品再起動2・プロトコル送信6・本人操作0。不正証拠対照18を検証し、監査設定とメタデータ設定を原本とのバイト一致で復元した。旧Runの期限切れ再利用失敗は非採用の記録として保持している。

## ネイティブ表示と既存プロトコル記録の再評価

SimpleSAMLphp の Run `run_BZCE2YCRJ1J6B0S9D9KNA317F1` は、製品の標準 consent 経路を実際の Chromium で読み、同じ認証要求・ネイティブ状態・適用されたメタデータに表示を結合した。DisplayName、ServiceName、entityID の優先順位を、候補だけ変えた一連の試行で確認し、`IIP-MD05-fj-idp-01` を Success とした。テンプレートは変更していない。Logo や URI の部分試験はこの確定に含めない。

外側の機能非使用ラッパーが、表示判定器の記録再評価を転送していなかった不整合も修正した。送信を行わない queued oracle を明示的に接続し、未完了の履歴、既確定、追加証拠なしは昇格させない。失敗した先行版の正式評価・稼働 JAR と、修正後の評価を別に保持する。`verify_ssp_consent_ui_acceptance.py` は両者を区別し、修正後の実際のラッパー・判定器で再実行してから採用する。

<!--g1-literal--> 全6試行で設定書込41（適用26・復元15）、ネイティブパーサ21（独立再生成4を含む）、プロトコル試行32、Run5、Chrome試行6（成功4）、製品再起動0・本人操作0。不正証拠16と構造正規化の対照2を確認し、正式再評価前後のtranscript20件は不変だった。

`IIP-SSO03-b-idp-01` の承認済み IdP 条件にない「複数種類のエラーが必要」という Suite 独自の条件を撤去した。正常な POST Success の対照と、相関した充足不能要求への POST エラーを要求し、GET エラーの変異で違反を検出する。Keycloak と SimpleSAMLphp は保存済みの署名付き応答原本で正式 Success になった。期限切れの待機結果も、このケースだけ原本から再評価できるようにし、開始時刻・期限・保存された原本は変更していない。別 Run と重複記録は観測前に拒否する。

<!--g1-literal--> 両製品で正常応答1と相関したPOSTエラー5を検証。今回の製品設定変更・再起動・送信・Run作成・本人操作はすべて0。正常系、GET変異、正常系不足、エラー不足、無相関、Status不足を稼働JARから再実行した。別Run・重複のガードは、原本を読まないことも直接検証している。

## SimpleSAMLphp の PDP パーサ前提の切り分け

`IIP-EXT01-c-idp-01` の `foreign-attribute-authz` は、拡張属性の処理だけを原因にした失敗として採用できない。配置された `PDPDescriptor` のコンストラクタは、`getAuthzService() !== []` の場合に「AuthzService が必要」という例外を送出していた。同じ履歴のメタデータから署名を外したパーサ専用対照で、foreign 属性がある場合とない場合の両方がこの例外になり、PDP 役割を外した対照は正常にパースされた。

これは属性を追加する前の正常前提が成立しない診断であり、EXT01.c の Failed や Success には変更しない。製品のソースや設定を修正せず、署名付き履歴原本と、変更点を明示した署名なしのパーサ対照を別に保存した。原本は `build/acceptance/reference-20261001/ssp-pdp-parser-precondition-v175/`、再現スクリプトは `dev/simplesamlphp/pdp_parser_precondition_audit.py` にある。

<!--g1-literal--> 4プロファイルで各3対照、nativeパーサ実行12。設定書込・製品再起動・SAML送信・本人操作はいずれも0で、実行前後の設定SHA-256とコンテナ状態は一致した。最初の起動はPythonモジュール名の衝突で製品操作前に停止し、その試行も記録した。

## SimpleSAMLphp の全表現のネイティブ受理

Run `run_C13B6TD29Y7SKNF0MTVFGFQ6W1` は、Suite の原本 XML を製品自身のメタデータパーサへ渡し、生成された PHP 設定の適用と読み戻しまで確認した。正常な署名付き SSO と署名を壊した要求へのネイティブ拒否を対照とし、元の設定はバイト一致で復元した。配置された Runner の再実行、正式な評価結果、証拠参照を独立検証し、`IIP-MD05-c-idp-01` を Success として採用する。表現の受理を扱う証拠であり、すべての鍵形式が実行時に使えるという結論へは流用しない。

<!--g1-literal--> 全19条件を受理し、正常前提を欠くパーサ対照2件を拒否した。パーサ実行21、設定書込20（適用19・復元1）、プロトコル試行2、Run作成1、Recorder原本書込24、製品再起動0・本人操作0。独立再生成のパーサ実行21を別に記録し、稼働Runnerの不正証拠対照34はすべて未検証だった。

原本は `build/acceptance/reference-20261001/ssp-mdiop-native-admission-v175-r1/`、採用検証は `dev/reference-acceptance/verify_ssp_mdiop_admission_acceptance.py` に保存した。署名・設定・復元の原本を変更せず、未使用のブラウザ補助資料に残る状態トークンだけを除去した。既採用の consent 表示と KeyValue 試験についても同じ除去を行い、稼働版の再実行で判定・詳細・正式結果・transcript が不変であることを確認した。旧本文を複製せず、除去前のハッシュと処理履歴だけを残す。

## Shibboleth のネイティブ UI のまとめ測定

Run `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` は、標準 Password 画面で適用された SP メタデータ、署名付きの新しい要求、実際のブラウザ画面、ネイティブ getter とテンプレートを対応付けて観測した。Discovery UI を使わない経路と、InformationURL・PrivacyStatementURL を描画しない経路は、DOM にないという理由だけで確定せず、実際の設定・読み戻し・処理ソースで確認した。

Logo は許可された URL の実ロードまたは実際の画像要求を確認し、SVG を画像として使った画面で試験用スクリプトが実行されなかったことを記録した。同じ画面の Logo 位置を実行可能な要素へ置き換えた隔離対照で、観測器が実行を検出することも確認した。隔離対照での実行を製品の違反とは扱わない。DisplayName と ServiceName は実際に表示されたが、両方がない条件ではネイティブ getter の hostname fallback がテンプレートの既知の分岐で抑止された。この反例は `IIP-MD05-fj-idp-01` の violated であり、承認済み SHOULD を使う中央 Evaluator の結果は Warning になる。

<!--g1-literal--> 全23 fixtureと、HTTPS画像の1条件だけの追加試行を実測した。失敗した先行2試行を含め設定書込36・再読込32・SAML要求30・製品再起動0・本人操作0。全設定をバイト一致で復元した。不十分な原本の対照23はNOT_VERIFIED、正しく相関した試験スクリプトの実行はVIOLATEDとなり、正式な4ケースは中央EvaluatorでWarningになった。

原本は `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/` に保存した。`verify_shibboleth_native_ui_acceptance.py` は保存済み結果だけを信用せず、配備された Runner 原本を再実行してから正式結果と照合する。再実行 helper の同義 JSON への再出力によって原本ハッシュが変わった先行試行は採用せず、原本バイトを保つ helper の結果を用いる。

## Keycloak の受理メタデータと追加 ACS の実挙動

Run `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` は、元のメタデータを製品自身の converter へ渡し、その出力を属性補正せずに同じクライアントへ適用した。更新後の正常な署名付き要求は既定 ACS で成功した一方、同じ受理メタデータに記載された追加 POST ACS への正当な要求は、ネイティブの Invalid redirect uri で拒否された。converter と設定読み戻しで追加 URI の欠落を確認し、実際の要求・拒否・署名対照・設定復元を併せて `IIP-MD06-a-idp-01` の製品側 Failed として採用する。部分的な更新の成功だけでは `IIP-MD06-ab-idp-01` を確定しない。

<!--g1-literal--> 採用Runは設定操作5・SAML要求15・Run作成1、先行2試行を含む合計は設定操作15・SAML要求45・Run作成3。製品再起動0・本人操作0で、全試行の設定復元を確認した。配備Runnerの実反例1と不正原本17の対照を再実行し、正式再評価前後のtranscript75件は不変だった。

先行 Run の不明配送が残るケースを製品違反へ変更しようとした際、中央の配送ガードが正式報告を拒否した。その診断と保存された CaseOutcome は履歴として保持し、未知配送を推定で既知配送へ書き換えていない。採用Runでは対象ケース自身の outbox action を実測して既知配送にする既存経路を用い、ガードを維持したまま正式評価を完了した。原本は `build/acceptance/reference-20261001/keycloak-native-supersession-v177-r3/`、採用検証は `verify_keycloak_metadata_supersession_acceptance.py` に保存した。

## SimpleSAMLphp のネイティブ consent のロゴ・安全性

`IIP-MD05-f9-idp-01` は、メタデータを製品自身のパーサへ渡したうえで、実際の consent と noconsent の処理ソース・テーマ・設定読み戻し・ブラウザ画面を照合した。この経路は SP メタデータの候補 Logo を選択せず、製品自身の静的 Logo を描画する閉じた処理だった。承認済みの非表示注記条件を適用し、中央 Evaluator の Warning として採用する。Suite の証明書が Run ごとに異なる正常試験を比較できなかった旧診断は保持し、各試行の鍵と署名を実バイトで検査した後に限って証明書内容の差を除外する比較へ修正した。その他の属性・端点・表示文字列・Logo 条件の差は除外しない。

`IIP-MD05-fg-idp-01` は、InformationURL と PrivacyStatementURL の javascript 条件を実際のネイティブ consent 画面でクリックし、製品が発行した CSP とブラウザの遮断記録を対応付けた。Logo の data 条件は同じ非使用の処理で確認した。画面の同じリンク位置を試験用の実行可能な要素にした隔離対照では観測器が実行を検出し、その隔離対照を製品違反へは流用しない。実機の保護を注記付きで確認した中央 Evaluator の Warning として採用する。

<!--g1-literal--> 稼働版 v178 の原本で f9 の不正証拠対照23件、fg の不正証拠対照35件はすべて未検証となり、fg の実行する producer 対照は violated となった。両ケースの保存済み CaseOutcome の全詳細・証拠を稼働 JAR の再実行と照合し、outbox は各0件のまま、transcript は各15・20件で不変。失敗した先行試行も含めた設定書込は f9 が16・fg が18、全試行をバイト一致で復元済み。製品再起動・本人操作は0。今回の正式再評価だけで未検証は250→248となる。

原本は `build/acceptance/reference-20261001/ssp-native-consent-logo-v176-r2/` と `ssp-native-consent-safety-v177-r2/`、採用検証は `verify_ssp_consent_logo_acceptance.py` と `verify_ssp_consent_safety_acceptance.py` に保存した。配置後の読み戻し・export 再生成・実稼働 Runner 再実行・正式結果・設定復元を独立検証し、生成器から比較表と台帳へ反映する。


## ネイティブ原本の正式再判定と実登録経路

Keycloak の `IIP-MD06-c-idp-01` は、製品自身のメタデータ取込・署名鍵選択・暗号鍵選択の原本を用い、追加の信頼設定を要しなかったこの操作を Success として採用した。設定登録の成功だけでは確定せず、実際の署名応答と暗号処理、別鍵対照、取込前後と復元の読み戻しを照合する。承認済み ATTESTED モードを変更せず、実観測の証拠種別に合わせて報告の自己申告表示を修正した。保存された CaseOutcome と transcript は変更していない。

Keycloak の `IIP-MD05-f9-idp-01` は、製品の native consent が選択した既定 Logo と画像読込の実観測から Success とした。承認済みの一般 Logo 選択は MAY なので、Suite が追加していた「希望言語に一致する Logo だけが正常」という条件を撤去した。言語一致がない場合の既定選択条件、相関、画像読込、入力差分と対照の検査は維持する。`IIP-MD05-fh-idp-01` は、実際の native consent にメタデータ由来の file URI が利用者向け Privacy リンクとして出力された反例を Warning とした。管理画面の設定値だけや、入力を拒否した native HTTP エラーを SAML 応答の証拠にしていない。

SimpleSAMLphp の `IIP-SSO01-fr-idp-01` と `IIP-SSO01-gd-idp-01` は、固定された stock responder・有効な認証処理・通常の署名付き bearer 応答に、追加の attester や複数の SubjectConfirmation を観測する機会がないことを原本で確認した。承認済みの通常 bearer の注記条件を用い、Warning として採用する。任意の custom PHP を構成した場合の能力がないとは結論しない。CONFIG の入力画面と自己申告の fallback は残し、原本を所有する Run の不正な受領証では宣言経路へ抜けない。

Shibboleth の `IIP-IDP17-s-idp-01` は、同一 native logout の参加者へ実際の失敗応答が発行され、残る参加者の応答を native flow が受理した原本を確認した。起点の署名付き応答に必要な第二階層 PartialLogout がないため、中央 Evaluator の Failed として採用した。平行処理だけでは失敗を知った後の継続を証明できないため、`IIP-IDP17-r-idp-01` は未検証を維持する。Suite の観測器が実際の M3 登録へ接続されず旧判定を使っていた不備を修正し、承認済みカタログから生成する登録経路でも回帰確認した。

<!--g1-literal--> この採用で未検証は248→242、異なるケースIDは97→96となった。Shibboleth の POST エラー応答は既確定のため削減に重複計上せず、署名原本と正負対照を追加検証した。配備 v180 の対象97テスト、G1構造46/46、G2 21/21が成功。採用時の製品設定書込・製品再起動・プロトコル送信・本人操作は各0。Suiteと転送コンテナの再作成は各1、Docker buildは成功1・sandboxのbuildx書込権限制約による失敗1を原本付きで記録した。未使用ビルドキャッシュを309.4MB削除し、実行中コンテナとボリュームは不変だった。

正式結果・実稼働 JAR・操作と復元の原本は `build/acceptance/reference-20261001/` の `keycloak-native-self-contained-trust-v178-r1/`、`keycloak-native-ui-consumer-v178-r1/`、`ssp-subject-confirmation-native-v178-r1/`、`shibboleth-native-slo-v178-r7/reader-v180/`、`combined-runtime-v180/` に保存した。採用バッチの集合・ハッシュ・確認結果は `progress-v180.json` に記録し、比較表と未検証台帳は生成器で更新する。

## persistent NameID・既知 Subject・UI URL の原本採用

Keycloak の `IIP-SSO05-a3-idp-01` は、同じ認証主体に対する別 SP と新しい認証セッションの署名・復号済み応答を対応付け、実際の persistent NameID の維持と SP 間の分離を Success とした。同じ識別子を別 SP に返す native mapper の対照も観測器で検出し、通常の persistent 発行と NameIDPolicy の既確定ケースは削減に重複計上していない。正式結果は `keycloak-native-persistent-pairwise-v180-r4/evaluation/` に保存した。

Shibboleth の `IIP-MD05-a1-idp-01` は、native metadata resolver の重複 entityID の競合と、異なる entityID の相関した署名付き通信を併せて Success とした。`IIP-G02-a-idp-01` は、限定された native c14n 設定で認識できる既知 Subject、文字列入力、拡張文字列入力に対する実際の成功応答を確認した。Suite が再生成した要求と保存原本の構造・実署名、製品の応答署名、既知 principal の audit、未知 Subject の拒否対照を照合する。文字列を無視して成功することが認められる義務であり、返却 NameID の一致や他の文字列処理義務まで Success とはしていない。原本は `shibboleth-entityid-uniqueness-v180-r1/` と `shibboleth-g02-known-subject-v181-r1/` に保存した。

SimpleSAMLphp の `IIP-MD05-fh-idp-01` は、製品自身が取り込んだ InformationURL・PrivacyStatementURL の禁止 scheme が native consent の利用者向けリンクへ出力された反例を Warning とした。実際の CSP によるスクリプト遮断の安全性とは別の義務として扱う。`IIP-MD05-fb-idp-01` は、固定された stock Password・consent・responder の設定と処理ソースを閉じた範囲で照合し、Discovery UI を使わない経路の承認済み注記付き Warning を採用した。汎用 PHP の機能不存在や DOM の欠落だけからは確定していない。原本は `ssp-native-consent-uri-v181-r2/` に保存した。

<!--g1-literal--> この採用で未検証は242→237観測、異なるケースIDは96→92となった。新規採用はSuccess 3・Warning 2で、5観測以外の未検証の増減はない。配備v182の対象153テストと、G1構造46/46・G2 21/21が成功した。正式再評価と台帳採用だけの製品設定書込・製品再起動・プロトコル送信・本人操作は各0。実測キャンペーンの設定変更と復元、先行失敗試行は各原本の操作台帳に保持する。

<!--g1-literal--> 配備後のDocker清掃で未使用ビルドキャッシュ309.7MBと未使用イメージの2.096kBを削除した。実行中5コンテナのID・イメージ・マウントとデータボリュームは清掃前後で一致し、Suiteのhealthは200だった。データボリュームと受入証拠は削除していない。

採用検証器は `verify_keycloak_persistent_pairwise_acceptance.py`、`verify_shibboleth_entityid_uniqueness_acceptance.py`、`verify_shibboleth_g02_known_subject_acceptance.py`、`verify_ssp_consent_uri_acceptance.py`。実稼働 JAR の独立再実行、正式な CaseOutcome の全詳細と証拠、中央 Evaluator の判定、復元原本を照合し、生成器で比較表と台帳へ反映した。採用集合と台帳ハッシュは `build/acceptance/reference-20261001/progress-v182.json`、清掃証拠は同ディレクトリの `docker-cleanup-after-v182/` に保存した。

## 要求 Subject・メタデータ schema・transient AllowCreate の正式採用

Shibboleth の `IIP-SSO07-b-idp-01` は、既知 Subject の保存済み原本を再利用し、要求と署名・復号済み応答の識別子が一致せず、異なる NameIDPolicy による例外にも該当しない反例を Failed とした。修飾子の属性省略だけでは失敗にせず、正常対照、既知 principal の audit、原本の相関と復元を確認した。追加の製品設定変更や SAML 送信は行っていない。

Keycloak の `IIP-MD05-b-idp-01` は、製品自身の converter が schema 上有効な EndpointType の外部名前空間拡張を拒否し、同じ鍵・URL の拡張なし対照を受理した実測反例を Failed とした。通常の native 取込と署名付き SSO、固定された製品 parser の再実行、設定の読み戻しと削除・復元を照合した。真の schema 不正入力は診断対照として保持し、その受理・拒否から別の義務を作っていない。公開クライアント読み戻しでは資格情報を記録前に除去し、除去可能なフィールドと必須の公開属性を reader で検査する。証拠分類は既存 CONFIG 経路の `OPERATOR_ASSISTED` を保持し、本人操作の有無は操作台帳で別に記録する。

SimpleSAMLphp の `IIP-SSO01-fp-idp-01` は、明示・暗黙の transient と AllowCreate の各条件に対する実署名応答、同じ認証セッション、固定された native policy と生成・関連付けソースを照合し、Success とした。通常のログイン状態やログアウトのセッション情報が存在しないとは主張していない。保存前に除去した公開 SAML binding 入力だけをメモリ上で補い、元の HTTP body のハッシュとの一致を要求する。ホストと Suite の時計を同一と仮定せず、各時計内の順序と、時計をまたぐ要求・応答のバイト、ハッシュ、相関 ID をそれぞれ検査する。

<!--g1-literal--> この採用で未検証は237→234観測、異なるケースIDは92→90となった。新規採用はSuccess 1・Failed 2で、既確定の対照は重複計上していない。配備v184の対象222テストとG1構造46/46・G2 21/21が成功し、実稼働125ファイルは配布物と一致した。正式再評価と台帳採用だけの製品設定書込・製品再起動・プロトコル送信・本人操作は各0。

<!--g1-literal--> Keycloak の収集は先行診断・ガード拒否試行を含め設定書込8、native converter14、正常SAML往復1、Run作成4で全復元済み。SimpleSAMLphp の収集は設定書込3（適用2・復元1）、SAML試行8、認証入力1、本人操作0、製品再起動0で全復元済み。reader 修正時の追加製品送信はない。失敗した export・再実行・受領証整形の試行も元の原本と操作記録を保持した。

<!--g1-literal--> 配備後、未使用Dockerビルドキャッシュ314.4MBを削除した。実行中5コンテナとデータボリュームは不変で、Suite healthは200だった。採用集合・正式結果ハッシュ・実稼働配備・確認結果は `build/acceptance/reference-20261001/progress-v184.json`、清掃証拠は同ディレクトリの `docker-cleanup-after-v184/` に保存した。

## 各製品の通常 bearer と属性サービス選択の正式採用

Keycloak と Shibboleth の `IIP-SSO01-fr-idp-01`・`IIP-SSO01-gd-idp-01` は、実際の署名付き通常 bearer 応答と、この Run で有効な stock factory・mapper・設定・処理ソースを照合した。追加の attester または複数の SubjectConfirmation を観測する機会がない構成に対する承認済みの注記条件を用い、中央 Evaluator の Warning として採用した。汎用の拡張実装に同じ能力がないとは結論せず、応答 DOM の欠落だけを能力不存在の証拠にしていない。署名付きの意味対照は製品通信の原本と分離し、壊れた原本、異なる Run、設定変更、復元不成立を未検証にする検査を維持する。

Shibboleth の実登録経路では、初期の registry 作成に metadata variant の鍵が渡されていなかった。既存の後段 preparation hook を通じて鍵を observer へ渡すよう修正し、空の鍵、別 Run・別 variant の鍵では未検証、正しい鍵でのみ原本に基づく注記が成立することを実稼働 JAR で確認した。保護された M1 runtime のソースは変更していない。

SimpleSAMLphp の `IIP-IDP04-b-idp-01` は、製品自身が受理した属性サービスのメタデータ、両属性を返す正常対照、同じ認証主体・セッションと固定された属性設定を照合した。署名付き要求のサービス選択を変更しても同じ UID だけが返る反例を、中央 Evaluator の Failed とした。パーサが別サービスを失うことだけでは確定せず、実際の署名付き要求・応答とネイティブ処理を併せて判定した。既存 CONFIG の `OPERATOR_ASSISTED` 分類を保持し、本人操作の回数とは分けて記録する。

<!--g1-literal--> 新規採用はWarning 4・Failed 1で、未検証は234→229観測、異なるケースIDは90→88となった。Keycloak 88・Shibboleth 58・SimpleSAMLphp 83観測が残る。配備v185の対象260テスト、G1構造46/46・G2 21/21が成功し、実稼働125ファイルは配布物と一致した。正式判定と台帳採用だけの製品設定書込・製品再起動・プロトコル送信・本人操作は各0。

<!--g1-literal--> Keycloak の収集は設定書込2（作成・削除）、native HTTP 31、プロトコル試行2。Shibboleth は先行試行を含め設定書込12・再読込8・プロトコル試行8・Run作成4、採用試行だけでは設定書込3・再読込2・プロトコル試行2・Run作成1。SimpleSAMLphp は設定書込3（適用2・復元1）、プロトコル試行5、認証入力1、Run作成1、native parser 2と独立再実行2。製品再起動と本人操作は各0で全設定を復元した。失敗した helper・export・保存結論読取の試行も原本と操作履歴を保持し、reader修正のための追加製品送信は行っていない。

<!--g1-literal--> 不正原本対照はKeycloak 29・Shibboleth 32・SimpleSAMLphp 53で、すべて未検証となった。配備後の未使用Dockerイメージとビルドキャッシュの清掃では、実行中5コンテナとデータボリュームが不変で、Suite healthは200を維持した。

原本と正式結果は `build/acceptance/reference-20261001/` の `keycloak-native-subject-confirmation-v184-r1/`、`shibboleth-subject-confirmation-v184-r4/reader-v185/`、`ssp-attribute-service-index-v184-r1/` に保存した。独立採用検証器は `verify_keycloak_subject_confirmation_acceptance.py`、`verify_shibboleth_subject_confirmation_acceptance.py`、`verify_ssp_attribute_service_index_acceptance.py`。保存済み結果だけでは採用せず、配置した原本の読み戻し、実稼働 JAR の再実行、CaseOutcome の全詳細・証拠、中央判定、設定復元と transcript 不変を照合した。採用集合と台帳ハッシュは `progress-v185.json` に記録し、比較表と未検証台帳は生成器で更新した。

## Keycloak・Shibboleth の transient AllowCreate 原本採用

Keycloak と Shibboleth の `IIP-SSO01-fp-idp-01` は、transient の明示・暗黙と AllowCreate の各条件について、実際の署名付き要求・応答、この認証処理の主体、有効な native factory と設定、関連付け処理を照合し、中央 Evaluator の Success として採用した。通常のログイン・ログアウト用のセッション情報まで保存されないとは主張せず、この Run で選択された transient 生成の処理範囲を明示する。

Shibboleth には UID 属性を返すことや、応答ごとに同じ SessionIndex を返すことを追加条件として要求しない。native audit の Assertion ID・principal・認証時刻・IdP の認証セッションを、署名・復号済みの実応答に対応付ける。処理ソースの定数文字列の欠落だけでは判断せず、選択された stock bean、実 method Code と呼出先、crypto-transient の DataSealer 経路を検査する。native 鍵で署名した意味対照は実製品の通信原本と分離する。

Keycloak の初回復元は管理 token の期限切れで失敗した。失敗した原本と restored:false を残し、別の recovery 原本で削除・読み戻し・復元完了を証明する。Shibboleth の helper が JSON を再整形して証拠参照のハッシュを変えた診断も保存し、正式再実行では配置した manifest の実バイトをそのまま使う。所有する受領証が不正な場合や複数製品の受領証が競合する場合は、開始・再開・queued・再評価の各経路で未検証を維持する。

<!--g1-literal--> この採用で未検証は229→227観測、異なるケースIDは88→87となった。追加はSuccess 2で、Keycloak 87・Shibboleth 57・SimpleSAMLphp 83観測が残る。配備v186の対象297テスト、G1構造46/46・G2 21/21が成功し、実稼働125ファイルは配布物と一致した。正式再評価と台帳採用だけの製品設定書込・製品再起動・プロトコル送信・本人操作・Run作成は各0。

<!--g1-literal--> Keycloak の全収集は native HTTP 115、設定書込試行4・成功3、プロトコル試行8、Suiteだけのprepare/abort 126、管理token取得3、製品再起動・本人操作0。Shibboleth はプロトコル試行8、設定書込4、再読込3、Run作成1、Suiteだけのprepare/abort 126、製品再起動・本人操作0。Shibboleth の追加matrixは認証入力0で、正常対照の認証入力総数は未計測として記録する。全設定を復元し、失敗した選択・観測・helper試行の原本と補足前のハッシュを保持した。

<!--g1-literal--> 不正原本対照はKeycloak 27・Shibboleth 36ですべて未検証、Shibboleth のnative署名付き意味対照4も検査した。配備後に未使用Dockerイメージ115.7MB・ビルドキャッシュ319.2MBを削除し、実行中5コンテナとデータボリュームは不変、Suite healthは200だった。

原本と正式結果は `build/acceptance/reference-20261001/keycloak-native-transient-allow-create-v185-r1/` と `shibboleth-transient-allow-create-v185-r1/reader-v186/` に保存した。独立検証器は `verify_keycloak_transient_allow_create_acceptance.py` と `verify_shibboleth_transient_allow_create_acceptance.py`。実配備 JAR の再実行、配置と読み戻し、CaseOutcome の全詳細・証拠、中央判定、復元、transcript 不変を照合し、台帳と比較表は生成器で更新する。採用集合・ハッシュ・配備と確認結果は `progress-v186.json` に記録した。

## 参照製品での採用と一般利用者の実行可能性

ここまでの native 採用は、実際の参照製品の挙動と Suite の判定を確かめた結果である。一般利用者が任意の製品を指定し、Suite の画面だけで同じキャンペーンを実行できることの証明ではない。native adapter は固定した製品版・設定・実装原本を要求し、開発用の収集には管理 API、内部ファイルの読み戻し、コンテナアクセスが必要なものがある。通常の SAML 通信によるシナリオと、追加の内部原本を使う参照キャンペーンを分けて扱う。

設定変更・認証入力・復元を自動化しても、その作業が不要になったことにはならない。本人操作が記録上不要だったことと、管理権限の準備・初期設定・実行手段の選択まで含む導入負担を測定したことも区別する。導入時の操作数、任意環境での実行、画面からの一括起動は未検証であり、ゼロ操作やリリース可能とは報告しない。

今回の各キャンペーンの入口、追加権限、製品版への依存、実測した設定書込と送信、本人操作と未計測項目は `build/acceptance/reference-20261001/execution-readiness-v187.json` に記録する。今後は、通常のメタデータ取得と SAML 通信で実行できる判定を優先し、追加の管理アクセスが必要なものは実行前に必要条件を示す。参照環境の未検証削減数を、一般ユーザー向け実行経路の完成率として扱わない。


## 受理済み更新メタデータと暗号化ログアウトの限定反例

SimpleSAMLphp の旧 `IIP-IDP06-b-idp-01` の Success は監査撤回する。外部の再認証時刻だけでは、認証機構が内部で ForceAuthn を参照できるという承認済み義務を証明しない。元の result と transcript は保存し、原本ハッシュ・Run・参照応答・承認済み variant を照合する review qualification として未検証へ戻す。`IIP-IDP06-a-idp-01` の外部再認証判定と、別 Run の内部機構証拠は変更しない。撤回は `audit_force_authn_mechanism_evidence.py` が検証し、製品の違反を新たに割り当てるものではない。

Keycloak の `IIP-MD06-ab-idp-01` は、同じ entity・native client に対する A→B の元メタデータ取込、明示的な受理、保存設定、実装ソース、署名付き正常対照を固定した共有キャンペーンの証拠を使用する。受理済み B が広告する第2 POST ACS を、同じ B 鍵で正しく署名して要求したときの native `Invalid redirect uri` を、正常 ACS の署名付き Success と不正署名対照に対応付けた。全条件を満たす Success ではなく、承認済み `IIP-MD06.ab#v-7e4460130e` の実適用義務に対する具体的な反例を中央 Evaluator の Failed とする。他の binding・profile や全製品能力の不存在には広げない。

この Run の実際の要求は元の `IIP-MD06-a-idp-01` の共有原本のままで、AB が送信したことにはしていない。AB 自身の準備済み outbox は PENDING・transcript参照なしのまま残る。最初の v187 保存結果では既に原本に基づく再評価が完了しており、明示的な evaluate の前後は同じ結論だった。この finished case と未送信 outbox の組合せは別の Suite 診断原本に記録し、status・case_id・過去の未知配送を修正しない。

SimpleSAMLphp の `IIP-IDP19-c-idp-01` は、正常ログアウト、登録済み第2鍵による復号、登録されていない鍵による暗号化の対照を同じ native セッション・要求・応答に相関した。製品自身の parser・復号検証と実装原本を照合し、登録外鍵の暗号文を native 復号では拒否する一方、同じ実ログアウト経路が成功応答を返した限定反例を中央 Evaluator の Failed とする。汎用ブラウザ observer の対照不成立による古い NOT_VERIFIED は原本どおり残し、無応答や HTTP エラーだけから拒否能力を断定しない。追加 native 原本がない環境には今回の確定を適用しない。

<!--g1-literal--> このバッチの正式採用はFailed 2件で、未検証227→225観測、異なるケースID87は不変。配備v187の対象299テスト、G1構造46/46、G2 21/21が成功し、実行時125ファイルは配布物と一致した。Keycloak 86・Shibboleth 57・SimpleSAMLphp 82観測が残る。正式再評価と採用だけの製品設定書込・製品再起動・SAML送信・Run作成・本人操作は各0。

<!--g1-literal--> Keycloak は過去の収集3試行を共有し、設定操作15・SAML試行45・Run作成3を再利用した。今回のAB採用に重複加算しない。SimpleSAMLphp は先行失敗を含む7試行で設定書込試行33（適用19・復元14）、SAML試行40、認証入力19、Run作成7、native parser12・復号4・署名検査25。Suiteだけのprepare/abortは159、一時鍵7・一時ファイル書込14・削除14を記録した。全設定は復元済みで、一時鍵は削除、製品再起動・本人操作は各0。native helper失敗と旧汎用対照不成立は削除せず、reader修正の追加製品送信はない。

<!--g1-literal--> 実配備JAR再実行ではKeycloakの23対照と既採用a/cの全Outcome・対照を保持し、SimpleSAMLphpの不正原本38対照はすべて未検証になった。独立検証器は `verify_keycloak_supersession_counterexample_acceptance.py` と `verify_ssp_encrypted_logout_acceptance.py`。原本・正式結果・復元と操作数は `build/acceptance/reference-20261001/keycloak-native-supersession-counterexample-v187-r1/`、`ssp-encrypted-logout-native-v186-r7/` に保存し、台帳差分・配備・独立検証ログは `progress-v187.json` に記録する。比較表の原因分類は exact case・profile・reason とこの検証器の一致を必須にする。

## 認証主体との対応と ForceAuthn の内部到達性

SimpleSAMLphp の `IIP-SSO01-ae-idp-01` は、実際に認証した主体と、署名付き応答に含まれる識別子との対応を native 認証処理、mapper、設定読み戻し、相関した正常系で確認した。任意の表示名や属性が同じことだけを根拠にせず、この認証経路で固定した対応を中央 Evaluator の Success とした。本人の宣言を作ったわけではなく、元の CONFIG mode と OPERATOR_ASSISTED 分類を保持する。

Shibboleth の `IIP-IDP06-b-idp-01` は、実際に選択された stock Password 境界について、元の要求入力に束縛した native 初期化と同じ context オブジェクトで ForceAuthn の値を参照できることを、固定された製品 JAR の内部計測 fixture で確認した。入力の flag、context の結合、初期化、機構への到達を失わせる native mutant は判定を成立させない。これは内部境界の能力の証明であり、true の実 Password UI を完走したという主張ではない。実ブラウザの true＋IsPassive が返した NoPassive 原本は維持し、一般の MFA・証明書認証や未選択の実装へ広げない。承認済み ATTESTED mode のまま、内部観測の証拠を用い、attested:false の中央 Success として採用する。

SimpleSAMLphp の旧 `IIP-IDP06-b-idp-01` は外部の再認証時刻だけで内部到達性を確定していたため、監査資格として未検証へ戻した。旧 PASS、attested flag、元の result と transcript は一切改変せず、原本ハッシュ・Run・参照応答・承認済み variant に束縛した撤回を台帳と比較表へ反映する。外部再認証そのものを評価する `IIP-IDP06-a-idp-01` と、別 Run の新しい Shibboleth 内部観測は不変である。

<!--g1-literal--> 新規Success 2件と旧Successの撤回1件で、未検証は225→224観測となった。配備v188の対象318テスト、G1構造46/46・G2 21/21が成功し、実行時125ファイルは配布物と一致した。正式再評価と採用だけの製品設定書込・製品再起動・SAML送信・Run作成・本人操作は各0。

<!--g1-literal--> SimpleSAMLphp の収集は設定書込試行3（適用2・復元1）、native parser2、プロトコル試行3、認証入力1、Run作成1、Suiteだけのprepare/abort70。全設定を復元し、製品再起動・本人操作は各0。Shibboleth は保存済み正常系を再利用し、追加製品設定・再読込・再起動・SAML送信・Run作成・本人操作は各0。native JVM は先行の合成入力診断2回と原本入力・native mutant の計測2回、target compile試行3回を記録し、失敗したcompile・source読取・helper・archive・cleanupの原本を保持した。

<!--g1-literal--> 実配備JARの原本検証ではSimpleSAMLphpの不正原本28対照、Shibbolethの不正原本14対照とnative mutant4種を検査した。旧SimpleSAMLphp撤回器は正常原本とresult/transcript改変の負対照を確認した。独立検証器は `verify_ssp_authentication_identity_acceptance.py`、`verify_shibboleth_forceauthn_mechanism_acceptance.py`、`audit_force_authn_mechanism_evidence.py`。正式原本は `build/acceptance/reference-20261001/ssp-authentication-identity-v187-r1/` と `shibboleth-forceauthn-mechanism-v186-r1/reader-v188/`、撤回原本は `build/acceptance/reference-20260914/queue-integrated-implementation/simplesamlphp/browser_sso_idp/` のまま保存する。台帳差分、旧PASS撤回、配備、確認結果と独立ログは `progress-v188.json` に記録する。


## 内部証拠のクラスパス固定と操作の前提確認

Shibboleth の機構到達性 reader は、参照したnativeクラスパス一覧の原本を固定SHA-256に照合する。受領証に書かれたJARハッシュだけでは変更された中間実装を採用しない。採用済み原本と正式結果はそのまま保持し、production側の固定検査を補強した。

<!--g1-literal--> v189の対象319テストとG1構造46/46・G2 21/21が成功し、実稼働125ファイルは配布物と一致した。未検証224観測・87ケースIDは不変。この補強だけで新しい製品判定や台帳削減は行わない。

一般利用者向けには、内部証拠のないIDP06.bで外部ログインを要求する経路を廃止した。開始・再開・旧待機の解消はいずれも追加のブラウザ操作を要求せず、内部証拠が不足する場合は管理者が用意すべき証拠を案内して未検証を維持する。キャンペーン画面は実行できる操作と残る未検証を分け、ブラウザ操作を必要としない項目には実行リンクや再ログイン指示を表示しない。参照環境の自動収集・本人操作不要という結果を、一般利用者の最小手順の実証と混同しない。初期設定を含む総負担の未計測項目は引き続き明示する。

<!--g1-literal--> この改善の対象Java 89テストとWeb 87テスト、G1構造46/46・G2 21/21が成功した。配備v190の125ファイル一致と既採用の内部証拠を確認し、製品設定・追加SAML送信・本人操作は各0。IDP06.b単体で内部証拠がない場合の予定ブラウザ段階は4→0、予定認証チェックポイントは2→0となる。この値からキャンペーン全体の実際のログイン回数は推定していない。検証原本と測定範囲は `build/acceptance/test-user-effort-20261002/summary.json` に保存した。

## セッション共有と認証証拠の追加採用

Keycloakの `IIP-SSO01-ae-idp-01` は、選択したクライアントのPassword認証経路、通常ログインの公開チャレンジ、認証した主体を含む署名付き応答、空セッションのpassive要求に対する署名付きNoPassiveを照合し、Successを採用した。管理者の準備を伴うため既存のCONFIG分類 `OPERATOR_ASSISTED` を維持し、本人の証言とは区別して `attested:false` としている。全認証経路や任意の拡張に同じ性質があるとは主張していない。

Shibbolethの `IIP-IDP08-a-idp-01` は、クラス参照・宣言参照・満たせない要求を含む承認済みのexact比較を、署名・復号・相関した原本で確認した。正常なログイン後は同じ認証クライアントを共有し、追加の入力が必要な条件と通常のSSO要求を分けた。保存済みCaseOutcomeと中央Evaluatorの結果、意味を変えた対照と原本の束縛を壊した対照、設定復元、正式再評価前後のtranscript不変を照合した。

<!--g1-literal--> 新規Success 2件により未検証は224→222観測、異なるケースIDは87→85となった。配備v191の対象Java89テスト、G1構造46/46・G2 21/21が成功し、稼働125ファイルが配布物と一致した。正式再評価と台帳採用だけの追加製品設定・SAML送信・本人操作は各0。比較表と未検証台帳は生成器で更新し、残る全観測と承認済みvariant/controlおよび元結果ハッシュの照合はエラー0だった。

<!--g1-literal--> Shibbolethの収集はプロトコル試行7、自動認証入力1、共有クライアント利用6、要求された新規セッション境界0、製品設定書込5（復元2を含む）、製品再起動2で、本人操作0。Keycloakの採用対象収集はプロトコル試行2、自動認証入力1、設定書込6（復元2を含む）、製品再起動・本人操作0。Keycloakの初回非採用試行も含む累計はプロトコル試行4、自動認証入力2、設定書込12で全復元済み。初回collectorが数えなかった正常Redirect要求は、元countを改変せず原本の相関した往復を根拠に別記録で訂正した。

実測原本と本人・管理者・自動操作の区別は `build/acceptance/reference-20261002/shared-authentication-adoption/summary.json` と各campaignに保存した。参照環境で本人操作を省けたことを、一般利用者の初期設定を含む負担が最小であるという主張にはしていない。

## 同じセッションで測定したメタデータの実効期限

Shibboleth と SimpleSAMLphp の `IIP-MD05-ar-idp-01` は、EntityDescriptor 自体、早く期限切れになる親、早く期限切れになる子の各条件を、製品が実際に読み込んだ元のメタデータで測定した。正常な署名付き要求・応答、製品の時計と実効期限、期限後のネイティブな無効化、設定読み戻しと復元を関連付ける。HTTPエラー、待ち時間、自己申告した復元フラグだけでは確定しない。Shibboleth の期限後はネイティブ resolver の拒否と相関した製品ログ、SimpleSAMLphp はネイティブな期限拒否と公開エラー原本を併せて検査した。

それぞれの期限条件は同じメモリ内の認証クライアントで続けて測定した。初期疎通の不足による追加作業は、正常疎通だけを補って保存済みの期限試験を再利用し、全条件を再送していない。今後のcollectorは初期疎通を先に行い、そのクライアントを期限試験でも共有する。設定変更・読み戻し・復元・操作回数の記録は自動化している。必要な空セッション対照や強制再認証まで省くものではない。

<!--g1-literal--> 正式な追加Successは2件で、未検証222→220観測、異なるケースID85は不変。Keycloak 85・Shibboleth 54・SimpleSAMLphp 81観測が残る。配備v193の対象Java102テスト、G1構造46/46・G2 21/21が成功し、稼働125ファイルは配布物と一致した。正式再判定と台帳採用には追加設定・SAML送信・ログイン・本人操作を要していない。承認済みCONFIG分類のOPERATOR_ASSISTEDとattested:falseを保持する。

<!--g1-literal--> 初期疎通の補完を含む累積操作は、ShibbolethがSAML要求8・自動認証入力2・設定書込10（復元3を含む）・再読込6・製品再起動2、SimpleSAMLphpがSAML要求8・自動認証入力2・設定書込6（復元2を含む）・製品再起動0。本人操作は各0で、全設定を復元した。将来のcollectorが初期疎通と期限条件を認証入力1回で完走することは、この採用バッチでは再測定していない。一般環境での初期権限準備まで含む最小操作数も未計測である。

<!--g1-literal--> 原本を壊す対照はShibboleth 33・SimpleSAMLphp 28で未検証、承認済みの期限・親子期限の意味を変える対照はShibboleth 3・SimpleSAMLphp 1で違反を検出した。正式結果・保存CaseOutcome・原本の配備読み戻し・transcript不変・復元を独立に照合し、比較表と未検証台帳は生成器で更新した。採用検証器は `verify_shibboleth_metadata_validity_acceptance.py` と `verify_ssp_metadata_validity_acceptance.py`。台帳差分と累積操作は `build/acceptance/reference-20261002/shared-metadata-validity-adoption/summary.json` に保存する。

## 認証セッションを共有した登録・役割鍵のキャンペーン

Keycloakの `IIP-MD05-a1-idp-01` と `IIP-MD05-a2-idp-01` は、異なるentityIDを持つSuiteのPeerを同時に製品自身へ登録して測定した。元XMLを製品の変換経路へ渡し、その出力を新規登録に使用する。両Peerの署名・暗号化された正常応答、同じentityIDを別の鍵・ACSで重複登録した際の明示的な競合、登録前後の読み戻し、削除と元の設定への復元を関連付ける。既存クライアントの明示的な上書き操作を、同時登録の競合試験として扱わない。

<!--g1-literal--> 両Peerの正常試験は同じ認証クライアントを共有し、SAML通信2・自動認証入力1で完了した。ネイティブ管理HTTP試行33、設定書込試行5（成功4、復元の削除2を含む）、製品再起動0・本人操作0を記録した。公開読み戻しに秘密の属性が含まれた最後の収集試行は保存前に停止し、原本を保持したまま読み取りだけで補完した。補完では追加の設定・通信・認証入力を行っていない。

Shibbolethの `IIP-MD06-a2-idp-01` は、SPとIdPのRoleDescriptorを併せ持つ元XMLを、役割の並び順と鍵のuse指定を変えてネイティブなMetadataResolverへ渡した。要求への署名鍵、製品が読み込んだ役割別の鍵、署名・暗号化された正常応答、別役割の鍵を使った要求への明示的なネイティブ拒否を照合する。暗号化用と記した鍵による署名を受理したことだけを根拠に、承認済み義務に存在しない禁止を追加しない。その対照は未検証とし、別役割の鍵を受理する対照とは区別する。

<!--g1-literal--> 初期疎通を先に同じメモリ内クライアントで実行し、役割鍵の11要求を続けた。累積SAML通信12・自動認証入力1・設定書込11（復元3を含む）・再読込6・製品再起動2・本人操作0で、全設定を復元した。初期疎通と本試験で観測した認証入力は同じ操作であり、重複して加算しない。署名付き正常応答4件とネイティブ拒否7件を収集した後、判定器の修正と正式再判定には原本だけを再利用し、追加ログインを要求していない。

<!--g1-literal--> 役割鍵の保存済みv194未検証結果と原本を保持し、v195で同じRunを再判定した。原本を壊す29対照は未検証、別役割の鍵を受理する4対照は違反、暗号化用途の鍵を受理する2対照は未検証となった。正式な保存CaseOutcomeでは旧結果の全履歴を検査し、transcriptとoutboxの不変も確認する。正常対照や校正用の合成入力を製品の実測結果として採用しない。

参照環境の収集では本人操作を省けたが、一般環境の初期権限準備や認証方式による操作数まで同じになるとは限らない。セッションを共有できる試験はまとめ、空セッション・強制再認証を要求する試験では必要な境界を保持する。設定と操作回数の原本は各キャンペーン、採用差分は `build/acceptance/reference-20261002/shared-role-entity-adoption/` に保存する。

<!--g1-literal--> この合同採用でSuccessを3件追加し、未検証は220→217観測となった。異なるケースID85は不変で、Keycloak83・Shibboleth53・SimpleSAMLphp81観測が残る。正式再判定・採用による追加の設定変更・SAML通信・認証入力は各0。未検証全217観測の元結果・承認済みvariant/controlの照合はエラー0、G1生成一致・構造46/46、G2 21/21を確認した。Keycloakの登録キャンペーンの操作数は両ケースで一度だけ計上し、判定数と操作数を分ける。

## 登録された署名者と証明書条件の合同採用

KeycloakとSimpleSAMLphpの `IIP-SSO01-al-idp-01` は、製品自身に登録した別Peer、実効鍵の読み戻し、署名付き正常応答、不正署名と別Peerの鍵による要求へのネイティブ拒否を関連付けた。HTTPエラーだけから署名者制限を断定せず、拒否本文と製品の検証経路を照合する。両Peerは同じメモリ内の認証クライアントを共有し、別Peerの対照用Runを追加の確定件数には数えない。承認済みATTESTED modeを変更せず、内部観測を根拠としたOPERATOR_ASSISTED・attested:falseのSuccessとして採用する。

Shibbolethの `IIP-MD06-a6-idp-01` は、正常証明書、critical拡張、未知CA、失効、失効情報へ到達できない条件を同じ認証セッションで測定した。元の証明書バイト、ネイティブなメタデータ鍵の読み込み、Suiteのoutbox要求、署名・復号・相関した正常応答と不正署名の拒否、設定復元を照合した。通常の署名拒否をPKIXの追加検査と取り違えず、原因が証明できない拒否は未検証を維持する。native JCAによる反例は判定器の校正専用で、製品の実測や確定件数には採用しない。

<!--g1-literal--> 正式な追加Successは3件で、未検証217→214観測、異なるケースID85は不変。Keycloak82・Shibboleth52・SimpleSAMLphp80観測が残る。実配備v197の対象Java30テスト、G1生成一致・構造46/46、G2 21/21を確認し、実稼働125ファイルは配布物と一致した。保存CaseOutcomeの旧結果全文・revision・時刻、transcriptとoutboxの不変、受領証の配置読み戻しと復元を独立に検査した。正式再判定と採用での追加設定・SAML送信・認証入力・本人操作は各0。

<!--g1-literal--> 収集の累積操作は、KeycloakがSAML送信8・自動認証入力1・設定書込4（復元2を含む）、SimpleSAMLphpが先行失敗を含めSAML送信11・自動認証入力2・設定書込4（復元2を含む）、ShibbolethがSAML送信7・自動認証入力1・設定書込12（復元3を含む）・再読込7・製品再起動2。全設定を復元し、本人操作は各0。SimpleSAMLphpの成功した収集だけの値はSAML送信8・認証入力1であり、失敗試行の負担を累積値から除外しない。

<!--g1-literal--> 最終確認中のDocker I/O障害は、Desktop再起動1・同じ製品コンテナの起動3・Suite起動1・転送コンテナ起動1・Shibbolethサービス起動1で復旧した。設定書込・SAML送信・認証入力・本人操作・ボリューム削除は各0。この障害復旧は試験中の操作数と分け、旧測定epochと原本を変更せず、復旧前後のコンテナID・image・全Mount要素とStartedAtを別原本で対応付ける。生きている環境の確認を省くためにepochの照合条件を撤廃していない。

採用差分と累積操作は `build/acceptance/reference-20261002/shared-signer-certificate-adoption/`、正式原本は `keycloak-registered-signer-r1/`、`simplesamlphp-registered-signer-r3/`、`shibboleth-certificate-runtime-r1/` に保存した。一般利用者の初期権限準備まで含む最小負担を実証したという主張ではない。比較表の生成では同じキャンペーンの完全な検証を生成単位で共有し、別の生成時には原本から再検証する。

## SimpleSAMLphpの証明書条件と本番経路の再判定

SimpleSAMLphpの `IIP-MD06-a6-idp-01` は、元の証明書メタデータを製品自身のparserへ渡し、実効署名鍵の読み戻し、署名付き正常応答、不正署名のネイティブ拒否、設定復元を照合した。正常証明書、critical拡張、未知CA、失効、失効情報への到達不能を同じメモリ内の認証クライアントで測定した。通常の署名拒否や無応答を、証明書の追加検査による拒否として扱わない。

要求のIssueInstantはSuiteがoutboxを準備した時刻であり、製品の設定適用より前でも、実際の送信は設定適用後になり得る。判定器は元の要求・署名・時刻を変更せず、設定読み戻し、実際のoutbound記録、ネイティブHTTP送信の開始・終了と要求ハッシュ、相関応答、送信後の読み戻しを関連付ける。本番の鍵取得APIと同じvariant契約で再実行し、補助検証だけが受け付ける鍵の別名に依存しない。暗号化された初期baselineは現在のreaderでは未検証を維持する。今回のbaselineと正常応答は実バイトでplaintext Assertionを確認し、variantの受信鍵は実際の広告鍵に結合する。

<!--g1-literal--> 正式な追加Successは1件で、未検証214→213観測、異なるケースID85は不変。Keycloak82・Shibboleth52・SimpleSAMLphp79観測が残る。v200の対象Java40テスト、G1生成一致・構造46/46、G2 21/21を確認し、実稼働125ファイルは配布物と一致した。保存CaseOutcomeは旧revision8の未検証から9のSuccessへ更新し、旧結果全文・時刻・revision、70件のtranscriptと6件のoutbox不変、受領証の配置読み戻し、設定の完全復元を独立に検査した。承認済みCONFIG分類のOPERATOR_ASSISTED・attested:falseを保持する。

<!--g1-literal--> 成功した収集はSAML送信7・自動認証入力1・設定書込7（復元1を含む）、製品再起動・本人操作0。初回はfixture準備の依存不足で停止し、設定を完全復元した。そのRunは待機期限で終了していたため、状態や未送信outboxを復活させず、新Runでまとめて再測定した。初回を含む累計はSAML送信13・自動認証入力2・設定書込14（復元2を含む）、本人操作0。今後のcollectorは必要なfixtureとコマンドをすべて確認してから製品設定を変更する。収集後のreader修正・正式再判定・独立監査には追加の設定変更・SAML送信・認証入力を要していない。

<!--g1-literal--> 実配備JARの原本改変対照33種は未検証となり、承認済みの到達不能変異は違反を検出した。native署名検証後に証明書自身のCDP/AIA取得が失敗し、固定した追加検査方針でOpenSSLの失効情報エラーとなる診断原本を校正に使用した。失効証明書のエラーは別の追加対照として扱う。これらは校正専用で、実製品の拒否・実送信時刻・台帳確定件数には採用しない。診断の追加設定・SAML送信・認証入力は各0で、準備中に停止した診断処理とその操作数も別の原本に保存する。

原本と正式結果は `build/acceptance/reference-20261002/simplesamlphp-certificate-runtime-r2/`、初回失敗は `simplesamlphp-certificate-runtime-r1/`、採用差分と検査結果は `ssp-certificate-runtime-adoption/` に保存する。`verify_ssp_certificate_runtime_acceptance.py` が両試行の原本ハッシュと累計費用、旧配備の未検証履歴、固定した本番JARの再実行、中央Evaluatorの全結果を検証する。一般環境の初期権限準備まで含めた最小負担を実証したという主張ではない。

今後の正式再評価では、実APIの証拠準備状態を先に保存し、未準備なら評価POSTを送らずにSuiteの接続不足として停止する。完了済みの履歴を再実行して、この確認を過去の証明へ追加することはしない。保存結果を読むヘルパーの選択は専用のPython module内に閉じ、同じ生成プロセスで別キャンペーンの検証設定を書き換えない。

<!--g1-literal--> この採用CLIの改善は回帰4テストと既存原本のdefault/live検証を通過し、Java/JAR・保存済み原本・製品設定・SAML送信・認証入力・正式評価POSTの追加は各0。

## 署名証拠の追加による再評価と証明書の抽出範囲

`MD05.am/an/ao` で取得・利用の実証が揃い、署名検証の証明だけが不足していた結果は、真正な原本が後から揃えば同じRunで再評価できる。Runnerが実際に読んだ原本参照を、署名ゲートの全検査が成功した場合だけ追加し、中央の確定更新条件で採否を決める。不完全なvariant、無応答、設定利用不能、すでに確定した結果は、この経路で確定へ変更しない。再ログインや同じプロトコル操作の繰り返しを要求しない。

埋込署名鍵の証明書は、メタデータ文書のルート直下の署名と、その直下のKeyInfoから取得する。役割の公開鍵や子Entityの別署名を借用しない。署名や証明書の候補が欠ける場合、または複数で曖昧な場合は証明不成立として扱い、製品の失敗とは判定しない。承認済みのout-of-band信頼鍵との区別、原本の相関、対照、復元の条件は保持する。

<!--g1-literal--> 関連Java62テストが成功した。この修正自体による製品設定変更・SAML送信・認証入力・本人操作・台帳の追加確定は各0で、未検証213観測／85ケースIDを維持する。検証原本は `build/acceptance/reference-20261002/v201-verification/` に保存する。

<!--g1-literal--> ローカルSuiteへv201を配備し、health 200、配布物と稼働125ファイルの完全一致、G1生成一致・構造46/46、G2 21/21を確認した。変更はRunner JAR内の署名readerとconsumer caseのクラスに限られ、証明書条件の採用readerは不変である。配備後も採用済みCaseOutcomeと原本transcriptは保存結果と一致した。配備の追加操作はDocker build・Suite再作成・転送コンテナ再作成が各1で、製品再起動・設定変更・正式再評価POSTは各0。

<!--g1-literal--> 未使用の旧Suiteイメージ3つと未使用ビルドキャッシュを削除し、現行v201と復旧用v200を保持した。未接続ボリュームは保存データの所有元を確認できないため削除していない。Dockerの表示上の回収可能量とMac本体で実測した空き容量を分けて記録し、容量不足の解消は主張しない。操作原本は `build/acceptance/reference-20261002/docker-maintenance/` と `cross-cluster-audit/docker-storage-ownership-v201/` に保存する。

## 役割鍵・登録署名者と既存証拠の再利用

SimpleSAMLphpの `IIP-MD06-a2-idp-01` は、SPとIdPの役割を併せ持つ元XMLについて、役割の並び順と鍵のuse指定を変えて製品自身のparserへ渡し、実効設定と署名・暗号化応答、別役割・不正署名への明示的拒否を照合した。共有する役割鍵readerをネイティブadapterのインターフェースへ分け、既採用のShibboleth結果をそのまま再生できることも確認した。Keycloakはuse省略時に製品の取込経路から鍵が失われ、全条件の証拠が揃わないため未検証を維持した。

Shibbolethの `IIP-SSO01-al-idp-01` は、別々に登録したPeerの署名者を、同時期のExplicitKey trust engine、実効設定、元の要求・応答、要求に結合したネイティブな署名拒否から検証した。HTTPエラーだけを署名拒否の証明にはしていない。旧非同期ログアウトの誤確定の取り消しは [docs/32](32-slo-oracle-implementation.md) に記録した。

<!--g1-literal--> SimpleSAMLphpの役割鍵は、初期疎通を含むSAML送信12・自動認証入力1・設定書込6（復元1を含む）・製品再起動0・本人操作0で収集した。Shibbolethの登録署名者は、SAML送信8・自動認証入力1・設定書込6（復元2を含む）・製品再起動2・本人操作0だった。どちらも同じメモリ内の認証クライアントを共有し、設定を完全復元した。正式再判定・採用のための追加設定・SAML送信・認証入力は各0。

SimpleSAMLphpの `IIP-MD06-c-idp-01` は、上記の役割鍵キャンペーンで取得済みの署名・暗号化証拠を再利用した。当該XML署名検証とEncryptedAssertion生成・復号について、製品が元メタデータから取り出した鍵を使い、追加の信頼鍵入力を必要としない経路を検査する。TLSや全authproc・全信頼ストアの不存在には一般化していない。承認済みATTESTED分類と `attested:false` を維持し、本人の自己申告で確定したものとは区別する。

校正用の追加アンカー要求は、実際に選択したネイティブ入力・出力・ソース・実行コマンドへ結合する。受領証のラベルを変えるだけでは違反を生成できない。本番readerとwrapperは校正用証拠を未検証にし、明示的なオフライン校正の許可を持つ検証ヘルパーだけが同じ判定処理で反例を検出する。校正用入力・出力は本番へ配置しない。

<!--g1-literal--> この追加採用は、同じRunの未検証revision0からSuccess revision1への正式更新、旧結果の全履歴、80件のtranscriptと全31件のoutbox不変、stock-only受領証の配置読み戻しを確認した。追加の製品設定・SAML送信・認証入力・製品再起動・本人操作は各0。公開PHP診断は正式候補2呼出、初期試作と修正前試行を含む累計5呼出で、失敗・非採用の試行も保存した。

<!--g1-literal--> 配備v203の関連Java34テスト、台帳取り消しと原本結合のPython6テスト、G1生成一致・構造46/46、G2 21/21が成功した。配備はRunnerの5クラスに限定し、他のJARは不変。最初の環境変数リスト比較が順序差で停止したため、実効値をメモリ内のmapで照合し、古かったSuite image digest環境変数も実イメージへ修正した。Suiteと転送コンテナの再作成は各2、製品コンテナの再作成・設定変更・SAML送信・本人操作は各0。Run作成時の履歴は書き換えていない。

ビルド用JARと保存用JARのhardlinkが共有されていた箇所は、再ビルドによる上書きを検知し、稼働中の原本から既存の固定SHA-256へ完全復元した。保存側は独立したバイトコピーへ分離し、他のプロジェクトJARの保存hardlinkも解除した。旧検証結果・受領証・原本ハッシュの記録は変更していない。

原本と採用検証は `build/acceptance/reference-20261002/simplesamlphp-role-keys-r1/`、`simplesamlphp-self-contained-trust-r3/`、`build/acceptance/reference-20261003/shibboleth-registered-signer-r1/` に保存する。`verify_native_metadata_role_key_acceptance.py`、`verify_simplesamlphp_self_contained_trust_acceptance.py`、`verify_shibboleth_registered_signer_acceptance.py` が実配備JARと原本、中央Evaluator、正式保存結果を照合する。

<!--g1-literal--> Docker容量不足の復旧ではDesktop再起動2回、コンテナ開始試行7回（成功6）、ShibbolethのTomcat開始1回を別記録に残した。古い未使用Suite/PostgreSQLイメージ、ビルドキャッシュ、重複ビルドJAR、古いログとキャッシュを削除し、最新確認でMacの空き容量は約43GiB、Dockerビルドキャッシュ0。未接続ボリューム164件は使い捨て用途を確認できず保持した。物理的な空き容量の増加を個別イメージの表示サイズへ単純に帰属させていない。復旧・削除の原本は `docker-maintenance/` に保存する。

<!--g1-literal--> この継続バッチでは新たに3観測を確定し、証拠不足だった旧非同期ログアウト2観測の採用を取り消した。未検証は213→212観測、異なるケースIDは85→84となり、Keycloak83・Shibboleth52・SimpleSAMLphp77観測が残る。比較表と台帳は生成器で更新した。取り消した元result.jsonとtranscriptは保持し、監査による採用取り消しを製品の失敗とは扱わない。

Shibbolethの追加信頼入力の候補は、証拠を収集したブラウザRunに対象のメタデータケースが存在せず、別Runへ証拠を借用する契約もないため採用していない。候補readerと校正原本は保管し、本番登録・配備・判定更新は行わなかった。今後は実装前に、対象Runのケース、役割、mode、対象メタデータ、証拠元Runの対応を確認する。

事前検査は `.venv/bin/python dev/reference-acceptance/preflight_observation_adoption.py --case-id CASE_ID --target-result RESULT_JSON` で実行する。既存証拠を再利用する場合は `--source-result SOURCE_RESULT_JSON` も指定する。これは採用経路の存在を調べる読み取り専用の検査であり、`scope_ready:true` は証拠の正しさやSuccessを意味しない。ケースがない場合や、契約のない別Runの再利用は実装前に停止する。

<!--g1-literal--> 事前検査の回帰7テストと実原本4組を確認した。同一RunのSimpleSAMLphpの再利用は経路確認を通過し、Shibbolethのケース欠落と別Run混用は停止した。この改善の製品設定変更・SAML送信・認証入力・本人操作・追加確定は各0。原本は `cross-cluster-audit/observation-adoption-preflight/` に保存する。

## 信頼鍵とUI安全性の正式採用

Shibbolethの `IIP-MD06-c-idp-01` は、対象ケースを含むメタデータRunの役割鍵キャンペーンを利用した。製品自身のMetadataCredentialResolverとExplicitKey trust engine、署名・暗号化された正常応答、別役割の鍵と不正署名への拒否、同時期の実効設定を関連付け、追加の信頼鍵入力なしで処理した範囲をSuccessとした。承認済みATTESTED分類を保持し、本人の自己申告を使わない `attested:false` の観測結果とする。別Runのブラウザ証拠を移したものではない。

Keycloakの `IIP-MD05-fg-idp-01` は、元メタデータを製品自身の変換・登録経路へ渡し、画像の実際の出力先、InformationURLを使用しないネイティブ経路、危険なPrivacyStatementURLの登録拒否を確認した。使用しないURLの注記を中央EvaluatorがWarningへ変換しており、Successとは区別する。実際のブラウザ原本・製品ソース・設定読み戻し・復元を照合し、危険なリンクを出力する校正専用の対照は本番へ配置しない。

<!--g1-literal--> 配備v204の関連Java62テスト、G1生成一致・構造46/46、G2 21/21が成功した。正式追加はSuccess 1・Warning 1で、未検証212→210観測、異なるケースID84→82。Keycloak82・Shibboleth51・SimpleSAMLphp77観測が残る。正式再評価・採用の追加設定・SAML送信・認証入力・本人操作は各0。Shibbolethの45件とKeycloakの36件のtranscript、両outbox、保存済み未検証結果の履歴を保持した。台帳全観測の原本と承認済みvariant/controlの照合はエラー0で、比較表と台帳を生成器で更新した。

<!--g1-literal--> 収集操作は、Shibbolethが初期疎通を含むSAML送信12・自動認証入力1・設定書込11（復元3を含む）・再読込6・製品再起動2、KeycloakがSAML送信3・自動認証入力1・設定書込試行7（成功6、削除による復元3を含む）・製品再起動0。本人操作は各0で全設定を復元した。Shibbolethの元wrapper countは11のまま保存し、初期疎通のRecorder原本による補正を別記録に残した。初回の未採用・事前停止試行も操作履歴から除外しない。参照環境の自動認証入力を、一般利用者の初期権限準備まで含む最小負担の実証とはしていない。

正式結果・原本と採用検証は `build/acceptance/reference-20261003/shibboleth-role-self-contained-trust-r2/trust-proof/` と `keycloak-ui-safety-r1/` に保存する。採用検証器は `verify_shibboleth_self_contained_trust_acceptance.py` と `verify_keycloak_ui_safety_acceptance.py`。合同差分は `native-adapter-integration-v204/adoption-summary.json` に保存した。既知の広範囲テスト失敗と未完の試験が残り、リリース準備完了は主張しない。

<!--g1-literal--> 未使用の旧SuiteイメージとPostgreSQLイメージ、ビルドキャッシュ369.5MB、重複したビルド用JARを削除した。現行v204と復旧用v203、採用証拠の独立したJARコピーは保持した。保存JARと可変ビルド出力のhardlink共有は0、用途未確認のボリュームは削除していない。Dockerの回収表示とMacの実測空き容量を分け、原本は `deployment-v204/cleanup-final.json` に保存した。

## UIメタデータ入力の修正と旧採用の取り消し

旧 `full-ui-info` fixtureは、DiscoHintsをUIInfoの子に置いていた。正しい配置はRoleDescriptorのExtensions内でUIInfoと並ぶ位置であり、fixtureを修正した。公式MetaUIスキーマによる回帰で、通常・ポーリング両方の正しい配置を検証し、旧配置や同じ名前空間の未定義要素が不正になることも確認した。未知の別名前空間の拡張は保持し、未定義拡張そのものを製品が解釈するという追加義務は設けない。

旧Shibboleth・SimpleSAMLphpの `IIP-MD05-f-idp-01` は、誤配置fixtureの取込と相関したSSOだけでSuccessになっていた。SimpleSAMLphpのネイティブな出力には既知UIInfo値が残っていたが、DiscoHintsの既知値は無く、Shibbolethでも必要な値の読み戻しが保存されていない。不正署名の拒否は、UI拡張を丸ごと無視する実装を検出する対照にならない。この全ケースの採用を取り消し、製品の失敗とは扱わない。LogoやURLだけを別に検証したケース、および前節で新規採用した信頼鍵・UI安全性の結果は、この取り消しの対象外である。

<!--g1-literal--> 厳密な原本pin、承認済みall_ofの4variant、Run、実際の誤配置とネイティブな証拠不足を検証し、過去2観測をNOT_VERIFIEDへ戻した。未検証210→212観測、異なるケースID82は不変。Keycloak82・Shibboleth52・SimpleSAMLphp78観測が残る。元result.jsonとtranscriptは変更せず、生成器の監査選択で取り消す。台帳全観測の契約・原本照合はエラー0。この取り消し自体の製品設定変更・SAML送信・認証入力・本人操作は各0。

採用取り消しは `audit_metadata_full_ui_evidence.py` が原本から限定して資格確認する。配置を直した文書や別Runは、監査ラベルだけを残しても取り消し対象にならない。過去原本、variant検査表、差分は `build/acceptance/reference-20261003/cross-cluster-audit/keycloak-ui-complete-qualification/` に保存した。再試験は正しい元fixtureを製品自身へ渡し、実稼働MetadataResolverなどの読み戻しで必要な値を確認する。Suiteで元XMLを再解析した出力を、製品の実効読み戻しとして採用しない。
