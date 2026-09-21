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
