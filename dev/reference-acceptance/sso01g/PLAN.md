# SSO01-g キャンペーン準備

> 追記（2026-10-31）：以下は当初のオフライン準備の記録。後続のユーザー承認に基づくKeycloak管理API調査とlive設定driverは[SELF-REVIEW-KC.md](SELF-REVIEW-KC.md)に記録した。SAML campaign全体と全4ケースの採用は引き続き保留。

2026-10-31。対象はKeycloakとSimpleSAMLphpの`browser_sso_idp`にあるga/gb/gc/gj。
今回は実機・Docker・ネットワーク・認証情報を使わず、正式台帳は更新しない。
**準備コードのテスト完了と、実機キャンペーンの実行可能性は別である。現時点では両製品とも全ケース実行を保留する。**

## 根拠と境界

- 最初にAGENTS.md、docs/67-authn-context-native-acceptance.md、docs/82-generic-evidence-and-configuration-binding.md、dev/reference-acceptance/GENERIC-BROWSER-CAMPAIGN.mdを確認した。
- 定義は`tests/cases.yaml`の34748行以降と35395行以降、負対照は`tests/mutants/catalog.yaml`の13657行以降と13951行以降を読んだ。変更していない。
- `coverage.yaml`、`specs.yaml`、`predicates.yaml`、`approvals/*`は今回の読み取り禁止に従い未読。署名の再検証やレベル・条件の独立再解釈は行っていない。「承認済み」はプロジェクト資料が示すG2境界を指し、case内のPENDING_REVIEW欄を承認証明にしていない。
- 全variantは下表の`covers_variants`そのもの。全てowner_condition、default-all-of。読み取ったcaseには継承リンク宣言がない。coverageを未読のため推移的リンクの完全性は実機前に許可された検証環境で確認する。ownerのrole/level/testabilityを変更しない。
- ローカル製品根拠の基点を以下では`AUDIT`と書く。
  `build/acceptance/reference-20261002/cross-cluster-audit/authn-context-contracts/`。
  `grouped-contract-review.json`、`kc-archived-bytecode-execution.json`、`ssp-public-source-execution.json`と、それらが指す保存コードを確認した。これらは当時の記録であり、将来の稼働版を証明しない。

## 条件・全variant・正負対照

|case / case_digest|全variant末尾と承認済み条件|正対照 / 負対照|
|---|---|---|
|IIP-SSO01-ga-idp-01 / `765d35ba28060794b59849437e24158b120872a6c4206ecf58688f9edfc897e8`|`ga#v-1c554772bb`: DeclRefも同じminimum規則。`ga#v-96adbf55c8`: 製品のlow < high、minimum lowの成功値≥low。`ga#v-f97a937262`: 達成不能要求のerror Responseを適合として記録。|`iip-sso01-ga-idp-01-positive` / `iip-sso01-ga-idp-01-negative`。baseline `idp-core-no-ecp` / mutant `mut-iip-sso01-ga-idp`。成功値がlow未満になる変異を検出する。|
|IIP-SSO01-gb-idp-01 / `1bd2950222633a51bd756b9ac18629c82fb654b2821afc407d3fff84615d8c19`|`gb#v-09620a84ce`: 達成不能error。`gb#v-5fe19b2dd9`: 製品のlow < high、better lowの成功値>low。`gb#v-a24a0bb304`: DeclRefも同じ規則。|同じ命名のgb positive/negative、baseline同上 / `mut-iip-sso01-gb-idp`。low以下の成功を検出。|
|IIP-SSO01-gc-idp-01 / `2907382964c0928d342d883bc76dd3331922dea687a1dcd64c8f363fa25a325c`|`gc#v-783eafdabe`: low < medium < high、low/mediumのみ利用可能、maximum highで成功時medium。`gc#v-eb393305b0`: 達成不能error。`gc#v-f709ff344a`: DeclRefも同じ規則。|同じ命名のgc positive/negative、baseline同上 / `mut-iip-sso01-gc-idp`。mediumが利用可能なのにlowを返す変異も検出。上限以下だけでは不足。|
|IIP-SSO01-gj-idp-01 / `87b0066aa931850eb730d22136df8bf53253518c4b662a01ea60bec9e87dba15`|`gj#v-1650dc6d0a`: 充足可能なDeclRefの先頭優先。`gj#v-3a6f061c0d`: 同じ候補を逆順にし成功値も反転。`gj#v-f1a318dbe9`: 充足可能な異なるClassRef [A,B]でA優先。|同じ命名のgj positive/negative、baseline同上 / `mut-iip-sso01-gj-idp`。DeclRef順序無視を含む変異を検出。単一候補やerrorは順序の正対照にならない。|

上表のvariantにはすべて`IIP-SSO01.`接頭辞を付ける。正負対照が失敗・未実施ならcontrol_failed/NOT_VERIFIEDとし、成功扱いしない。
ClassRefだけの結論をケース全体へ拡張しない。ga/gb/gcはerrorを許すが、全要求errorは成功選択対照を欠くので全体は未検証。
達成不能要求には相関・署名等を検証したSAML error原本が必要。HTTP500、沈黙、HTMLは代用しない。

## Shibbolethとの差分

`dev/shibboleth/authn_context_preparation.py:inputs()`を実際にimportして要求行列を再利用する。
評価条件は各caseでCLASS/DECLARATION各2、maximumのEXACT low/medium対照は各kindに用意する。
今回さらにnormal設定中にEXACT low/highを各kindで収集してgjの候補可用性を裏付ける。
normalとmaximumにまとめ、同じ状態の通信前後に製品から読み戻す。通常SSO復元対照は別に行う。

Shibbolethは`AuthnComparisonRules`とPassword.supportedPrincipals、`saml2`/`saml2declref`を製品自身に設定できた。
docs/67ではga/gb/gj成功、gcはClassRef medium・DeclRef lowで製品不適合を採用した。これは他製品へ転用できない。
当時は評価・可用性対照20往復と復元後の通常SSOがあり、今回の計画はgjの独立対照も含め24条件＋通常SSOとなる。

旧campaignのDocker操作、既定資格情報、自動ログイン、専用Shibboleth receipt exporterはimportしない。
`export_authn_context_preparation.py`はShibbolethのXMLとPassword flowを再検証するため、製品名を差し替えて流用できない。
Keycloakの`browser_chain_campaign.py`からは公開read-backの投影と比較・復元方式を参照し、認証付きモジュール自体はimportしない。
SimpleSAMLphpは`configuration_batch.py:ConfigurationBatch`をラップし、inode維持と外部編集拒否を再利用する。
旧applied_countはhost適用数なので、製品実効適用数としては使用しない。

### 通信経路の未解決事項

g系はCONFIGで`AuthnContextConfigurationTestCase.evidenceActionKeys()`が空。
generic collectorの`caseIds`へ追加するだけでは比較要求は生成されない。
旧Shibbolethが呼ぶ`SamlScopeApplication`の`/start/metadata-preloaded/{index}`は、署名要求生成・Run更新・Recorder記録を行うが、確認したルートにはpersisted outbox actionの生成がない。
従って今回指定されたoutbox必須条件を旧経路だけで満たすとは主張しない。
将来は、現在の署名済みRunで全24条件を**既存Runnerの永続outbox/browser action**として取り出せることを独立に確認する。
条件・要求原本・actionIdの対応を確認できなければ送信前に停止する。新しい直接HTTP senderやpreloadedへのフォールバックは作らない。
必要なSuite側経路整備がprotected implementationに当たる場合は、別作業で独立レビューとG2更新が必要。今回の書き込み範囲では行わない。

## 製品自身の設定経路の仮説

### Keycloak

根拠: AUDITの`AuthnContextClassRefMapper.javap.txt`は`STEP_UP_AUTHENTICATION_SAML`による有効化、`LoAUtil.getCurrentLevelOfAuthentication`、client note `saml_authn_context_class_ref`、`AcrUtils.getUriLoaMap`を参照する。
`AcrStore.javap.txt`/`LoAUtil.javap.txt`と監査記録はnative LoA候補を示すが、比較の完全実装・DeclRef対応を証明しない。

|条件|設定経路の仮説|実機で要確認|
|---|---|---|
|minimum/better|SAML step-up feature、専用clientのnative URI→LoA map、専用native authentication flow、ClassRef mapperを組み合わせる。low/medium/highは製品が採用したmapから得る。|featureの稼働状態、正確な属性名・設定API、全executionとauthenticator config、各LoAの実際の選択、minimum/better解釈。OIDCの設定だけでSAML対応と判断しない。|
|maximum|同じnative mapのhighを上限として、同じログイン入力でlow/mediumのみ達成可能な専用flowにする。|利用可能集合の網羅性、highの不達、low/medium EXACT成功、最大許容値選択、達成不能error。|
|先頭優先|native mapとflowを固定してlow/high各EXACTを成功させ、候補の順だけを反転する。|実際にrequest順を使うか。LoA数値順と選好順を混同しない。|
|全caseのDeclRef|保存資料からnative設定経路は特定できない。|受理・比較・Response/AuthnContextDeclRef出力を同じ設定で確認。ClassRef mapperの存在から推定しない。未充足なら全case保留。|

変更範囲は専用client、mapper、専用flowと関連execution/configだけに限定する仮説。realm全体や既存共有flowは書き換えない。
依存を含む元状態を製品APIで取得し、公開設定だけを保存する。製品GETによる差分確認をPUT成功とは別に数える。
host書き込み成功は管理API方式なら0（該当なし）、native管理API成功数を別集計する。
復元では専用オブジェクトの存在/不存在、参照、元公開表現の完全一致を再確認する。秘密値を含むexportは読まない。

### SimpleSAMLphp

根拠: AUDITの`RequestedAuthnContextSelector.php`は`contexts`の数値key→identifier/sourceとdefaultを読み、ClassRef exactでは要求配列順に探索する。
一方minimum/maximum/betterは明示的に`throw new Exception('Not implemented.')`。
DeclRef-onlyはClassRefなしのdefault分岐へ入る。
保存コピー`build/acceptance/reference-20261004/ssp-nameid-omission-readonly-preflight/SimpleSAML_Module_saml_IdP_SAML2.php`の1167行以降はClassRefを設定し、当該生成箇所にDeclRef setterは確認できない。

|条件|設定経路の仮説|実機で要確認|
|---|---|---|
|minimum/better/maximum|`core:RequestedAuthnContextSelector`のnative contextsが候補。ただし保存版では未実装なので、このままでは実行前提を満たさない。|将来の稼働版の標準機能に実装があるか。別の標準sourceがあるなら保存ソース・読み戻しで根拠を追加する。なければNOT_VERIFIEDを維持。|
|先頭優先|既存の資格情報を含まないsource参照を使う専用selectorをnative authsources設定に置き、IdPのauth参照を向ける。numeric contextsのlow/highを固定する。|source選択・EXACT low/high成功、forward/reverse成功、製品が実際に読み込んだauth設定とselector/source/filterの全依存。|
|全caseのDeclRef|保存版に再現経路はない。|標準設定でDeclRefを生成できるか。ClassRefのみの部分実験は全case採用不可。|

`saml:AuthnContextClassRef`フィルターは固定ラベルであり、強度比較の実装ではない。
`ExpectedAuthnContextClassRef`はSP受信状態の検証であり、IdPの比較処理に転用しない。
独自PHPで応答を書き換えたり比較を実装して「製品自身の機能」とは扱わない。
authsources.php全体には資格情報があり得るため今回は読まない。将来も公開selector/source参照だけの分離ファイルを使い、秘密を含む元ファイルを証拠として保存しない。
hostのinode維持書込み後に製品PHPのConfiguration/実行中プロセスから有効値を投影して取得する。
同じmountのcatだけでは実効適用を証明できない。opcacheやmount不整合なら診断し、ログインを繰り返さない。

## コードと将来アダプターの契約

`keycloak_campaign.py`と`simplesamlphp_campaign.py`は`--dry-run --out ...`のみを公開する。
製品経路とoutbox経路が未確定なのでライブbackendは同梱しない。空欄の管理APIや任意shell hookで実機実行を装わない。
`campaign.py`は注入したdriverを使ってmembership確認→元状態捕捉→2群の設定適用→各通信前後read-back→finally復元→元状態照合を実装し、単体テストではメモリdriverだけを使う。
これは将来driverを接続するための準備コードであり、このCLIで実機キャンペーンが完走するという成果物ではない。

driverは`preflight(product, caseIds)`、`capture()`、`apply(mode, counters)`、`read_effective()`、`collect_existing_outbox(input)`、`restore(original, counters)`を実装する。
preflightは実Runのprofile/role/target/hash/case digest、署名定義互換性、native順序/DeclRef/全条件outboxの裏付けを確認する。
適用・復元の各実writeは`Counters.write(...)`で試行前に数え、host成功とnative成功を各完了時に数える。
1 applyが複数設定を書けば実writeごとに数える。1群=1writeとは決めない。
`read_effective`は製品が解釈した公開設定全依存のfingerprint。単なるhost hashでは不可。
`collect_existing_outbox`は既存のRun/actionを一度だけ消費し、Recorder request/responseと元bytes digestを返す。timeout/UNKNOWN_DELIVERYは止めて同じhandleを保持し、自動再送しない。
generic collectorのブラウザ表示・資格情報非保存・fresh/reuse方針を使う将来実装は別レビューする。g系が空actionのままならpreflightで保留する。

ログはsupplemental/unadoptedであり、正式receipt・Outcome・Verdictを生成しない。
将来の製品別receipt readerは元のRun、metadata、request fingerprint、署名・復号・宛先・issuer・Audience・SubjectConfirmation・RelayState・action/session/operationを独立に検証し、正負対照を再実行する。
別Runへの原本付け替えやcase挿入は不可。docs/82のIDP19.b専用source-Run bindingはg系には適用されない。
復元未確認なら採用不可。正式caseはoutcomeのみを返し、EvaluatorがlevelからVerdictへ変換する。

## 操作数の見積

1製品・再試行なし・全前提成立時の条件通信24、復元後M0 1、開始前M0が必要ならさらに1。
2製品では50〜52往復を計画上限の基準とする。全要求を独立ブラウザにすればログイン最大26回/製品、共有可能なら減るが未測定。
ログアウトは0回を予定し、fresh context閉鎖をログアウトと数えない。MFA、同意、IdP画面遷移のclick数は未測定。
明示的ログアウトが必要なら別途回数を追加する。管理者操作は自動化可能か未確認。
native設定はnormal/maximum/restoreの3群。write件数は依存オブジェクト数によるため未確定。
dry-runは1群1writeの場合の最小試行数3と、製品GET/read-back等の最低回数を出し、実測と区別する。
既知の保留を解消するまでは予定実機write/通信/ログインは全て0。探索のために先にログインしない。

## 実行方法（オフラインのみ）

```sh
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py --dry-run --out dev/reference-acceptance/sso01g/dry-run-keycloak
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/simplesamlphp_campaign.py --dry-run --out dev/reference-acceptance/sso01g/dry-run-simplesamlphp
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s dev/reference-acceptance/sso01g -p 'test_*.py' -v
```

出力先はこのsso01gディレクトリか指定jobディレクトリの子だけ。既存のdry-run JSONは上書きしない。
台帳・比較・inventoryの生成は実機採用後の別作業。今回の未検証観測数は変わらない。
