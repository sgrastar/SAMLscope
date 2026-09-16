# Keycloakメタデータ観測経路の調査と分類

対象は`metadata_idp`プロファイルのKeycloak 91観測です。いずれも「ターゲットがSuiteのメタデータを消費して振る舞う」義務で、Suite側がメタデータ文書の内容を作り、ターゲットの消費結果を観測する構造です。一括して自己申告へ分類せず、実行経路の有無で3つに分けました。

<!--keycloak-metadata:start-->
対象一意一覧: 91ケースID（台帳のKeycloak metadata_idpは91観測、重複なし）。

| # | ケース | 義務 | 分類 | 理由コード |
|---:|---|---|---|---|
| 1 | `IIP-ALG01-a-idp-01` | IIP-ALG01.a | `evidence-form-mismatch` | `idp.signed-request.inconclusive` |
| 2 | `IIP-ALG02-a-idp-01` | IIP-ALG02.a | `evidence-form-mismatch` | `idp.signed-request.inconclusive` |
| 3 | `IIP-ALG03-a-idp-01` | IIP-ALG03.a | `suite-observation-gap` | `case.pending-interaction` |
| 4 | `IIP-ALG07-a-idp-01` | IIP-ALG07.a | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 5 | `IIP-EXT01-b-idp-01` | IIP-EXT01.b | `role-inapplicable` | `browser_fixture_partial` |
| 6 | `IIP-EXT01-c-idp-01` | IIP-EXT01.c | `role-inapplicable` | `browser_fixture_partial` |
| 7 | `IIP-G01-a-idp-01` | IIP-G01.a | `suite-observation-gap` | `browser_fixture_partial` |
| 8 | `IIP-MD01-a-idp-01` | IIP-MD01.a | `suite-observation-gap` | `case.pending-interaction` |
| 9 | `IIP-MD02-a-idp-01` | IIP-MD02.a | `suite-observation-gap` | `case.pending-interaction` |
| 10 | `IIP-MD02-b-idp-01` | IIP-MD02.b | `suite-observation-gap` | `case.pending-interaction` |
| 11 | `IIP-MD02-c-idp-01` | IIP-MD02.c | `suite-observation-gap` | `case.pending-interaction` |
| 12 | `IIP-MD02-d-idp-01` | IIP-MD02.d | `suite-observation-gap` | `case.pending-interaction` |
| 13 | `IIP-MD03-a-idp-01` | IIP-MD03.a | `suite-observation-gap` | `case.pending-interaction` |
| 14 | `IIP-MD03-b-idp-01` | IIP-MD03.b | `suite-observation-gap` | `case.pending-interaction` |
| 15 | `IIP-MD03-c-idp-01` | IIP-MD03.c | `suite-observation-gap` | `case.pending-interaction` |
| 16 | `IIP-MD03-d-idp-01` | IIP-MD03.d | `suite-observation-gap` | `case.pending-interaction` |
| 17 | `IIP-MD04-a-idp-01` | IIP-MD04.a | `suite-observation-gap` | `case.pending-interaction` |
| 18 | `IIP-MD04-b-idp-01` | IIP-MD04.b | `suite-observation-gap` | `case.pending-interaction` |
| 19 | `IIP-MD04-c-idp-01` | IIP-MD04.c | `suite-observation-gap` | `case.pending-interaction` |
| 20 | `IIP-MD05-a-idp-01` | IIP-MD05.a | `suite-observation-gap` | `case.pending-interaction` |
| 21 | `IIP-MD05-a1-idp-01` | IIP-MD05.a1 | `suite-observation-gap` | `case.pending-interaction` |
| 22 | `IIP-MD05-a2-idp-01` | IIP-MD05.a2 | `suite-observation-gap` | `case.pending-interaction` |
| 23 | `IIP-MD05-a3-idp-01` | IIP-MD05.a3 | `suite-observation-gap` | `case.pending-interaction` |
| 24 | `IIP-MD05-a4-idp-01` | IIP-MD05.a4 | `suite-observation-gap` | `case.pending-interaction` |
| 25 | `IIP-MD05-a5-idp-01` | IIP-MD05.a5 | `suite-observation-gap` | `case.pending-interaction` |
| 26 | `IIP-MD05-a8-idp-01` | IIP-MD05.a8 | `suite-observation-gap` | `case.pending-interaction` |
| 27 | `IIP-MD05-ac-idp-01` | IIP-MD05.ac | `suite-observation-gap` | `case.pending-interaction` |
| 28 | `IIP-MD05-ad-idp-01` | IIP-MD05.ad | `suite-observation-gap` | `case.pending-interaction` |
| 29 | `IIP-MD05-ae-idp-01` | IIP-MD05.ae | `suite-observation-gap` | `case.pending-interaction` |
| 30 | `IIP-MD05-af-idp-01` | IIP-MD05.af | `suite-observation-gap` | `case.pending-interaction` |
| 31 | `IIP-MD05-ah-idp-01` | IIP-MD05.ah | `suite-observation-gap` | `metadata.rsa-sha1.unobserved` |
| 32 | `IIP-MD05-am-idp-01` | IIP-MD05.am | `suite-observation-gap` | `case.pending-interaction` |
| 33 | `IIP-MD05-an-idp-01` | IIP-MD05.an | `suite-observation-gap` | `case.pending-interaction` |
| 34 | `IIP-MD05-ao-idp-01` | IIP-MD05.ao | `suite-observation-gap` | `case.pending-interaction` |
| 35 | `IIP-MD05-ap-idp-01` | IIP-MD05.ap | `suite-observation-gap` | `case.pending-interaction` |
| 36 | `IIP-MD05-aq-idp-01` | IIP-MD05.aq | `suite-observation-gap` | `case.pending-interaction` |
| 37 | `IIP-MD05-ar-idp-01` | IIP-MD05.ar | `suite-observation-gap` | `case.pending-interaction` |
| 38 | `IIP-MD05-as-idp-01` | IIP-MD05.as | `suite-observation-gap` | `case.pending-interaction` |
| 39 | `IIP-MD05-av-idp-01` | IIP-MD05.av | `suite-observation-gap` | `case.pending-interaction` |
| 40 | `IIP-MD05-aw-idp-01` | IIP-MD05.aw | `suite-observation-gap` | `case.pending-interaction` |
| 41 | `IIP-MD05-b-idp-01` | IIP-MD05.b | `suite-observation-gap` | `case.pending-interaction` |
| 42 | `IIP-MD05-c-idp-01` | IIP-MD05.c | `suite-observation-gap` | `case.pending-interaction` |
| 43 | `IIP-MD05-c1-idp-01` | IIP-MD05.c1 | `suite-observation-gap` | `case.pending-interaction` |
| 44 | `IIP-MD05-c2-idp-01` | IIP-MD05.c2 | `suite-observation-gap` | `case.pending-interaction` |
| 45 | `IIP-MD05-c3-idp-01` | IIP-MD05.c3 | `suite-observation-gap` | `case.pending-interaction` |
| 46 | `IIP-MD05-c5-idp-01` | IIP-MD05.c5 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 47 | `IIP-MD05-c6-idp-01` | IIP-MD05.c6 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 48 | `IIP-MD05-c7-idp-01` | IIP-MD05.c7 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 49 | `IIP-MD05-cd-idp-01` | IIP-MD05.cd | `suite-observation-gap` | `case.pending-interaction` |
| 50 | `IIP-MD05-d-idp-01` | IIP-MD05.d | `suite-observation-gap` | `case.pending-interaction` |
| 51 | `IIP-MD05-d1-idp-01` | IIP-MD05.d1 | `suite-observation-gap` | `case.pending-interaction` |
| 52 | `IIP-MD05-e-idp-01` | IIP-MD05.e | `suite-observation-gap` | `case.pending-interaction` |
| 53 | `IIP-MD05-e5-idp-01` | IIP-MD05.e5 | `suite-observation-gap` | `case.pending-interaction` |
| 54 | `IIP-MD05-e7-idp-01` | IIP-MD05.e7 | `suite-observation-gap` | `case.pending-interaction` |
| 55 | `IIP-MD05-e8-idp-01` | IIP-MD05.e8 | `suite-observation-gap` | `case.pending-interaction` |
| 56 | `IIP-MD05-e9-idp-01` | IIP-MD05.e9 | `suite-observation-gap` | `case.pending-interaction` |
| 57 | `IIP-MD05-ea-idp-01` | IIP-MD05.ea | `suite-observation-gap` | `case.pending-interaction` |
| 58 | `IIP-MD05-eb-idp-01` | IIP-MD05.eb | `suite-observation-gap` | `case.pending-interaction` |
| 59 | `IIP-MD05-f-idp-01` | IIP-MD05.f | `suite-observation-gap` | `case.pending-interaction` |
| 60 | `IIP-MD05-f5-idp-01` | IIP-MD05.f5 | `suite-observation-gap` | `browser_fixture_partial` |
| 61 | `IIP-MD05-f7-idp-01` | IIP-MD05.f7 | `feature-absent` | `case.pending-interaction` |
| 62 | `IIP-MD05-f8-idp-01` | IIP-MD05.f8 | `feature-absent` | `case.pending-interaction` |
| 63 | `IIP-MD05-f9-idp-01` | IIP-MD05.f9 | `feature-absent` | `case.pending-interaction` |
| 64 | `IIP-MD05-fa-idp-01` | IIP-MD05.fa | `feature-absent` | `case.pending-interaction` |
| 65 | `IIP-MD05-fb-idp-01` | IIP-MD05.fb | `feature-absent` | `case.pending-interaction` |
| 66 | `IIP-MD05-ff-idp-01` | IIP-MD05.ff | `suite-observation-gap` | `case.pending-interaction` |
| 67 | `IIP-MD05-fg-idp-01` | IIP-MD05.fg | `suite-observation-gap` | `browser_fixture_partial` |
| 68 | `IIP-MD05-fh-idp-01` | IIP-MD05.fh | `feature-absent` | `case.pending-interaction` |
| 69 | `IIP-MD05-fj-idp-01` | IIP-MD05.fj | `feature-absent` | `case.pending-interaction` |
| 70 | `IIP-MD05-g-idp-01` | IIP-MD05.g | `suite-observation-gap` | `case.pending-interaction` |
| 71 | `IIP-MD06-a-idp-01` | IIP-MD06.a | `suite-observation-gap` | `case.pending-interaction` |
| 72 | `IIP-MD06-a1-idp-01` | IIP-MD06.a1 | `suite-observation-gap` | `case.pending-interaction` |
| 73 | `IIP-MD06-a2-idp-01` | IIP-MD06.a2 | `suite-observation-gap` | `case.pending-interaction` |
| 74 | `IIP-MD06-a3-idp-01` | IIP-MD06.a3 | `suite-observation-gap` | `case.pending-interaction` |
| 75 | `IIP-MD06-a5-idp-01` | IIP-MD06.a5 | `suite-observation-gap` | `case.pending-interaction` |
| 76 | `IIP-MD06-a6-idp-01` | IIP-MD06.a6 | `suite-observation-gap` | `case.pending-interaction` |
| 77 | `IIP-MD06-a7-idp-01` | IIP-MD06.a7 | `suite-observation-gap` | `case.pending-interaction` |
| 78 | `IIP-MD06-a8-idp-01` | IIP-MD06.a8 | `suite-observation-gap` | `case.pending-interaction` |
| 79 | `IIP-MD06-a9-idp-01` | IIP-MD06.a9 | `suite-observation-gap` | `case.pending-interaction` |
| 80 | `IIP-MD06-ab-idp-01` | IIP-MD06.ab | `suite-observation-gap` | `case.pending-interaction` |
| 81 | `IIP-MD06-b-idp-01` | IIP-MD06.b | `suite-observation-gap` | `case.pending-interaction` |
| 82 | `IIP-MD06-c-idp-01` | IIP-MD06.c | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 83 | `IIP-MD07-a-idp-01` | IIP-MD07.a | `suite-observation-gap` | `case.pending-interaction` |
| 84 | `IIP-MD07-b-idp-01` | IIP-MD07.b | `suite-observation-gap` | `case.pending-interaction` |
| 85 | `IIP-MD09-a-idp-01` | IIP-MD09.a | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 86 | `IIP-MD09-b-idp-01` | IIP-MD09.b | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 87 | `IIP-MD11-a-idp-01` | IIP-MD11.a | `suite-observation-gap` | `case.pending-interaction` |
| 88 | `IIP-MD12-a-idp-01` | IIP-MD12.a | `suite-observation-gap` | `case.pending-interaction` |
| 89 | `IIP-MD12-b-idp-01` | IIP-MD12.b | `suite-observation-gap` | `case.pending-interaction` |
| 90 | `IIP-MD12-c-idp-01` | IIP-MD12.c | `suite-observation-gap` | `case.pending-interaction` |
| 91 | `IIP-MD12-d-idp-01` | IIP-MD12.d | `suite-observation-gap` | `case.pending-interaction` |

分類の合計: `evidence-form-mismatch` 2 / `feature-absent` 7 / `operator-attestation-available` 7 / `role-inapplicable` 2 / `suite-observation-gap` 73 = 91。

メタデータ分類の合計は `suite-observation-gap` 73 + `operator-attestation-available` 7 + `feature-absent` 7 = 87で、残り4件は同プロファイル内の非メタデータケース（`role-inapplicable` 2 = `IIP-EXT01-b/c`、`evidence-form-mismatch` 2 = `IIP-ALG01/02`）です。

不存在が未確認の61ケースは`suite-observation-gap`へ移しました（`absence_basis=not-confirmed-investigated-path`）。`feature-absent`の7件はmdui公開要素で、Suite自身が取得した対象公開メタデータで不存在を確認済みです。`IIP-MD05.aw`は取込観測側（`suite-observation-gap`）にのみ属し、旧分類の重複は解消しています。
<!--keycloak-metadata:end-->

## 0. 件数の再集計

台帳のKeycloak `metadata_idp`は**91観測（91ケースID、重複なし）**です。内訳は`IIP-MD*`が84、非MD（`IIP-ALG01/02/03/07`、`IIP-EXT01-b/c`、`IIP-G01-a`）が7です。基準台帳（546観測時点）では92（MD 85）で、`IIP-MD05-fi`の1件が以前の追加実証で解決済みのため91になっています。87は現在の一意な一覧からは再現できず、MD総数84（基準時85）との差はこの解決済み1件と非MD 7件の区分によるものです。分類は次の一意な集合で行い、重複はありません（`IIP-MD05.aw`は取込観測側にのみ属します）。

## 1. 実機で確認したKeycloakの能力

管理APIで確認した事実（`build/acceptance/reference-20260915/slo-oracle/keycloak-metadata-probe.json`）:

- SAMLクライアントは明示フィールドで構成されます。`saml_assertion_consumer_url_post/redirect`、`saml_single_logout_service_url_*`、`saml.signing.certificate`、`saml.encryption.certificate`、`saml_name_id_format`、`saml.client.signature`等が対応します。
- **メタデータURLや更新間隔の属性は存在しません**。実行時にSuiteのメタデータを取得・再取得する経路はありません。
- **サーバー側のメタデータ取込APIも存在しません**（`client-descriptions`・`clients/import`は404）。管理コンソールの取込はブラウザ側でXMLを解析し、クライアント表現を作成します。
- 署名用証明書は**クライアントごとに1つ**です（`saml.signing.certificate`単一）。同一用途の複数鍵は表現できません。

## 2. 3分類

### (a) 調査した経路では能力を確認できない（feature-absent）

実行時取得・再取得、文書の有効期限、文書署名の検証、複数文書の集約に対応する属性やAPIは、**調査した経路（管理APIの属性一覧、サーバー側取込APIの有無、単一証明書モデル）では確認できませんでした**。不存在の確認は未完了であるため、分類は事実に合わせて`suite-observation-gap`とし（`feature-absent`は使用しません）、製品自身の取込経路（管理コンソールのメタデータ取込）での再確認を次の作業とします。台帳の`absence_basis`は`not-confirmed-investigated-path`です。

調査経路で確認できない集合（`_KEYCLOAK_METADATA_FEATURE_ABSENT`）: `IIP-MD01.a`、`IIP-MD02.a/b/c/d`、`IIP-MD03.a/b/c/d`、`IIP-MD04.a/b/c`、`IIP-MD05.a/a1/a2/a3/a5/a8/ac/ad/ae/af/ah/am/an/ao/ap/aq/ar/as/b/c/c2/c3/cd/d/d1/e/e5/e7/e8/e9/ea/eb/g`、`IIP-MD06.a1/a2/a3/a6/a7/a9/ab/b`、`IIP-MD07.a`。`IIP-MD05.aw`は含みません（取込観測側にのみ属します）。

### (b) 製品自身の取込経路で観測する（suite-observation-gap。不存在が未確認の61件を含む）

**SuiteがXMLを解析して管理API属性へ変換する方式は、製品のメタデータ解釈能力の証明に使いません。** 製品自身の取込経路（管理コンソールのメタデータ取込）へ元のfixtureを渡し、その後の挙動（署名検証、鍵選択、ACS選択、証明書受理）を観測します。属性の直接設定で検証できる義務は、承認済み定義に照らして別途限定します。fixtureの識別、取込結果、復元（試験用クライアントの削除）を記録し、取込成功だけをSuccessにはしません。現時点で経路・oracleとも未実装のため未確定です。

対象: `IIP-MD05.a4`（単一EntityDescriptorの受入）、`IIP-MD05.av`（isDefault ACS）、`IIP-MD05.aw`（use=signing鍵での署名検証）、`IIP-MD05.c1`（ロール別の端点・鍵解決）、`IIP-MD06.a`（メタデータのみでのプロビジョニング）、`IIP-MD06.a5/a8`（メタデータ鍵と実行時鍵の同一性）、`IIP-MD07.b`（メタデータ外鍵での署名拒否）、`IIP-MD11.a`（use属性なし鍵）、`IIP-MD12.a/b/c/d`（証明書の有効期間・署名方式・subject）。加えて(a)の61件も、不存在が未確認のため(b)の実行経路で確認する対象として分類しています（一覧は上の生成表を参照）。

### (c) 公開・運用証拠が必要（operator-attestation-available）

鍵ロールオーバーの公開履歴、失効鍵の扱い、Trust設定（CA取込等）の要否、アルゴリズム公開の生成方法は、実行時のプロトコル観測では確認できません。運用者証言（ケースごとに1回答）で確認する範囲です。

対象: `IIP-MD05.c5/c6/c7`、`IIP-MD06.c`、`IIP-MD09.a/b`。

## 3. 製品自身の取込経路の実装（コードで検証済み）

管理コンソールのメタデータ取込をPlaywrightで自動化し、**元のfixtureファイル**を製品自身の取込経路へ渡す経路を実装しました（`dev/keycloak/console_import.mjs`、実行に`npm i playwright`が必要）。SuiteによるXML→属性変換は使いません。

検証できたこと:
- コンソールの「Import client」がSuiteのSPメタデータ文書を受け付け、クライアントを作成しました。**クリックと保存成功を分離**し、成功シグナル（クライアント設定ページへの遷移）と**管理APIの読み戻し**（属性・証明書の存在）を照合しています。固定待機だけに依存しません。
- **1つの試験記録**として関連付けています: fixture識別（パス・SHA-256・entityID）、作成クライアント（DB ID・clientId）、取込結果（UI表示・API読み戻し）、任意の後続フロー（`--verify-command`）、削除/復元の読み戻し検証（`--delete`）。
- スクリプトの終了状態を整備しました。検証済みのときだけ`IMPORT VERIFIED`で終了コード0、失敗時は`IMPORT FAILED`と`status=failure`を記録して終了コード1です（成功に見える出力を出しません）。成功例と2種類の失敗例（entityIDなし、メタデータ拒否）で確認済みです。
- 同じclientIdの既存クライアントは取込で再作成されました（クライアントDB IDが変化）。既存属性は保持され、後続Runで使うSLO Redirect端点を再適用して復元を確認しました（`console-import/restore.json`）。
- 取込成功はSuccessの根拠にしません。以後は取込後にプロトコルフローを実行し、署名検証・鍵選択・証明書受理の実挙動で判定します。

## 4. 未確定を残す理由と次の作業

(b)の取込観測は、取込経路（実装済み）に加えて、取込後の挙動観測（署名検証・鍵選択・ACS選択）をoracleとして実装する必要があります。次の実装単位は、取込済みクライアントに対するSSO/署名フローの観測を`docs/05`のインターフェースに沿って追加し、MD05.a4/av/aw・MD12系から着手します。分類はVerdictを変えず、`docs/26`の診断へ反映しています。
