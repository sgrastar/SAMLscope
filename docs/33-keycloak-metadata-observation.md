# Keycloakメタデータ観測経路の調査と分類

対象は`metadata_idp`プロファイルのKeycloak 91観測です。いずれも「ターゲットがSuiteのメタデータを消費して振る舞う」義務で、Suite側がメタデータ文書の内容を作り、ターゲットの消費結果を観測する構造です。一括して自己申告へ分類せず、実行経路の有無で3つに分けました。

## 1. 実機で確認したKeycloakの能力

管理APIで確認した事実（`build/acceptance/reference-20260915/slo-oracle/keycloak-metadata-probe.json`）:

- SAMLクライアントは明示フィールドで構成されます。`saml_assertion_consumer_url_post/redirect`、`saml_single_logout_service_url_*`、`saml.signing.certificate`、`saml.encryption.certificate`、`saml_name_id_format`、`saml.client.signature`等が対応します。
- **メタデータURLや更新間隔の属性は存在しません**。実行時にSuiteのメタデータを取得・再取得する経路はありません。
- **サーバー側のメタデータ取込APIも存在しません**（`client-descriptions`・`clients/import`は404）。管理コンソールの取込はブラウザ側でXMLを解析し、クライアント表現を作成します。
- 署名用証明書は**クライアントごとに1つ**です（`saml.signing.certificate`単一）。同一用途の複数鍵は表現できません。

## 2. 3分類

### (a) 製品が機能として持たない（feature-absent）

実行時取得・再取得、文書の有効期限、文書署名の検証、複数文書の集約はKeycloakのSAMLクライアントモデルに存在しません。取込は管理者の一度きりの操作で、文書の署名・validUntil・EntitiesDescriptor階層・AffiliationDescriptorは解釈対象外です。また署名方式のメタデータ駆動ネゴシエーション（`md:SigningMethod`等）と複数署名鍵の併用も表現できません。

対象: `IIP-MD01.a`、`IIP-MD02.a/b/c/d`、`IIP-MD03.a/b/c/d`、`IIP-MD04.a/b/c`、`IIP-MD05.a/a1/a2/a3/a5/a8/ac/ad/ae/af/ah/am/an/ao/ap/aq/ar/as/aw/b/c/c2/c3/cd/d/d1/e/e5/e7/e8/e9/ea/eb/g`、`IIP-MD06.a1/a2/a3/a6/a7/a9/ab/b`、`IIP-MD07.a`、`IIP-MD05.f7〜fj`（mduiは既分類）。

### (b) 取込経路を実装すれば観測できる（suite-observation-gap）

管理APIでクライアントを作成・更新し、プロトコルフローで挙動を観測できるものです。取込の成功だけをSuccessとはせず、**実際の製品挙動**（署名検証、鍵選択、ACS選択、証明書受理）を判定に使います。fixtureの識別（メタデータ項目→クライアント属性の対応）、取込結果、復元（試験用クライアントの削除）を記録します。現時点でoracle未実装のため未確定です。

対象: `IIP-MD05.a4`（単一EntityDescriptorの受入）、`IIP-MD05.av`（isDefault ACS）、`IIP-MD05.aw`（use=signing鍵での署名検証）、`IIP-MD05.c1`（ロール別の端点・鍵解決）、`IIP-MD06.a`（メタデータのみでのプロビジョニング）、`IIP-MD06.a5/a8`（メタデータ鍵と実行時鍵の同一性）、`IIP-MD07.b`（メタデータ外鍵での署名拒否）、`IIP-MD11.a`（use属性なし鍵）、`IIP-MD12.a/b/c/d`（証明書の有効期間・署名方式・subject）。

### (c) 公開・運用証拠が必要（operator-attestation-available）

鍵ロールオーバーの公開履歴、失効鍵の扱い、Trust設定（CA取込等）の要否、アルゴリズム公開の生成方法は、実行時のプロトコル観測では確認できません。運用者証言（ケースごとに1回答）で確認する範囲です。

対象: `IIP-MD05.c5/c6/c7`、`IIP-MD06.c`、`IIP-MD09.a/b`。

## 3. 未確定を残す理由と次の作業

(b)の取込観測は、メタデータ項目→クライアント属性の写像と、その後の挙動観測（署名検証・鍵選択・ACS選択）をoracleとして実装する必要があります。取込が成功しても意味処理のSuccessにはしません。次の実装単位は、`MetadataFixtureObservationTestCase`系の既存観測と管理API取込を組み合わせ、MD05.a4/av/aw・MD12系から着手します。分類はVerdictを変えず、`docs/26`の診断へ反映しています。
