# 対象起点メッセージの受入記録（2026-09-15）

対象は、Suiteから直接起動できないIdP起点SSOとtarget-initiated logoutの証拠生成です。基準コミットは `f653393413204cf9549e4175695ddc09f9598d56` で、ALG04/06の生成側判定バッチ（`eec07cdd`）の後続です。実装・検証・検証環境への反映はローカルで行い、公開やpushはしていません。

## 実装

- `TargetInitiatedIntents`: 単一使用の準備intent（`UNSOLICITED_SSO` / `TARGET_LOGOUT`）。Run単位の消費、TTL、プラン内で一意なRunの解決、曖昧時の拒否、プロセス再起動での失効。
- `SpPeerService`: 準備済みintentがある場合だけ、RelayStateなしのunsolicited Response、または単一待機Runへのプラン解決を受け付けます。Issuer・Destination・Success・単一使用を検証し、未準備では従来どおり拒否します。
- `SloPeerService`: Run相関のないtarget-initiated LogoutRequestを、プラン内で唯一の`TARGET_LOGOUT` intentがある場合だけ受け付けます。Issuerを検証し、intentを消費します。
- API: `GET/POST /api/runs/{id}/target-initiated`（状態・準備、no-store、既存のRun認可・CSRF）。
- 画面: `browser_sso_idp`と`single_logout_idp`のRun workspaceに準備パネルとRelayState・待機状態を表示。
- `LogoutBrowserEvidenceTestCase`: 完了後のNOT_VERIFIEDを、新しいTranscript証拠が付いた場合に再評価できるようにしました。
- SLO判定の復号: 暗号化Assertion内のNameID/SessionIndexをRun鍵で復号してから照合します（暗号化されたログイン応答でもIDP17-n/uが判定可能）。
- 正常系観測の分離: DOCTYPE付きの敵対的**送信要求**が正常系観測全体を停止させないようにし、解析不能な**受信応答**は従来どおり不確定として扱います。

## 実証結果

| ケース | 製品 | 結果 | 根拠 |
|---|---|---|---|
| `IIP-SSO01-g` | Keycloak / Shibboleth | Success | SP起点とIdP起点の両方の成功応答にAssertionがある |
| `IIP-SSO01-z` | Keycloak / Shibboleth | Warning | unsolicited成功応答を観測 |
| `IIP-SSO01-k` | Shibboleth | Success | 異なるACS宛のBearer確認（レシピエントと期限） |
| `IIP-IDP17-j/k/l/m` | Shibboleth | Success | 対象発行LogoutRequestのIssuer数・値・形式・署名 |
| `IIP-IDP17-t` | Shibboleth | Failed (Product) | 対象発行LogoutRequestのNotOnOrAfterがセッション失効より前（承認済みの既知FAIL） |
| `IIP-IDP17-n` | Shibboleth | Not verified | 復号しても識別子のstrong matchを証明できない |
| `IIP-IDP17-u` | Shibboleth | Not verified | NotOnOrAfterとセッション失効の対応を証明できない |

未検証は559から**546**へ減少しました（異なるケースID 180→179）。内訳は、browser_sso_idpの6観測（Keycloak: ALG04.a/ALG06.a/ALG06.c/ALG06.d/SSO01-g/SSO01-z）と3観測（Shibboleth: SSO01-g/k/z）、ecp_idpの2観測（Keycloak: ALG04.a/ALG06.a、クライアント属性をAES128-GCM + rsa-oaep-mgf1pへ変更してPAOS宛先を登録し、観測後に既定値へ復元）、SimpleSAMLphpの2観測（browser/ECPのALG06.a: Suite SPメタデータに`assertion.encryption=true`を設定してRSA-OAEP-MGF1Pの鍵輸送を観測。内容暗号はCBCのままのためALG04は未検証を維持し、設定は復元）です。ShibbolethのIDP17-j/k/l/m/tは台帳の未検証集合に含まれていなかったため、解消数には算入していません。

ShibbolethのAES256-GCM + rsa-oaep(1.1)は、カスタムEncryptionConfigurationをglobal.xmlへ追加して再起動する試行を行いましたが、Tomcatの多重起動で新旧プロセスが競合し、観測は既定のAES128-GCMのままでした。プロセスを整理して設定を復元し、IdPがメタデータ200で稼働することを確認済みです。この経路の追加観測は計上していません。

## 製品の問題とSuiteの問題の区別

- 製品側（未検証のまま維持）:
  - Keycloak: IdP起点SSOは管理APIのURL名登録と`RelayState`で起動でき、`IIP-SSO01-g/z`に成功しました。一方、target-initiated logoutは管理APIのセッション終了とOIDCログアウトのどちらでもSAML LogoutRequestがSuiteへ到達せず、未検証のままです。クライアントのSLO URLをコンテナ到達可能なSOAP URLへ変更して試行しましたが到達しませんでした。
  - SimpleSAMLphp: IdP起点SSOの開始URLは提供されておらず（AuthnRequestを必要とする実装）、target-initiated logoutもSuiteへのLogoutRequestに到達しませんでした。
- Suite側（本バッチで解消）: 対象起点メッセージの受信相関、単一使用intent、完了後NOT_VERIFIEDの再評価、暗号化Assertionの復号、DOCTYPE要求による観測停止。
- 残るSuite側の課題: Keycloakのtarget-initiated logout到達性（製品側のログアウト伝播を切り分ける必要）、SimpleSAMLphpのIdP起点経路の有無確認。

## 操作量

計測は2026-09-15の本バッチのみです。Dockerの再起動が1回発生し、Suite/転送コンテナの再作成は実装修正ごとに実施しました（約6回、うち初回のフルビルドはDocker Desktop再起動に伴い破損したため不採用）。製品設定は次のとおりです。

| 製品 | 設定書き込み | 復元 | 再読込 | 内容 |
|---|---:|---:|---:|---|
| Keycloak | 11 | 2 | 0 | 暗号アルゴリズム属性のフェーズ設定・既定値復元・IdP起点URL名・SOAP SLO URL |
| Shibboleth | 0 | 0 | 0 | Tomcat再起動のみ（Docker再起動後） |
| SimpleSAMLphp | 0 | 0 | 0 | なし |

Keycloakの暗号属性は個別削除が反映されないため、事前観測と同じ既定値（AES256-GCM / rsa-oaep / sha256 / mgf1sha256）を明示して復元しました。`saml_idp_initiated_sso_url_name`とSOAP SLO URLは残置し、目的と現在値を`build/acceptance/reference-20260915/peer-intent/keycloak/`のクライアント記録に保存しています。ユーザー本人の操作は0回です。

## 証拠と限界

Runのresult.json・report.html・transcript・ログ・設定バックアップは `build/acceptance/reference-20260915/peer-intent/` に保存しています（Git管理対象外）。G2-30は未解消のままで、この作業は独立承認ではありません。[全件台帳](26-unverified-case-inventory.md)と[比較表](23-reference-test-comparison.md)を生成器で更新しています。
