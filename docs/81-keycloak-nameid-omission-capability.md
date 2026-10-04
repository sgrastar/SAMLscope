# Keycloak NameID 省略能力の参照実装監査

`IIP-IDP11-a-idp-01` は、IdP が `Subject` 内に `NameID` のない Assertion を生成できるという承認済みの CONFIG / MUST ケースである。`configuration_failure_semantics: normative_capability` のため、実装にその構成能力がないと立証された場合だけ `capability_absent` を製品 FAIL として扱う。未設定・設定権限不足・根拠不足を FAIL にしない。

<!--g1-literal--> 対象は固定イメージ `sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067` の Keycloak 26.7.2、`browser_sso_idp` の Run `run_P57XA0ZDWHSVWX8PNW01MXSVT7` に限定する。証拠は `build/acceptance/reference-20260930/keycloak-nameid-omission-probe-v2/` に保存した。

管理 UI の SAML NameID Format は `username`、`email`、`transient`、`persistent` を表示する。管理 API は任意文字列の保存を許すが、実行時 `SamlClient.getNameIDFormat()` は未知値を `unspecified` に変換する。インストール済み NameID mapper は user attribute mapper のみで、値を返せない場合、`SamlProtocol.authenticated()` は `STATUS_INVALID_NAMEIDPOLICY` エラーを返す。値があれば `SAML2Response.createResponseType()` が `Subject` に `NameIDType` を置く。後段の応答 mapper は audience と AuthnContext のみを変更する。さらに後段の `SamlAuthenticationPreprocessor` SPI は存在するが、このイメージには実装 provider がない。client policy executor と custom provider の経路も監査した。

<!--g1-literal--> 全 471 個の実行時 JAR は live SHA-256 と保存コピーが一致する。管理 API の SAML mapper schema は 14 件。独立 verifier は全 JAR を再走査し、実装クラス、service 登録、関連 bytecode、UI アセット、管理 API、client policy inventory を照合する。単なる UI 文言検索から能力欠如を推定していない。

一時 SAML client を作成し、同じ Suite Run で通常、未知 format `none`、存在しない user attribute を指定した NameID mapper、復元後の順で SSO を実行した。通常・未知 format・復元後は、署名済み Success Assertion の `Subject/NameID` が各原本に存在した。値欠落 mapper は、署名済み Responder と Assertion 不在になった。要求・応答相関、元メタデータ署名鍵、Response と Assertion の署名、原本 hash を独立検証した。client は mapper を明示削除してから元設定を読戻し、最後に client 自体を削除して不在を確認した。人手操作はなかった。

最初の試行 `keycloak-nameid-omission-probe-v1/` では、client `PUT` だけでは protocol mapper が削除されないことが判明した。したがって見かけ上の「復元後」応答は Responder だった。この失敗を保持し、v2 では mapper 専用 DELETE と設定の完全一致 read-back を追加した。v1 の一時 client も削除済みであり、v1 の「復元後」応答を対照に採用していない。

<!--g1-literal--> 独立 verifier `verify_keycloak_nameid_omission_absence.py` が通過し、7 種の一時コピー改変証拠（JAR hash/count、custom provider、null mapper 応答、baseline NameID、client 残存、mapper inventory）はすべて予期した理由で拒否された。その後、Suite の CONFIG event から当該ケースのみ `VIOLATED` / `FAIL` / `capability_absent` が生成された。生成器は verifier の再実行を通じて比較表へ接続する。別製品、ECP、将来の Keycloak 版へ推定しない。
