# 追加試験と設定・操作コストの記録

この記録は2026-09-15の追加試験だけを計測対象にしています。それ以前の環境構築・試行の回数や時間は未計測であり、ゼロとは扱いません。既存Runに追加の証拠を集め、同じケース定義で判定の差分を比較しています。対象ケースを限定した前後比較です。

ユーザー本人の操作、エージェントが代行したブラウザ操作、API・ファイルによる設定変更を別々に数えます。設定書き込みは復元も含めて1回ずつ数え、サービス再読み込みは別計上します。ブラウザ操作はページを開く・項目入力・クリック・手動継続をそれぞれ1回と数え、自動リダイレクトは含めません。スクリプトによる代行は、設定作業自体の消滅を意味しません。

## 判定の変化

| 製品 | Not verified：前 | 後 | 減少 |
|---|---:|---:|---:|
| Keycloak | 12 | 8 | 4 |
| Shibboleth | 12 | 8 | 4 |
| SimpleSAMLphp | 6 | 6 | 0 |

上の差分は対象ケースに限定した前後比較です。対象外ケースの判定は変更していません。全件の未検証件数と製品別の再試験結果は [全件台帳](26-unverified-case-inventory.md) を参照してください。

この件数は製品・プロファイル・ケース単位の延べ観測数です。操作や設定の回数とは異なります。

## 作業量

| 製品 | 設定書き込み（復元含む） | サービス再読込 | 代行ブラウザ操作 | ユーザー本人の操作 |
|---|---:|---:|---:|---:|
| Keycloak | 1 | 0 | 0 | 0 |
| Shibboleth | 1 | 1 | 0 | 0 |
| SimpleSAMLphp | 0 | 0 | 0 | 0 |

補助接続コンテナの起動は0回です。一時スクリプトの誤りによる設定再試行も台帳に含め、製品の不具合とは扱いません。

Suiteのローカル検証環境の再起動は1回、転送コンテナの再起動は1回です。製品の設定操作とは別計上しています。

操作時間はツール呼び出しの実測時間またはスクリプト内の経過時間です。調査・判断・コード作成・呼び出し間の時間を含まず、人間が手作業した場合の所要時間としては使えません。未計測は「—」と表示します。

## 操作明細

| # | 製品 | 作業 | 実行手段 | 設定書込 | 再読込 | ブラウザ操作 | 実測秒 |
|---:|---|---|---|---:|---:|---:|---:|
| 1 | Keycloak | browser_sso_idp新Runで対象生成のEncryptedAssertionアルゴリズムを観測 | protocol_client | 0 | 0 | 0 | 832.6 | <!--g1-literal-->
| 2 | Shibboleth | browser_sso_idp新Runで対象生成のEncryptedAssertionアルゴリズムを観測 | protocol_client | 0 | 0 | 0 | 950.4 | <!--g1-literal-->
| 3 | SimpleSAMLphp | browser_sso_idp新Runで暗号化Assertionの有無を確認 | protocol_client | 0 | 0 | 0 | 169.2 | <!--g1-literal-->
| 4 | Keycloak | ecp_idp新RunでECP応答の暗号化アルゴリズムを観測（PAOS宛先を登録） | protocol_client | 1 | 0 | 0 | — | <!--g1-literal-->
| 5 | Keycloak | ecp_idpのプローブ失敗試行（正常系ログイン前） | protocol_client | 0 | 0 | 0 | 0.6 | <!--g1-literal-->
| 6 | Shibboleth | ecp_idp新RunでECP応答の暗号化アルゴリズムを観測（PAOS宛先を登録・再読込） | protocol_client | 1 | 1 | 0 | — | <!--g1-literal-->
| 7 | suite | 実装イメージをv20へ反映しSuite/転送コンテナを再作成 | docker | 0 | 0 | 0 | 6.0 | <!--g1-literal-->

## 判定が変わったケース

| 製品 | Profile | Test | 前 | 後 | 根拠コード |
|---|---|---|---|---|---|
| Keycloak | browser_sso_idp | `IIP-ALG04-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes256-gcm.decrypted` |
| Keycloak | browser_sso_idp | `IIP-ALG06-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep.decrypted` |
| Keycloak | ecp_idp | `IIP-ALG04-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes256-gcm.decrypted` |
| Keycloak | ecp_idp | `IIP-ALG06-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep.decrypted` |
| Shibboleth | browser_sso_idp | `IIP-ALG04-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes128-gcm.decrypted` |
| Shibboleth | browser_sso_idp | `IIP-ALG06-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep-mgf1p.decrypted` |
| Shibboleth | ecp_idp | `IIP-ALG04-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes128-gcm.decrypted` |
| Shibboleth | ecp_idp | `IIP-ALG06-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep-mgf1p.decrypted` |
## 対象と結果

対象は IIP-ALG04 / IIP-ALG06 の6ケース（Keycloak / Shibboleth / SimpleSAMLphp × browser_sso_idp / ecp_idp = 36観測）です。加えて、SSO/SLOの NormalFlow 判定で証拠を生成できないケース9件（SSO01-g/k/z/ep、SSO03-b、SSO05-a/a2、IDP17-n/u）を調査対象にしました。

実装した共通判定は、正常に相関した Response 内の EncryptedAssertion を Suite の Run 鍵で復号し、EncryptionMethod（ブロック暗号）、EncryptedKey の EncryptionMethod（鍵輸送）、DigestMethod、MGF を読むものです。公開メタデータのアルゴリズム名だけでは Success にしません。復号できない場合、暗号化Assertionがない場合、要求と異なるアルゴリズムだけの場合、4組合せの一部だけの場合は NOT_VERIFIED を維持します。ECP は outbox action による相関（SOAP 内の AuthnRequest ID を使う場合を含む）を補完しました。

実証により確定した Success は8観測です。

- Keycloak: `IIP-ALG04-b`（AES256-GCM）と `IIP-ALG06-b`（rsa-oaep）を browser_sso_idp と ecp_idp の両方で確認
- Shibboleth: `IIP-ALG04-a`（AES128-GCM）と `IIP-ALG06-a`（rsa-oaep-mgf1p）を browser_sso_idp と ecp_idp の両方で確認
- SimpleSAMLphp: 暗号化Assertionが browser_sso_idp の161ケースで0件のため確定なし。ECPは今回実行していません

未確定の理由は次のとおりです。

- Keycloak は AES128-GCM と rsa-oaep-mgf1p を生成せず、`IIP-ALG06-d` では MGF1-SHA256 を明示するため「MGF未指定の既定MGF1-SHA1」の証拠になりません。`IIP-ALG06-c` は4組合せのうち1つだけです
- Shibboleth は AES256-GCM と rsa-oaep（1.1）を生成せず、`IIP-ALG06-d` は rsa-oaep-mgf1p のため対象外、`IIP-ALG06-c` は1組合せだけです
- SimpleSAMLphp は暗号化Assertionを生成していません

## 製品の問題とSuiteの問題の区別

- 製品側: 必須アルゴリズムの生成が既定で観測できないこと自体は未検証であり、FAILにはしていません。アルゴリズムの選択が製品設定やメタデータ宣言で可能かは未確認です
- Suite側（本バッチで解消）: ALG04/06 に判定コードがなく `browser.oracle-unavailable` を返していた問題を、生成側の共通判定として実装しました。ECP の相関不足も補完しました
- Suite側（残る課題）: `IIP-ALG06-c` のように複数アルゴリズムを同一Runで要求するには、Suite SPメタデータでのアルゴリズム宣言または入力生成の設計が必要です

## SSO/SLO観測の調査結果

対象ケースと不足箇所は次のとおりです。いずれも判定コードはありますが、要求される証拠を実製品が生成しないため、判定は前後で変わっていません。

| ケースID | 製品・プロファイル | 不足している証拠 |
|---|---|---|
| `IIP-SSO01-g-idp-01`, `IIP-SSO01-z-idp-01` | 3製品 / browser_sso_idp | IdP起点（unsolicited）成功Response。Suiteに入力生成経路がない |
| `IIP-SSO01-ep-idp-01` | 3製品 / browser_sso_idp | major≠2へのVersionMismatchのSAML Response。現行経路は非SAMLエラーで終了 |
| `IIP-SSO01-k-idp-01` | 3製品 / browser_sso_idp | 受理された2つ以上の異なるACS宛Bearer確認。KeycloakはIDP12-aがFAILでindex指定を無視 |
| `IIP-SSO03-b-idp-01` | 3製品 / browser_sso_idp | POSTの2種類以上のエラー応答。SAMLエラーになるトリガーがis_passive 1種類のみ |
| `IIP-SSO05-a-idp-01`, `IIP-SSO05-a2-idp-01` | Keycloak以外 | persistent NameIDの要求・応答。Keycloakは既にPASS |
| `IIP-IDP17-n-idp-01`, `IIP-IDP17-u-idp-01` | 3製品 / single_logout_idp | 対象IdPが発行するLogoutRequest。target-initiated logoutの入力経路がない |

Suite側で補完できるのはECP相関（実装済み）です。unsolicited SSOとtarget-initiated logoutは対象製品側の起点操作が必要で、受信後の判定は既存コードが自動確定します。製品固有のURL・UIに依存するため、操作手順（ユーザー本人の操作）として分離します。単体テスト条件の追加は未検証の解消として数えていません。

## 検証範囲と証拠

ローカル検証は Runner の関連テストと API/Web テストをまとめて実行し、`EncryptionAlgorithmObservationTest` を含めて成功しています。G1生成文書一致と構造検証は別途実行しています。実製品の証拠は `build/acceptance/reference-20260915/algorithm-observation-batch/` に Run の result.json・report.html・transcript・操作ログ・比較結果を保存しています。このディレクトリはGit管理対象外です。

## 限界

- このバッチの完了は未検証0件の達成を意味しません。ALG04/06 の残りと SSO/SLO の観測不足は未解消です
- ECP の Run は ALG ケースが確定した時点で開始済みの未完了ケースを含みます。判定に使ったのは完了した ALG ケースの証拠だけです
- Shibboleth の PAOS 登録は署名を除去したローカル信頼ファイルを追加変更する形で、復元は実施していません。Keycloak はクライアントの redirectUris への追加のみです
