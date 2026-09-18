# 属性名・NameFormat生成能力の実証

承認済み`IIP-IDP01-a-idp-01`のCONFIG経路へ、製品が生成した属性を検査する判定を接続した。準備確認だけで合格にせず、同一RunのAuthnRequestと正常Responseの相関、ACS、固定した対象メタデータの証明書による署名検証、AssertionのIssuerを確認する。暗号化AssertionはRun鍵で復号し、内側に署名があれば検証する。属性値は診断へ保存しない。

<!--g1-literal--> 必須3条件はURN形式のName、非URI文字列のName、未知のNameFormat URI。試験用の名前は`urn:samlscope:test:attribute-name`と`SAMLscope arbitrary attribute`、NameFormatは`urn:samlscope:test:attribute-name-format`とした。各条件の欠落、署名改変、要求相関不一致、ACS不一致、不完全な履歴、重複記録、準備確認のみの場合はNOT_VERIFIEDとなることをテストした。

## 実機結果

| 製品 | 採用Run | 結果 |
|---|---|---|
| SimpleSAMLphp | `run_4GWY98RD670EAFJ3R8Q6V2MW52` | Success |
| Shibboleth | `run_8S5P9BVTX8CCQ770M2KHKXG5CM` | Success |

<!--g1-literal--> 両製品で、通常設定の対照では3条件が未観測、試験用SPに限定した属性設定後は全条件が観測された。原本のハッシュ、署名、復号結果、設定復元を別途照合し、正式結果を採用した。未検証は472→470観測、異なるケースIDは157のまま。Keycloakの同ケースは未検証を維持する。

SimpleSAMLphpではネイティブメタデータパーサーによる取込と、試験用SP限定のAttributeMap／NameFormat設定を分けて記録した。Shibbolethでは一時メタデータプロバイダー、属性resolverのencoder、対象SP限定のrelease policyを使用した。各設定の元と復元後のSHA-256一致を確認した。

Shibbolethの初回Run `run_GRQ3P0CQSEVDVKV84W0HTT10KE`では全条件が未観測だった。原因は属性レジストリの再読込不足で、失敗試行として保存した。inline encoderの追加・削除にはレジストリの再読込が必要であることは[公式のAttributeEncoder設定](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199504645)にも記載されている。実行スクリプトへ適用時・復元時の再読込を追加し、別Runで再試験した。

証拠は`build/acceptance/reference-20260918/`配下の`simplesamlphp-attribute-name-capability/`、`shibboleth-attribute-name-capability/`、`shibboleth-attribute-name-capability-registry/`。`VerifyAttributeCapability.java`は固定メタデータからResponse署名を再検証し、秘密鍵をコンテナ外へ出さず属性名と形式だけを抽出する。`verify_attribute_name_capability.py`が対照、原本ハッシュ、採用結果、復元記録を検査してから台帳へ反映する。

## 操作と検証

<!--g1-literal--> 製品設定書込等は計19回（SimpleSAMLphp 3、Shibboleth初回8、再試験8。一時ファイル削除2回を含む）。サービス再読込14回、通常SSO6回、Run作成・preflight・準備確認は各3回。Docker build1回、Suite／転送コンテナ再作成各1回、製品再起動0回、本人操作0回。初回失敗を費用から除外していない。

<!--g1-literal--> 対象Runnerテスト16件成功、API配布物ビルド成功。G1生成一致・構造46/46、台帳監査エラーなし。G2は既存の保護実装ソース署名差分G2-30により20/21で、再承認済みとは扱わない。

稼働イメージは`samlscope:reference-attribute-name-v41`、digestは`sha256:2cd23990e237f2ff8225e36254d8b953f58e68d973771209c49cd11ca0a7045a`。前版に今回のRunner成果物だけを重ね、作業ツリーにある別件のAPI変更は含めていない。
