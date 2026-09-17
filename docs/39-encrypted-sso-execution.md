# SimpleSAMLphp暗号化SSOの実行経路と不足理由

## 今回の到達点

SimpleSAMLphp自身のネイティブメタデータ取込を使い、試験用SPだけに `assertion.encryption=true` を設定して、通常SSOの暗号化Assertionを生成・受信・復号する経路を追加した。設定投入、読み戻し、待機、正常SSO、Suite評価、原本保存、元設定への復元を自動化した。

<!--g1-literal--> 新たなVerdict確定は0件。未検証は485観測・159ケースIDを維持する。既に確定済みのrsa-oaep-mgf1pを再確認したことは削減へ重複計上しない。残る暗号アルゴリズム5観測の「自動判定なし」という古い分類を、必要な生成アルゴリズムの追加観測不足へ更新した。

## 実装

- `dev/simplesamlphp/import_metadata_batch.py` に明示的な暗号化有効化オプションを追加した。元XMLの解釈は製品パーサーに委ね、追加設定であることを別フィールドへ記録する。
- `dev/simplesamlphp/normal_encrypted_sso.py` は通常のSuiteメタデータと通常SSOを使う。メタデータ試験の専用鍵・専用URLの応答を、通常フローの証拠として転用しない。
- 暗号アルゴリズムのEvidenceStatusに、暗号化Assertion数、復号成功数、実際の暗号アルゴリズムを固定トークンで出す。未受信・復号不能・復号済みだが要求アルゴリズム未観測を区別する。必要条件が満たされていなければreadyはfalseのまま。
- 読取時にRun一致と要求より後の応答であることを確認する。別Runや要求前の証拠を混在させない。

## 実測と制限

| 経路 | 観測 | 判定への使用 |
|---|---|---|
| メタデータfixtureキャンペーン | 暗号化Assertionを受信 | 専用鍵・専用URLなので通常SSO用の暗号アルゴリズム判定には使わない |
| 通常SSO | normalFlowAccepted、暗号化Assertion、Run鍵による復号 | 既存の暗号アルゴリズムオラクルが使用 |
| 生成されたデータ暗号 | AES128-CBC | AES128-GCM／AES256-GCMの証拠にはしない |
| 生成された鍵輸送 | rsa-oaep-mgf1p | rsa-oaep(1.1)や全Digest/MGF組合せの証拠にはしない |

稼働中の製品ソースで、SP側設定を優先するassertion.encryptionの選択と公開鍵経路のrsa-oaep-mgf1p指定を確認し、証拠フォルダーに保存した。別の共有鍵経路も存在するため、今回の既定経路だけを根拠に製品全体のGCM非対応を断定しない。共有鍵を使う生成・Suite復号の対応や、他の許容される生成設定の検証が残る。

通常SSOの生結果にある別義務の判定は一括採用していない。特にprincipalの意味的対応など、追加条件の充足をこの暗号化試験だけから推測しない。

## 証拠

基点は `build/acceptance/reference-20260918/`。

| 試験 | Run | フォルダー |
|---|---|---|
| fixture経路 | run_CDE4QVH4TBJV6R8FYCWFKEW2CQ | simplesamlphp-encrypted-assertions |
| 通常SSO経路 | run_XV8DY232PX2JEHS9QQ3EHEYWTY | simplesamlphp-normal-encrypted-sso |

`verify_encrypted_sso_diagnosis.py` は元fixture、製品パーサー出力、暗号化設定の反映、復元、応答原本のハッシュ・暗号方式、復号済みのSuite判定、未確定ケースの診断を照合する。診断の再取得は既存のRun証拠を利用し、製品設定やSSOをやり直さない。

稼働イメージは `samlscope:reference-encryption-diagnostics-v29`、digestは `sha256:dcf9a7071180aaf66569e54bfb28d50172af71f038bd0247729ce95753ab8b48`。

## コストと検証

<!--g1-literal--> 製品ネイティブ取込3、設定書込7（fixture経路の投入・復元4とfinally復元1、通常経路の投入・復元2）、Run作成2、preflight2、Docker build1、Suite／転送コンテナ再作成各1。本人操作0、製品再起動0。元設定のSHA-256一致で復元確認済み。

実行経路と診断をまとめた後にRunner全体を回帰検証し、成功した。G1生成一致・構造検証を実施。G2の既存署名差分は引き続き未解消として扱う。
