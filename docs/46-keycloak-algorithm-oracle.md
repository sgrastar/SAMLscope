# Keycloakへのアルゴリズム選択試験の展開

## 実行と判定

前回実装したMD05.ea／ebの共通判定を、Keycloakの製品コンソール取込経路でも実行した。元fixtureを`Import client`へアップロードし、保存画面遷移と管理API読戻しを照合してから、Suiteが発行した正常要求・無効署名対照を送る。各fixtureの後に作成クライアントを削除し、不存在を読み戻した。XMLからSuite独自の管理API属性への変換は行っていない。

<!--g1-literal--> Run `run_SMA5VXA5EDP001PKPR37ZR2893`で13条件すべての取込・正常SSO・後片付けが完了。Suiteが保存した原本とのバイト一致と、Run固定のIdP鍵によるResponse署名検証も13条件すべてで確認した。

| ケース | 判定 | 根拠・制限 |
|---|---|---|
| IIP-MD05-eb-idp-01 | Failed | Role側でSigningMethod／DigestMethodをそれぞれSHA384系に指定してEntity側と競合させた条件でも、検証済み応答はSHA256系を使用した。単一方式・逆向き競合条件も実行済み。 |
| IIP-MD05-ea-idp-01 | NOT_VERIFIED | 順序交換後もSHA256系を選ぶが、ローカルポリシー・SHA384の使用可能性は未確認。 |

この判定は試験したKeycloak参照環境のネイティブコンソール取込経路に限定する。新たな判定基準を製品ごとに追加せず、SimpleSAMLphpと同じ原本・要求応答相関・署名検証付きの判定を使用した。無効署名要求への無応答やキャンペーンの終了だけを違反の根拠にはしていない。

<!--g1-literal--> 今回の台帳は482→481観測、異なるケースIDは159のまま。前回のSimpleSAMLphpと合わせて483→481観測。元の594観測からは113観測が確定した。

## 証拠と監査

証拠は`build/acceptance/reference-20260918/keycloak-algorithm-metadata/`、準備確認と判定は`keycloak-algorithm-evaluation/`に保存した。取込時の結果は上書きせず、評価後の結果を別フォルダに保存した。

`native_algorithm_preparation.py`で各製品のネイティブ取込記録を検査する共通処理を追加した。Keycloakではfixture SHA-256、保存成功画面とクライアントDB ID、entityID読戻し、相関した正常フロー、削除後の不存在を必須とする。SimpleSAMLphpでは既存のパーサ出力ハッシュ・設定読戻し・復元を維持する。`verify_metadata_algorithm_outcomes.py`の検査を通った対象ケースだけを生成台帳へ採用した。

Javaコードと稼働イメージは前回の検証済み版を使用した。両製品の保存証拠による検査、台帳監査、G1生成一致・構造検証を実施。G2-30の既存署名差分は残っており、リリース完了の宣言ではない。

## 作業量

<!--g1-literal--> ネイティブUI取込13、クライアント作成13・削除13（製品設定書込26）、通常SSO試行13・無効署名対照試行13、Run作成1、preflight1、準備確認2。Docker build0、Suite再作成0、製品再起動0、本人操作0。自動操作はバックグラウンドのChromeで実施した。全クライアントの削除後読戻しを確認済み。

操作回数は`keycloak-algorithm-evaluation/operations.json`に保存した。共通判定を利用できたため、製品追加に伴う再配備は不要だった。
