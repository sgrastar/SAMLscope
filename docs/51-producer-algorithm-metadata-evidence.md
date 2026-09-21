# 暗号方式生成能力の条件別証拠とMGF省略の監査

## 実装

ALG04/06のブラウザ証拠判定へ`MetadataEncryptionAlgorithmEvidence`を接続した。既存の通常SSO証拠に加え、同じRun内のメタデータキャンペーンで得た署名付き応答を使用できる。元メタデータ・取得記録・送信要求・署名応答の相関は共通コレクターで検証する。

`MetadataEncryptionProof`へ鍵照合・Assertion復号・内包署名検証を抽出し、MD05.e8と共有した。fixture別の秘密鍵と元メタデータ内の公開鍵の一致を検査する。復号平文の型・Issuerを確認し、証拠不足・異なる鍵・署名不正・曖昧な構造は確定に使わない。秘密鍵と復号平文は保存しない。

生成能力を判定するため、広告内容だけではSuccessにならない。実際に生成された暗号方式・OAEPパラメーターを復号成立後に観測する。メタデータの消費義務への適合を、この生成能力判定から推論しない。

Shibboleth自動実行スクリプトにブラウザSSOプロファイルを追加した。メタデータ用Runの結果を別プロファイルへ流用せず、該当プロファイルの新しいRunで試験する。

## 実機結果

Run `run_0TMTHFWK5HEM14WFNJ10RD5D1X`、Plan `plan_989BVXEKC7VCVDY56VR4H5SQJR`で実行した。

<!--g1-literal--> 対照、AES128/256 GCM、旧／新RSA-OAEP×SHA1/SHA256、MGF省略広告の計8条件を実行した。元fixtureの取込・署名検証・対応鍵復号・別鍵拒否を全条件で確認し、製品設定を復元した。

| ケース | 今回の正式結果 | 確認した事実 |
|---|---|---|
| IIP-ALG04-b-idp-01 | PASS | AES256-GCMの生成と復号 |
| IIP-ALG06-b-idp-01 | PASS | rsa-oaepの生成と復号 |
| IIP-ALG06-c-idp-01 | PASS | 両OAEP方式とSHA1/SHA256の全組合せ |
| IIP-ALG06-d-idp-01 | NOT_VERIFIED | 応答はMGFを明示し、省略形の証拠がない |

ALG04.aとALG06.aもPASSだが既に確定していたため新規解消には数えない。原本は`build/acceptance/reference-20260918/shibboleth-producer-algorithms/`、正式評価結果は`shibboleth-producer-evaluation/`へ保存した。`verify_producer_algorithms.py`でプロファイル、原本、署名、復号、対照、全組合せ、ケースの証拠参照を検査してから採用する。

## MGF省略の判定修正と旧確定の撤回

承認済みALG06.dのvariantはMGFを明示しない既定動作を対象にしている。旧コードはMGF1-SHA1の明示指定もSuccessにしていた。判定を省略形に限定し、同じSHA1でも明示指定だけでは未検証になる対照を追加した。G1/G2の承認済み定義は変更していない。

Keycloakの旧Run `run_6AD6T3VS8H87WQQBB1T2DEB3MX`を監査した。採用済みALG06.dの原本応答では、rsa-oaepのMGFは常に明示されていた。MGF要素のない応答は旧rsa-oaep-mgf1pであり、この条件を満たさない。旧確定は現在の比較表・未検証台帳への採用対象から外し、未検証へ戻した。過去Runの保存結果は監査のため保持しており、正しい確定として再採用しない。

監査原本とハッシュは`keycloak-default-mgf-audit/`に保存した。台帳生成時に`verify_default_mgf_withdrawal`が、旧結果の全採用応答とMGF原本を検査する。単に既存の結果ラベルを書き換えたものではない。

<!--g1-literal--> 新規PASS3件、旧確定撤回1件で、未検証は474から472観測へ減少した。異なるケースIDは157のまま。製品FAILの追加はない。

## 検証・操作負担

暗号方式の正負対照、全組合せ不足、明示MGFと省略の区別、署名・原本・条件別鍵の相関、前回の共通部分選択判定の回帰をまとめて検証した。個別観測ごとの全テスト反復は行っていない。G1生成一致・構造検証と台帳監査も実施した。G2の既存保護ソース署名差分は残る。

<!--g1-literal--> メタデータ書込8、読込先設定の投入・復元2、一時ファイル削除1、製品書込計11。サービス再読込9、正常SSO8、無効署名試行8、Run作成・preflight各1。Docker build1、Suite／転送コンテナ再作成各1、製品再起動0、本人操作0。復号検査1回、別鍵対照8件。採用監査の初回はプロファイル名の大小文字の想定違いで停止し、APIの小文字表記に合わせて修正後に成功した。

実行イメージは`samlscope:reference-producer-metadata-v40`、digestは`sha256:cc159b10d6721a300e79756ff7d4342067466cdc37ccba2e2a2916b8e5582f67`。無関係な未コミットSOAP変更は含めていない。

<!--g1-literal--> 対象Runnerテスト20件成功、G1構造46/46、台帳監査エラーなし。G2は20/21で既存G2-30の署名差分のみが残る。

## 継続対象

他製品、ECP固有経路、MGF省略応答の生成経路は未完了。部分的な能力観測、広告、管理画面の成功、キャンペーン終了だけで判定を確定しない。

## ECPプロファイルへの生成能力観測の追加

Run `run_SSWFM7EX1V67WPRXPK975NW52B`、Plan `plan_0T6SEXB43B3RGP5WFP6F1CSMHP`で追加実行した。プロファイルは `ecp_idp` だが、今回の生成能力の観測経路はブラウザSSOである。PAOS固有の適合性をこの結果から推論しない。共通暗号方式ケースを同じRun内の実測証拠で評価し、他プロファイルの結果をコピーしていない。

<!--g1-literal--> 元fixture取込8条件、署名応答8件、対応鍵復号8件、別鍵拒否8件を確認した。正常ログイン前提も同じRunで完了させ、プロトコル証拠評価APIで正式評価した。新規PASSはALG04.b・ALG06.b・ALG06.cの3観測。ALG06.dはMGF明示のため未検証を維持する。

採用検証をプロファイル別に拡張し、Run、プロファイル、取込原本、復元、署名、復号、全条件、ケースの証拠参照を照合する。重複した条件・原本IDと必要条件の欠落も拒否する。旧ブラウザプロファイルの採用証拠も同じ検証に通ることを確認した。

原本は `shibboleth-producer-algorithms-ecp/`、正式結果は `shibboleth-producer-evaluation-ecp/` に保存。未検証台帳と比較表は生成器で更新し、未検証契約監査でエラーなしを確認した。

<!--g1-literal--> 未検証438→435観測、異なるケースID154は不変。元応答のMGF省略条件や未観測ケースを推定で解消していない。

<!--g1-literal--> 操作はメタデータ等の書込13（復元含む）、一時ファイル削除2、サービス再読込11、Run作成・preflight各1。送信AuthnRequest17件（通常ログイン1、条件別正常要求8、無効署名試行8）、受信Response9件。製品再起動0、Docker build0、Suite/転送再作成0、本人操作0。復号検査コンテナ1回はネットワーク無効・Suite鍵領域読取専用で実行し、秘密鍵・復号平文は保存していない。

必要な証拠検査のみ実施し、Java/Web全体のテストは反復していない。新しく追加した表示名・TLS観測コードの一括試験と実環境反映は引き続き別途必要である。

## Keycloakの生成設定切替を自動化

`dev/keycloak/producer_algorithm_campaign.py`を追加し、Run専用のクライアントを新規作成して暗号生成設定を切り替える経路を実装した。各段階で設定を読み戻し、既存クライアントを変更せず、終了時に作成したDB IDのクライアントだけを削除して不存在を確認する。管理トークンは操作ごとに取得し、記録しない。この経路は明示設定による生成能力の確認であり、製品のメタデータ解釈の証拠として扱わない。

Run `run_BCJDFCFSWYMHVSESDMZCMBNAKA`で実行。プロファイルは `ecp_idp`、実際の生成観測はブラウザSSOである。原本と正式結果は `keycloak-producer-algorithms-ecp/` に保持した。

<!--g1-literal--> AES256/128 GCMと旧／新OAEP・SHA1/SHA256を組み合わせた5段階を完走。元Redirectクエリの署名と送信XMLの一致、応答署名、Assertion復号・署名・Issuer、別鍵拒否、改変応答拒否を検査した。秘密鍵・復号平文は保存しない。ALG06.cを新規PASSとして採用し、未検証435→434観測、異なるケースID154は不変。

`VerifyNativeProducerAlgorithms.java`と`verify_native_producer_acceptance.py`で、原本一覧・Transcript・fixture・設定操作のハッシュを固定し、正式結果の証拠参照まで照合する。ALG06.dは新OAEPのMGFが明示されるため未検証のまま。単に管理APIが設定を受け付けたことは確定根拠にしていない。

<!--g1-literal--> 管理APIはGET16、POST1、PUT5、DELETE1（設定書込計7）、トークン取得23、ブラウザSSO5。製品再起動・Suite再作成・Docker build・本人操作はいずれも0。読取専用の復号検査コンテナは3試行。初回は検証ツールがRedirect署名をXML署名と誤って想定して停止し、元クエリ検証へ修正した。後続は正常完了し、最終回で採用証拠の原本ハッシュ結合も固定した。失敗試行と操作数は`operation-summary.json`に記録済み。

台帳と比較表を再生成し、未検証契約監査はエラーなし。Java/Web全体テストの反復やコミットは行っていない。
