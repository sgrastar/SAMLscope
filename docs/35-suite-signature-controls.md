# Suite発行の署名対照と製品ネイティブ取込

## 実証による台帳更新

<!--g1-literal--> SimpleSAMLphpのmetadata_idpで11観測をSuccessに確定しました。未検証は511から500、異なるケースIDは170から164になりました。基準594観測中の確定は94です。製品横断の全体適合率や単一Runの完走率ではありません。

| 採用ケース | 実測内容 |
|---|---|
| MD02.c、MD05.a4 | 単一・集合の文書ルートを製品の解析器で取り込み、SSOで使用 |
| MD05.a5 | cacheDuration・validUntilを持つ文書の取込と使用（期限切れ判定の証明ではない） |
| MD05.g | 未知拡張とRegistrationInfoの取込・使用 |
| MD05.ad、MD07.a | 複数鍵の各位置、use省略時の各鍵で署名した要求の受理 |
| MD06.a9、MD12.b、MD12.d | 期限・開始時刻・主体・発行者・拡張・用途が異なる証明書の公開鍵を使用 |
| MD12.a、MD12.c | 自己署名・長期証明書、異なる証明書署名アルゴリズムを持つ鍵の使用 |

採用Runは `run_KDFJDGNQQCVFANEG53YYWYS4A1`。各条件で、元XMLのハッシュ、製品解析器の出力、署名必須設定、設定反映、Suiteが発行した正常署名の要求、相関するSuccess応答、設定復元を照合しています。MD03.cはメタデータ署名を検証する信頼処理の証拠ではないため、元resultにPASSがあっても採用しません。KeyValueの使用も確定していません。

## Suiteへの対照の接続

メタデータキャンペーンに `signatureControl=invalid` を追加しました。Suite自身が破損署名のAuthnRequestを作り、実際に表示したXMLと要求ID、variant、キャンペーン識別子、制御種別をTranscriptへ保存します。受信した応答はInResponseToで関連付け、破損署名への応答ではキャンペーンを進めません。

`MetadataSignatureObservation` は、同じRun・variant・キャンペーンメンバー・送信先に属する正常要求のSuccessと不正署名要求のSAMLエラーが揃う場合だけ対照成立とします。無応答、外部ドライバの自己申告、別キャンペーン、別Run、別variant、重複要求ID、未発行の要求、不明なステータスは成立根拠になりません。不正署名のSuccessが観測されたvariantも対照不成立です。不正署名へのSuccessは通常のメタデータ使用証拠から除外します。

KeyValueのケースは、この対照が成立した場合に限り従来の保留を解除できるようにしました。KeycloakではKeyValue-onlyとuse省略の複数鍵で不正署名にもSuccessが返ったため、鍵消費の証拠に採用していません。

また、ドライバの「キャンペーンが進んだら成功」という扱いを修正しました。相関するSAMLエラーでも進行するため、Suiteが発行した要求に対する実際のSuccessステータスを確認します。

## SimpleSAMLphpの取込経路

`dev/simplesamlphp/import_metadata_batch.py` は、稼働製品の管理用変換処理と同じ `Utils\XML::checkSAMLMessage`、`Metadata\SAMLParser::parseDescriptorsString`、`getMetadata20SP` を呼びます。Suite独自のXMLから属性への変換は行いません。管理画面の操作試験ではなく、製品自身の解析器を呼ぶCLI経路です。

製品の管理用変換処理と同様、静的取込出力からentityDescriptorとexpireを除き、その製品出力を専用entityの設定として追加します。そのため、この経路はメタデータのHTTP更新・有効期限の強制・署名信頼検証の証明には使いません。既存設定は各試験後に元のバイト列へ戻し、最終ハッシュも照合します。

初回はSuiteの署名任意宣言が製品に反映され、破損署名を受理しました。これを製品の失敗とはせず、Suiteの正式な `requestSigningMode=REQUIRED` で新しいPlanを作成して再試験しました。

<!--g1-literal--> 次の試行ではPHP OPcacheの再検査間隔を未考慮だったため、その証拠は採用せず、設定した2秒の再検査間隔を超える3秒の反映待ちを設けて全27条件を再試験しました。これはローカル実験のキャッシュ対策であり、製品の適合判定へ時間閾値を追加したものではありません。

不正署名に対するSimpleSAMLphpのHTTPエラーは記録していますが、それだけで「SAML拒否義務を満たす」とはしていません。採用したケースは、署名必須設定下で各正規fixtureの鍵・文書が実際に使われたという正の証拠に基づきます。SAMLエラーを返さない対照についてSuite内の署名識別判定は保留を維持します。

## 検証と操作コスト

<!--g1-literal--> Runner 478、Peer 15、API 87テストが成功し、参照ドライバのPythonテスト29件も成功しました。G1生成一致・構造46/46。G2は20/21で、G2-30の保護ソースと既存署名承認の差分は残っています。

<!--g1-literal--> 今回の取込試行は60、設定書き込みは123（Keycloakの作成・削除、SimpleSAMLphpの追加・復元、最終復元の重複書き込み3回を含む）。全試行の削除・復元を確認しました。正常系の相関成功58、不正署名試行60、本人操作0です。製品コンテナ再起動0、Docker build 2、Suiteと転送コンテナの再作成各2です。全クリック・全管理API読取回数は未計測です。

実環境は `samlscope:reference-signature-controls-v24-final`。フルビルド時に既存の別作業のAPI差分を除いた隔離ソースを使い、元の作業ツリーは保持しました。実証は先行する同系列イメージで実施し、最終版では取得待ち画面の再開時も署名対照の指定を保持する修正を追加し、API回帰テストを確認しました。

証拠は `build/acceptance/reference-20260917/` の `keycloak-suite-signature-controls/`、`simplesamlphp-native-parser-1/`、`simplesamlphp-native-parser-2/`、`simplesamlphp-native-parser-3/` にあります。最後のSimpleSAMLphp試行だけを台帳に採用します。集計は `suite-signature-control-operations.json`、デプロイ記録は `suite-signature-control-runtime/` です。
