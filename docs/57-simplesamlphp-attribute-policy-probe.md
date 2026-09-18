# SimpleSAMLphpの属性公開経路の事前診断

[属性比較の正式判定](56-attribute-policy-acceptance.md)を他製品へ展開する前に、稼働中のSimpleSAMLphpのネイティブ取込と標準属性フィルターを実行した。`dev/simplesamlphp/probe_attribute_policy.py`は保存済みの元XMLを製品のXML検査・SAMLParserへ渡し、その戻り値を直接`core:AttributeLimit`のDestinationとして使う。SuiteでXMLを設定属性に変換しない。

入力属性は診断専用の合成値であり、認証済み利用者や署名付きSSO応答ではない。証拠には`protocol_observed=false`、`verdict_adopted=false`を付ける。これは実行経路の調査であり、ケースの合否に採用しない。

## 確認できた処理

| 比較 | パーサーの出力 | 標準フィルターの結果 | 残る条件 |
|---|---|---|---|
| EntityAttributesあり／なし | タグを保持／欠落 | 属性集合に差なし | タグを参照する既存ポリシー経路の確認 |
| RequestedAttributeあり／なし | 要求属性名を保持／欠落 | 存在時はuidのみ、不在時は制限なし | 実際のSSOでの観測 |
| isRequired=true／false | requiredリストを保持／欠落 | 両方uidのみ | isRequiredを入力として使う固定ポリシー |
| 索引付きメタデータ | 先頭のサービスの属性を保持 | uidのみ | 要求索引による選択を保持できる取込・実行経路 |

索引条件のラベルは元fixtureの採取条件を示す。このプローブ自体はAuthnRequestを送信せず、索引対応のプロトコル検査ではない。同一の元メタデータを再入力した結果を、要求索引が無視された証拠として扱わない。先頭要素だけを取り込むことは、稼働製品のSAMLParserソースでも確認した。

`core:AttributeLimit`では要求属性リストが空の場合に制限を行わない。要求属性の不存在を「全属性を除去する」期待値に置き換えると誤判定になる。また、パーサーがisRequiredを保持したことだけでは、承認済みケースが要求する属性公開ポリシーの差を証明できない。

確認した標準フィルターで差が出なかったことから製品全体の機能不存在を推定しない。独自PHPで期待する分岐を追加して検査対象の機能を代作することも、今回の実証として採用していない。

## 証拠と操作費用

元fixtureは`build/acceptance/reference-20260918/shibboleth-attribute-policy-preparation/`。出力は同親ディレクトリの`simplesamlphp-attribute-policy-native-probe/`と`simplesamlphp-attribute-policy-native-probe-provenance/`。後者には実際にロードしたパーサーとフィルターのパス・SHA-256を追加した。各条件の元fixtureハッシュ、終了コード、標準エラーも保持し、既存出力は上書きしない。

<!--g1-literal--> 各9条件、ソース同定追加後の再実行を含め18回のネイティブ呼出しが成功。製品設定書込・再読込・再起動・SSO・本人操作はいずれも0回。別途ソース読取の初回検索でコンテナにrgがなく失敗し、grepへ切り替えた。設定変更は行っていない。

<!--g1-literal--> 未検証は467観測／157ケースIDを維持。今回の診断で新しいSuccessやFailedを確定していない。G2の署名差分も未解消。
