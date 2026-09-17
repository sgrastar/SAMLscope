# 方式選択の署名検証付き証拠

## 共通処理と実機証拠

`VerifiedSignatureAlgorithms`を追加した。SAML Responseと直下のAssertionについて、期待したIssuerとRunの信頼鍵に合致し、当該要素を直接参照する署名が検証できた場合だけ、署名方式・Digest方式・検証鍵のSHA-256を返す。メッセージのKeyInfoを信頼鍵として採用しない。

重複ID、別Issuer、誤鍵、署名後の改変、SignatureMethodの改変、XPathによる部分署名を証拠から除外する。Assertionにしか署名がない場合、その署名をResponse全体の署名として扱わない。許可した変換で検証できないことは製品の違反ではなく、観測できないこととして扱う。

保存済みのSimpleSAMLphp Run `run_EF53BKR660XSH9Q27R8D4K1B41`を再検証した。対象メタデータのSHA-256をresult.jsonのmetadata_digestと照合し、対象entityのSAML IdP Roleにある署名用／use省略の証明書だけを信頼鍵として使用した。元XMLのハッシュと要求応答相関も確認した。

<!--g1-literal--> 全13条件でResponse署名が検証できた。直下のAssertion署名も検証でき、いずれもRSA-SHA256／SHA256だった。新しい製品設定変更やSSOは実行せず、元証拠の再解析だけで確認した。

実行用ツールは`dev/reference-acceptance/VerifyMetadataAlgorithmSignatures.java`。新しいSAML JARと既存配布物の依存ライブラリをclasspathへ指定して実行する。出力`verified-algorithm-signatures.json`は、選択した要素の署名と相関に限定した証拠であり、適合判定を直接変更しない。

## 広告値との比較

`diagnose_metadata_algorithm_selection.py`で署名検証済みの値を元fixtureの広告値と比較する。署名方式とDigest方式を独立に扱い、Role側に当該種類がある場合だけEntity側の同種の情報を上書きする。宣言なしは非対応と推論しない。

<!--g1-literal--> 署名方式とDigest方式を別々に数えた26観測では、広告なし4、先頭方式を選択10、広告リスト外の方式を選択6、後方方式を選択6となった。これはケースの確定数ではない。後方選択にはローカルポリシー未確認を明記し、すべてaffects_verdict=falseとしている。

SimpleSAMLphpのMD05.ea／ebの台帳へ、この追加観測のRun・証拠パス・ダイジェストを紐付け、次アクションを更新した。元ケース結果のRunやVerdictを置き換えていない。

## 残る判定接続

SuiteのMetadataFetch記録は現状、取得したvariantを記録するが、配信したメタデータXML自体をdecodedSamlRefとして保存していない。この不足を、外部ドライバが保存したfixtureと取込記録で補っている。Suite内部の自動判定へ移す際は、実際に配信したXML・取得・製品消費・同一条件の要求応答を結び付ける必要がある。variant名だけで配信内容を推定して判定しない。

承認済みMD05.eaのローカルポリシー例外、MD05.ebの種類ごとのRole優先、正負対照を含むcase実装と登録は残る。今回の署名検証結果だけでSuccess／Failedへ変更しない。

## 検証と状態

SAML回帰テストと追加の負の対照を実施した。初回は新規テストの鍵保管用Plan IDが形式制約に合わず失敗したため、既存形式に修正し、失敗した新規テストを再実行して成功を確認した。実環境イメージは前回のv32のままで、新しい処理はオフライン証拠検証に使用した。

<!--g1-literal--> 未検証は483観測・159ケースIDを維持。追加の製品設定変更0、Run作成0、本人操作0。G1生成一致・構造46/46、台帳監査のエラー0を確認した。G2の既存署名差分は未解消であり、全体完了とはしていない。
