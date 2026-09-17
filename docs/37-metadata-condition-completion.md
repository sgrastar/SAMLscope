# メタデータ拡張点・既定ACSの不足条件の補完

## 結果

<!--g1-literal--> 未検証は490→489観測、異なるケースIDは161のまま。SimpleSAMLphpのIIP-IDP12.cをSuccessとして採用した。Failed・Warningの追加はない。入力生成の追加自体は削減件数に含めない。

## まとめて追加した入力と実行経路

| 対象 | 追加した条件 | 完成範囲 |
|---|---|---|
| 拡張点 | Organization、ContactPerson、AffiliationDescriptorの非SAML名前空間拡張 | 必須の親要素構造を保持して署名メタデータを生成。製品自身のパーサーを経由した取込と署名付きSSOを実行 |
| 名前空間の負の対照 | Organization/Extensions内のSAML名前空間要素 | 旧root直下の入力と異なるvariant IDで生成。旧証拠を新条件へ流用しない |
| 既定ACS | 最初が明示falseで次が省略、すべてfalse、複数true | 要求から選択属性を省略して実行し、応答先をメタデータの既定選択と照合 |
| index負の対照 | 同じACS集合内の重複index | 入力生成のみ。重複入力の受理を直ちに製品違反と扱うオラクルには接続していない |

AffiliationDescriptorは通常のRoleDescriptor群と同一EntityDescriptorへ混在させず、別のEntityDescriptorとして集合内に配置する。既定ACSの照合はAssertionConsumerServiceの集合だけを使用する。

SimpleSAMLphpの取込ドライバーにbrowser_sso_idpプロファイルを追加した。既定ACSの対照はメタデータ変更後の応答先変更であり、通常AuthnRequest専用の署名破壊APIをこの経路へ呼び出さないよう修正した。初回試験の未対応呼出しはSuiteのHTTPエラーとして記録し、拒否成功の証拠には使っていない。

## 実測で判明したSuiteの誤判定と修正

IIP-MD05.a3の承認済み制約は「未知拡張の受理はMD05.g、ここでは名前空間修飾と拡張点制約を判定する」と分離している。既存の消費側オラクルはSuiteが生成した不適切な拡張を製品が受理するとVIOLATEDを返していた。これは対象自身の拡張内容が不適切である証拠にはならない。

この経路を修正し、名前空間を直接検査する証拠がない限りreadyにせず、NOT_VERIFIEDを維持する。必要証拠には `namespace-qualification:extension-points` を追加した。元の誤ったFAIL結果は履歴として保存するが、比較表・台帳には採用しない。修正後の新Runでも同じ入力が受理され、製品FAILが発生しないことを確認した。

修正後のケースは未完了なので結果の理由は `case.pending-interaction`。protocol-evidenceの詳細で、操作では解消できない名前空間確認経路の不足を記録し、台帳の次アクションを更新した。試行完了のconfigure送信は「Transcript駆動ケースはoperator確認不可」とSuiteが拒否したため、その経路で確定を代用していない。

## 証拠と再現

基点は `build/acceptance/reference-20260918/`。fixture原本、パーサー出力、設定投入・復元、フロー相関、要求・応答原本とSHA-256 manifestを保存した。

| 試験 | Run | フォルダー |
|---|---|---|
| 既定ACS | run_XKNHNHTS27D8V15RGGVWPPNWX4 | simplesamlphp-default-acs |
| 拡張点・修正前 | run_9HVYC3FA0WW6BYBZSMY1PN33YN | simplesamlphp-extension-points |
| 拡張点・修正後 | run_NTB45B0333JF88W97SGWEMZD0D | simplesamlphp-extension-points-corrected |

採用検証器 `verify_default_acs_batch.py` は、実際の要求にACS選択属性がないこと、署名の存在、応答のInResponseToとSuccess、実際の受信URLと元メタデータの選択先が一致することを確認する。全指定条件と変更対照が揃った場合だけ台帳へ採用する。

最終稼働イメージは `samlscope:reference-metadata-conditions-v27-final`、digestは `sha256:98a366f4362bddb9d5d1d395c6080b53d7eeeac67378cec0159a4eb9c3de04d4`。

## コスト・検証・残り

<!--g1-literal--> このバッチは入力種類追加8、ネイティブ取込23、設定書込49（投入・復元46と各バッチfinallyの再復元3）、Run作成3、preflight3、Docker build2、Suite／転送コンテナ再作成各2、本人操作0、製品再起動0。configureの拒否試行1。元設定はSHA-256一致で復元済み。

SAML生成とRunner全体をまとめて回帰検証し、実測で発見した誤判定の修正だけ追加検証した。G1生成一致・構造検証成功。G2の署名済みソース差分は引き続き未解消であり、リリース承認完了とは扱わない。

名前空間の直接確認、入れ子内の全entityの鍵・エンドポイント使用、重複index対照の適切な判定、他製品への同一条件の実行は継続課題。今回の受理結果や単体テストだけでこれらを完了と扱わない。
