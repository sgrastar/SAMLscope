# 属性公開ポリシー比較の正式判定接続

固定ポリシーの準備記録、署名・復号後の属性観測、要求ごとの比較条件をCONFIGケースへ接続した。[55](55-fixed-attribute-policy-observations.md)で段階的に追加した比較・収集・結合処理が、実際のRunの判定に使われる。

## 正式結果

Run `run_C97YCPR7F5KNWRMCMHWNPQ11N9`の保存済み実測を使用した。製品設定の再変更やSSO再実行はせず、検証済み準備記録を配置して準備確認を実行した。

| Shibbolethのケース | 正式結果 | 根拠 |
|---|---|---|
| `IIP-IDP03-a-idp-01` | Success | EntityAttributes存在・不存在による属性差 |
| `IIP-IDP04-a-idp-01` | Success | RequestedAttribute存在・不存在とisRequiredの差 |
| `IIP-IDP04-b-idp-01` | Success | 同一メタデータで要求の索引を切替えた属性差と復帰 |

すべて`SATISFIED / configuration.attribute-policy.comparison-observed`をEvaluatorがPASSへ変換した。自己申告の結果ではなく、`attested=false`である。準備確認だけでは合格しない。自動比較が成立しない場合は既存の手動証拠確認経路を維持する。

<!--g1-literal--> 未検証は470→467観測。異なるケースIDは157のまま。Keycloak／SimpleSAMLphpの同ケースは今回のShibboleth実証から推定しない。台帳監査はエラーなし、inventory SHA-256は`3cfb7fa86140303319cbd9faccf5661ae55f227cba3477090eb09e302d456a6f`。

## 準備記録の扱い

`export_attribute_policy_preparation.py`は、ネイティブポリシーの意味、設定の前後一致、元メタデータの条件、署名・復号後の観測を検査してローカルアダプター用記録を生成する。記録はVerdictを含まない。固定入力の比較指紋は、検査済みルールが参照する対象SP・uid入力元と固定した設定から作る。署名で確認した属性入力の一致も別途必要である。

Runnerは`attribute-policy-preparations/<run>.json`をデータディレクトリ内から読む。この場所は信頼されたローカルアダプター／管理者用であり、未検証の外部ファイルを任意に投入してよい境界ではない。HTTP投稿経路は追加していない。Run、固定対象メタデータ、準備記録が指す原本ハッシュ、要求／応答参照を再照合し、通常ファイル以外や過大なファイルも拒否する。ローカル管理者が記録自体を捏造した場合まで製品署名だけで検出できるとは主張しない。

初回の出力では、対象entityIDに公開resultの`redacted:internal-target`を使うSuite側の不備があった。Runnerはこれを拒否し、未検証を維持した。exporterを固定メタデータ原本のentityIDを使うよう修正した。拒否された記録は別名で保存し、修正版のハッシュと訂正理由を`preparation-correction.json`へ記録した。受理済み結果を別の準備情報で上書きしたのではない。

元証拠は`build/acceptance/reference-20260918/shibboleth-attribute-policy-preparation/`、正式なconfigure応答と結果は`shibboleth-attribute-policy-evaluation/`。`verify_attribute_policy_acceptance.py`が両方を照合して生成台帳へ採用する。元の実測結果・拒否記録・修正後の正式結果を分けて保持する。

## まとめて実施した検証と操作

<!--g1-literal--> Javaは計15テスト成功（比較・結合・原本属性読取・メタデータ入力・署名付き索引要求・API入力制限・準備ファイル境界）。Pythonの準備記録検査4テストも成功。これまでバッチ待ちだった負の対照をまとめて実行し、後から追加した準備ファイル境界の検証を補完した。G1生成一致・構造46/46。G2の既存署名差分は未解消。

<!--g1-literal--> G2は20/21でG2-30が阻害要因のまま。今回のM1Runtime接続変更も保護ソースの署名差分に含まれる。旧承認を今回の実装へ流用せず、リリース完了とは扱わない。

<!--g1-literal--> 今回の正式判定接続で製品設定書込・製品再起動・SSO・新Run作成・本人操作は0回。準備確認POST3回、ローカル準備入力の配置2回（拒否分を含む）、拒否記録の保存先変更1回。イメージbuild1回、Suite／転送コンテナ再作成各1回。前段の実測は[55](55-fixed-attribute-policy-observations.md)に失敗・復元込みで記録しており、今回の費用へ二重加算しない。

署名済み実装チェックポイント`1afa954a`から隔離ビルドした。稼働イメージは`samlscope:reference-attribute-policy-oracle-v43`、digestは`sha256:ebc4f33b53048011f765dc1b7189850bf7fee1d01a3e447dae0c41691e41e3ca`。別件の作業ツリー内SOAP変更は含めていない。exporterの対象entityID修正はローカル実行器の変更であり、配布したJava成果物の変更ではない。
