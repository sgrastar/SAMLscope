# Shibbolethのネイティブ読込経路と方式選択の実証

## 実行経路

`dev/shibboleth/import_metadata_batch.py`を追加した。元fixtureを一時的な専用ファイルへそのまま保存し、Shibboleth標準の`FilesystemMetadataProvider`で読み込ませる。SuiteのXML→製品属性変換を挟まない。各条件でファイルのバイト一致とサービス再読込を確認し、Suite発行の正常要求・無効署名対照を実行する。

終了時には元の`metadata-providers.xml`をバイト単位で復元・再読込し、一時ファイルを削除する。失敗経路も`finally`で復元する。既存のSPメタデータファイルは変更しない。新しい実行経路は、以降のメタデータ試験にも利用できる。

## 実機の結果

<!--g1-literal--> Run `run_XZ4CY23XHSV2NPFTDW2H0EVZCS`で13条件の読込・正常SSO・復元が完了。Suite保存原本と製品投入XMLの一致、およびRun固定IdP鍵によるResponse署名を全13条件で検証した。

| ケース | 判定 | 実測 |
|---|---|---|
| IIP-MD05-ea-idp-01 | Success | Entity／Roleの広告順を交換すると、署名方式・Digest方式も先頭のSHA256系／SHA384系へ切り替わる。単一方式条件も確認した。 |
| IIP-MD05-eb-idp-01 | Success | 競合時は方式ごとにRole側が優先される。Role側に片方の方式だけを指定した条件でも、もう片方のEntity側情報を維持する。逆向きの競合条件も確認した。 |

<!--g1-literal--> 台帳は481→479観測、異なるケースIDは159→158。MD05.ebは参照3製品すべてに実測の確定判定が揃った。元の594観測から115観測を確定したが、残り全体の完走には至っていない。

判定は前回までと同じ共通の原本相関・署名検証付き実装を利用した。無効署名対照の一部でクライアントが`unhandled location`と出力したのはSuiteのACS終了画面であり、正常要求の成否はこの表示から判定していない。保存済み要求IDに相関するSAML Successを別途確認している。

## 証拠・検証

元XML、フロー、サービス再読込記録、復元記録は`build/acceptance/reference-20260918/shibboleth-algorithm-metadata/`。準備確認と評価後結果は`shibboleth-algorithm-evaluation/`に分けて保存した。取込時点の結果を上書きしていない。

`native_algorithm_preparation.py`へFilesystemMetadataProviderの読戻し・再読込・元設定ハッシュ・一時ファイル削除確認を追加した。`verify_metadata_algorithm_outcomes.py`が原本・準備記録・署名検証記録・ケース証拠参照を照合し、対象ケースだけを台帳へ採用する。製品ごとの期待結果は受入監査側にあり、共通判定コードには製品名による分岐を追加していない。

Java実装は前回の検証済み稼働版を再利用した。今回は証拠監査、生成台帳の整合監査、G1生成一致・構造検証を実施。G2の既存署名差分は残っている。

## 操作回数

<!--g1-literal--> メタデータファイル書込13、読込先設定の投入・復元2、一時ファイル削除1（製品書込操作16）、メタデータサービス再読込14。正常SSO試行13・無効署名対照試行13、Run作成1、preflight1、準備確認2。Docker build0、Suite再作成0、製品再起動0、本人操作0。

回数は`shibboleth-algorithm-evaluation/operations.json`に保存した。サービス再読込はまだ条件ごとに必要なので、今後HTTP更新経路でまとめて実行する際の削減対象として残る。
