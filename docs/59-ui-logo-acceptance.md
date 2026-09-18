# UIロゴ言語選択の正式判定

[比較入力・ブラウザ観測・原本相関](58-ui-consumer-fixtures.md)をRunnerのケースへ接続し、Shibbolethの`IIP-MD05-f9-idp-01`を正式RunでSuccessと確認した。優先言語のロゴがあればそれを選び、優先・代替言語に該当する候補がなければ言語なしロゴへ切り替わる実画面の差が根拠である。

| 製品／プロファイル | 対象ケース | 正式結果 |
|---|---|---|
| Shibboleth／metadata_idp | IIP-MD05-f9-idp-01 | SATISFIED／PASS、attested=false |

<!--g1-literal--> 未検証は467→466観測、異なるケースIDは157のまま。生成した比較表と台帳へこの観測のみを採用し、他製品の結果を推定していない。台帳監査の不整合は0件、inventory SHA-256は`22f622b87a2f9ba13568196755517d95f1d35bb5453fafac3a5c42492b1cf7e8`。

## 採用した証拠

Runは`run_GNBRVD9WSNFGHMXZEFN4BAH6NR`。元実測は`build/acceptance/reference-20260918/shibboleth-ui-consumer-language-control/`、正式評価は同親ディレクトリの`shibboleth-ui-logo-evaluation/`。

`verify_ui_logo_acceptance.py`は、元XMLとブラウザ候補対応表、原本Transcript、ローカルreceipt、配置先の読戻し、Runner再生結果と負の対照、設定復元、固定対象メタデータ、正式CaseOutcomeの参照一致を再検査して台帳へ渡す。正式理由は`browser.ui-logo.language-fallback-observed`。候補トークンだけや設定確認だけを合格根拠にしない。

ブラウザ観測とnative準備は信頼されたローカルアダプターから受け取る。HTTPから証拠を任意に投稿する仕組みは追加していない。画面観測は製品の署名付きSAML応答ではなく、Suite管理下のブラウザ観測である。要求の原本相関、固定対象、実画面要素、言語条件、対照の差を組み合わせて評価している。

初回のtests/startは通常ログインが未完了のため拒否された。認証前画面の観測から始めたRunに必要な前提であり、判定条件を緩めず、同じRunで通常ログインを実施してから再評価した。`complete_run_baseline.py`を追加し、ネイティブメタデータ取込・通常往復・設定完全復元までを再利用できるようにした。

## 検証と費用

<!--g1-literal--> 蓄積した比較／fixtureのJava4テスト、Playwright境界1テストが成功。実測原本を本番収集・比較コードへ渡した再生でSATISFIEDを確認し、7つの変異対照はすべてNOT_VERIFIED。コンパイル・隔離配布ビルド成功。G1生成一致・構造46/46。G2は20/21、G2-30の保護ソース署名差分は未解消であり、リリース完了とは扱わない。

署名済みチェックポイント`e8174820`から隔離ビルドした。稼働イメージは`samlscope:reference-ui-logo-oracle-v46`、digestは`sha256:0f04f7c9844540cdce76177c83c064613ad511f348b5490f4840c1f1f32088d5`。別件の未コミットAPI変更は含めていない。

<!--g1-literal--> 正式評価の追加操作はreceipt配置1回、tests/startの試行3回（通常ログイン不足で拒否2回、成功1回）、通常ログイン1往復（追加Transcriptは要求／応答の2件）、通常ログイン用設定書込3回・削除1回・Resolver再読込2回。設定は完全復元済み。本人操作・製品再起動は0回。Suiteイメージbuild1回、Suite／転送コンテナ再作成各1回。前段のUI観測バッチ費用は[58](58-ui-consumer-fixtures.md)に記録済みで、ここへ二重計上しない。

表示名の最終フォールバック、他製品のUI表示、DiscoveryHintとURLスキームの判定は引き続き未完了である。
