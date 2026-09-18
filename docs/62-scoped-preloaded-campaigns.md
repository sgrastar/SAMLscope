# 必要なSPだけの事前取込とSimpleSAMLphp属性比較

Shibbolethで採用済みのSP別属性比較をSimpleSAMLphpへ展開するため、標準の`core:AttributeCopy`を使うネイティブ収集ドライバーを追加した。製品自身のSAMLParserで元XMLを解析し、各SPのauthprocに共通anchorと専用属性へのuidコピーを設定する。設定は両SPを一括追加し、各往復の前後で実コンテナから設定を読み戻し、最後に元ファイルへ復元する。

`AttributeCopy`が配列形式の複数コピー先を処理することは参照製品のソースで確認した。これは独自の適合動作を製品へ実装するものではなく、製品標準機能への設定である。属性値・ログイン入力は記録しない。共通のSP別プロトコルcollectorを使う前提だが、SimpleSAMLphp用の準備記録監査・正式採用はまだ未接続。

## 最初の実機試行で判明した問題

既存のpreloaded aggregateはUI URL比較も含んでいた。SimpleSAMLphpのネイティブ解析は、集約中のロゴURLを不正として例外終了した。今回必要な属性比較のSPに到達する前に止まっている。原本は`build/acceptance/reference-20260918/simplesamlphp-relying-party-attributes/fixture.xml`、診断は`parser-failure.stderr`と`attempt-status.json`。これを製品FAILへ変換しない。

<!--g1-literal--> Run/preflight各1、集約取得1、ネイティブ解析2（失敗原因確認の再解析を含む）。停止は設定変更前であり、製品設定書込・プロトコル往復・本人操作は0。例外にコマンド全文を含めない固定エラーへドライバーも修正した。

## Suite側の修正

`POST /api/runs/{id}/metadata-lab/preloaded`に任意の`variants`リストを追加した。空のbody/オブジェクトは従来の全対象を使う。指定時は空リスト、重複、対象外variant、nullを拒否する。署名付きの集約をSuite自身が選択範囲だけで生成し、製品へ渡す前に外部スクリプトがXMLを書き換える方法は使わない。

メタデータ取得・ダウンロード・ブラウザ実行の範囲はRunへ保存したリストに統一する。キャンペーンを作り直すとトークンを更新し、キャッシュキーにもトークンを含める。これにより、選択範囲が変わっても同じRunの古い集約が返る問題を防ぐ。新しい取込原本と証拠は別に記録される。

javascript/fileのURL負の対照は正の事前取込候補から除外した。通常・pollingの個別URL試験は維持する。dataや他の機能の対応可否を一律に仮定せず、複数機能をまとめたことによる取込失敗は必要な範囲の選択で避ける。

SimpleSAMLphpのドライバーは、属性比較に必要な既存の異なるSPだけを選択するよう変更済み。まだ新APIを稼働版へ反映していないため、この修正を使った再試験は次の工程である。

<!--g1-literal--> API/生成器/Run管理と検証コードのコンパイルは成功。範囲内のSPだけが含まれること、対象外の負の対照・重複・空リストの拒否、旧トークンの失効を検証するコードを追加した。機能テスト群は一括実行待ち。未検証465観測を維持する。

## 範囲指定の稼働反映と正式採用

署名済み`418e9603`から隔離ビルドし、`samlscope:reference-scoped-preload-v50`へ反映した。digestは`sha256:3bcdb93e2ed9e86d928b43b6323058ea4bd2f2d8036232f4bfa07adbc7876e3d`。この版は別件の未コミットSOAP変更を含まない。

<!--g1-literal--> SimpleSAMLphpの新Run `run_WNMZ106QK6JKRN8P6JFZQ0KNWG`では対象SPを2つに限定した集約をネイティブ解析へ渡し、取込が成功した。設定を固定してA/B/Aの3往復を収集し、設定を元のバイト列へ復元した。SP Bは集約の最後のメンバーなので、ACSの完了画面を汎用ドライバーが「unhandled」と記録したが、原本の相関・署名・復号が成立したため、その表示文言を判定根拠に使わなかった。

共通collectorによって、Aはanchor/first、Bはanchor/second、Aの再確認はanchor/firstを返すことを確認した。入力属性のfingerprintも同一だった。SimpleSAMLphp用の準備監査は、標準AttributeCopyのマッピング、SPとの対応、NameFormat、暗号化・要求署名検証設定、元fixture、native parser出力、実際に適用したoverlay、前後の設定読戻しを照合する。PHPコードの変換をSuiteのXML解釈に置き換えない。

`verify_relying_party_attribute_experiment.py`と準備記録exporterへネイティブ設定方式の違いを追加し、Javaの判定・原本collector・CONFIGケースは共通のまま使う。既存Shibboleth準備記録の再生成結果が変わらず、採用検証も通ることを確認した。

<!--g1-literal--> 保存原本の正式比較はSATISFIEDで、6種類の証拠混入・不足の負の対照を拒否した。その後、通常ログイン前提を満たし、Run専用準備記録を配置して読み戻した。正式Runの`IIP-IDP02-a-idp-01`はSATISFIED/PASS、attested=false。採用検証を通した比較表と台帳を再生成し、未検証465→464（−1）、ケースID数は157を維持した。

証拠は`build/acceptance/reference-20260918/simplesamlphp-relying-party-attributes-scoped/`、正式評価は`simplesamlphp-relying-party-attribute-evaluation/`。最初の失敗した広い集約のRunも削除せず、前節の記録へ残している。

<!--g1-literal--> 今回はイメージbuild 1、Suite/転送コンテナ再作成各1、新Run/preflight各1、取込parser 2（SP別比較の集約と通常ログインのメタデータ）、コンテナ内ポリシー読戻し7、製品設定書込4（比較の適用/復元2、通常ログインの適用/復元2）、プロトコル往復4、準備記録配置1、tests/start 1、準備確認1。製品再起動・サービス再読込・本人操作は0。標準OPcacheのため適用後に運用上の待機を行った。前節の失敗試行分は別に記録しており、この値へ隠していない。

通常ログインの取込・復元も`dev/simplesamlphp/complete_run_baseline.py`へまとめ、次の実証で同じ手順を再利用できるようにした。今回も広範囲の機能テスト群は実行せず、必要な原本検証と採用境界の検証を実施した。G2-30の既存署名差分は未解消。
