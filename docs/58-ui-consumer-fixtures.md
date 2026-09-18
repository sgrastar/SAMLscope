# UIメタデータ消費の比較入力

表示名の優先順位とロゴの言語選択を観測するため、`MetadataUiConsumerFixtures`を通常およびpollingメタデータ生成へ接続した。承認済み定義は変更していない。入力生成の完成は、製品のブラウザ表示や判定処理の完成ではない。

| 入力 | 対象ケース | 内容 |
|---|---|---|
| `ui-consumer-display-all` | `IIP-MD05-fj-idp-01` | UIInfo DisplayNameとServiceNameとentityIDが存在し、それぞれ区別できる |
| `ui-consumer-display-service` | 同上 | DisplayNameなし、ServiceNameあり |
| `ui-consumer-display-entity` | 同上 | DisplayNameとServiceNameなし |
| `ui-consumer-logo-localized` | `IIP-MD05-f9-idp-01` | 言語なしの既定ロゴと英語ロゴ |
| `ui-consumer-logo-fallback` | 同上 | 同じ既定ロゴとフランス語ロゴ |

UIInfoはSPSSODescriptorのExtensionsに配置する。ServiceNameを含むAttributeConsumingServiceには、スキーマ必須のRequestedAttributeを入れる。ロゴ比較では画像本体を変えず、ローカライズ候補の言語だけを変える。固定したdata SVGは外部通信・スクリプトを含まない。

ロゴの判定には、製品画面の実際の優先言語を固定・記録することが必要である。英語ロゴと既定ロゴをそれぞれ選ぶ差を期待できる構成で実行する。data画像が製品やCSPによって表示できない場合は、比較の前提が未成立であり言語選択の違反にはしない。別の到達可能な画像配信経路を準備する必要がある。

表示名は画面全体の文字列検索だけで判断しない。設定画面、ソース、非表示DOMに候補が存在することと、利用者向けの対象SP表示に選ばれたことは異なる。対象entityID、元fixtureハッシュ、製品自身の取込結果、同じ画面・言語・セッション条件、表示要素と可視性、前後の対照を結び付けるブラウザ観測経路が必要である。最終フォールバックは承認済み定義に従いentityIDまたは端点ホスト名を許容する。

## 未完了部分と検証の扱い

今回追加したのは共通入力と、その配置・候補差・不存在・通常／polling双方を検査するテストコード。製品取込後のブラウザ観測、正負対照のオラクル、正式なRun判定への接続は未完了。DiscoveryHintとURLスキームのケースも今回の入力ではカバーしない。

### ブラウザ観測モジュールの追加

`dev/reference-acceptance/ui_consumer_observation.mjs`は既存のPlaywright Pageを受け取り、製品アダプターが指定した表示要素を読み取る。画面のoriginとpath、ブラウザの優先言語、要素の一意性と可視性、画面内の配置、中央点の遮蔽を確認する。ロゴでは読み込み完了と自然寸法、currentSrcの候補一致を要求する。文字列は指定要素全体の表示テキストとの完全一致を使い、ページ全体の部分一致にはしない。

保存するのは候補トークン、fixtureと取込記録のハッシュ、固定診断だけである。未知の表示テキスト、フォーム値、Cookie、通信本文、スクリーンショットは保存しない。例外の文字列もDOMやURLの機密情報を含み得るため保存しない。記録ファイルは排他的作成とし、既存証拠を上書きしない。

モジュールが読んだ取込記録のハッシュは対応参照であり、取込成功やRunとの結合を検証したという意味ではない。`import_binding_verified=false`と`verdict_adopted=false`を付ける。ブラウザ言語が一致しても製品の保存済み言語設定まで証明したことにはならない。製品アダプターでの取込・言語設定・対象SP表示要素の確認、実際のSSO経路への接続、正負対照の比較、正式判定は引き続き未完了。

負の対照を含むブラウザ境界テストコードを追加した。構文確認のみ実施し、実ブラウザでのテスト実行は統合バッチ待ち。プロジェクトルートにはPlaywrightの解決可能なインストールがなく、既存の参照ブラウザ環境への接続も実行前に必要である。未実行を成功として集計しない。

### Shibboleth実画面への接続

`dev/shibboleth/ui_consumer_campaign.py`で元fixtureを一時FilesystemMetadataProviderへ渡し、読戻し・Resolver再読込後に`observe_ui_consumer.mjs`が製品の標準ログイン画面を開く。ブラウザは毎条件新しいコンテキストを使い、英語の優先言語で認証前に観測を止める。ログイン情報の投入やSSO完了の主張はしない。元のプロバイダー設定は完全一致で復元し、一時メタデータも削除する。

参照環境のPlaywrightはCodex同梱依存を`SAMLSCOPE_PLAYWRIGHT_MODULE`で明示して接続した。製品テンプレートは`header h1`に固定英語接頭辞を付けたSP名を、`img.service-logo`にSPロゴを表示する。IdP自身のヘッダーロゴは選択しない。

| 入力 | 実画面での観測 | 判定に残る条件 |
|---|---|---|
| DisplayNameとServiceNameあり | DisplayNameを表示 | 取込・要求・画面の厳密相関と全条件の対照 |
| DisplayNameなし | ServiceNameを表示 | 同上 |
| 名前候補なし | 対象見出しが存在しない | 別の表示画面の調査。標準login.vmはSP IDを含む名前の見出しを抑止する |
| 英語ロゴあり | 言語付きロゴを表示 | 製品側の実際の言語選択条件の確認 |
| フランス語ロゴのみ＋言語なしロゴ | フランス語候補を表示 | 同上。ブラウザ優先言語だけで製品違反を確定しない |

実測は`build/acceptance/reference-20260918/shibboleth-ui-consumer-campaign-v2/`、Runは`run_7HK04E50WDXFR6NH3QSN5EH0JA`。保存した画像候補値との完全一致を観測し、隠れたDOMの存在やimport成功のみを表示証拠にしていない。ただし観測モジュールは引き続き`import_binding_verified=false`であり、正式なケース判定には採用しない。

初回Run `run_NC94WEZVKV6P8Z75J6YKZE52FH`は`shibboleth-ui-consumer-campaign/`に保持。製品がPOST入口へ遷移したのに観測側がRedirect入口だけを許可していたため全条件を拒否した。固定参照メタデータに広告された両入口に限定して修正した。また、未評価Runにresult.jsonを要求した終了時のエラーを修正し、未生成の結果を作るためにケースを開始せず`evaluation-status.json`を記録するようにした。初回でも設定復元は完了していた。

<!--g1-literal--> 実環境操作は各バッチで設定書込7回・一時ファイル削除1回・MetadataResolver再読込6回・ブラウザ起動5回。初回の失敗分込みで合計書込14回・削除2回・再読込12回・ブラウザ起動10回、Run/preflight各2回。SSO完了・本人操作・製品再起動は0回。各バッチのoperations.jsonとrestoration.jsonが原本である。

<!--g1-literal--> Suiteイメージbuild1回、Suite／転送コンテナ再作成各1回。`samlscope:reference-ui-consumer-v44`のdigestは`sha256:5631b8c2463afa95bbcedab550a2146b67f1687e6e5ac136c40b24fb7c07cee9`。署名済みのUI fixtureソースからSAML jarだけを更新し、別件のAPI作業ツリー変更は含めていない。ヘルスチェック成功。境界テスト一式は統合バッチ待ちであり、この実画面観測をその代わりの成功として数えない。

<!--g1-literal--> 今回も正式判定の追加はなく未検証467観測を維持する。G2の署名差分は未解消。

<!--g1-literal--> コンパイルは成功。追加した2テストの実行は次の統合バッチまで保留し、成功扱いにしていない。ユーザー指定に従い、小さな追加のたびに機能テストを再実行しない。G1生成確認と構造検査は変更ごとの必須確認として実行する。

<!--g1-literal--> 未検証467観測／157ケースIDを維持。製品設定書込・コンテナ変更・プロトコル実行・本人操作は0回。新fixtureは作業ソースに追加した段階で、稼働中のイメージには未反映。
