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

<!--g1-literal--> コンパイルは成功。追加した2テストの実行は次の統合バッチまで保留し、成功扱いにしていない。ユーザー指定に従い、小さな追加のたびに機能テストを再実行しない。G1生成確認と構造検査は変更ごとの必須確認として実行する。

<!--g1-literal--> 未検証467観測／157ケースIDを維持。製品設定書込・コンテナ変更・プロトコル実行・本人操作は0回。新fixtureは作業ソースに追加した段階で、稼働中のイメージには未反映。
