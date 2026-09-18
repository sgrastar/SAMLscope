# 属性公開ポリシーの比較入力

承認済みの`IIP-IDP03-a-idp-01`、`IIP-IDP04-a-idp-01`、`IIP-IDP04-b-idp-01`に必要なメタデータ入力を`MetadataService`へ追加した。生成したXMLは既存の署名・MetadataPrepared原本記録経路を使う。生成できたことは製品による消費の証明ではない。

| 入力ID | 内容 | 用途 |
|---|---|---|
| `attribute-policy-entity-present` | EntityDescriptor直下のExtensionsにEntityAttributesを付与 | EntityAttributes存在条件 |
| `attribute-policy-entity-absent` | EntityAttributesなし | 不存在対照 |
| `attribute-policy-requested-required` | uidのRequestedAttribute、isRequired=true | 必須指定条件 |
| `attribute-policy-requested-optional` | 同一属性、isRequired=false | 必須指定の差分対照 |
| `attribute-policy-requested-absent` | RequestedAttributeなし | 属性要求の不存在対照 |
| `attribute-policy-indexed` | 異なる属性を指定したAttributeConsumingServiceのエントリー | AuthnRequestによる選択の比較入力 |

EntityAttributesの属性名は`urn:samlscope:test:release-policy`、値は`release`。RequestedAttributeにはuidとsurnameのOID形式名を用いる。索引付き入力はメタデータ側の準備であり、AuthnRequestでの索引切替・製品応答比較の実装完了を意味しない。

## 次の接続で守る条件

EntityAttributesの有無、RequestedAttributeの有無、isRequiredの値をそれぞれ製品自身の取込経路へ投入する。対象の公開ポリシーを固定したまま同じユーザーで実行し、署名付き応答の属性集合の差を観測する。設定ファイルを条件ごとに別の公開結果へ直接書き換えた事実を、メタデータ消費能力の根拠にしない。isRequired=trueなら必ず公開するという判定も追加しない。

同じentityIDを保つpolling経路を比較の基本とする。preloaded集約は条件別にentityIDを変えるため、その出力差だけではメタデータ属性が原因だと証明できない。また既存のpolling経路は条件別に鍵やACSを変えるので、それらを含む差分と製品ポリシーの実際の参照条件を検査してから判定へ採用する。

索引選択の試験では同じメタデータを維持し、AuthnRequestのAttributeConsumingServiceIndexだけを切り替える必要がある。異なるメタデータの既定サービスから別属性が返っただけでは、この試験を確定しない。

## 索引付き要求の実行経路

`SamlSignedRequestFactory`へ索引を受け取るoverloadを追加した。属性は署名を生成する前に設定し、既存の呼出しは属性省略を維持する。XML SchemaのunsignedShort範囲外を拒否する。AssertionConsumerServiceURLと混同せず、応答のACSは維持する。

<!--g1-literal--> polling開始APIの`attributeConsumingServiceIndex`は`attribute-policy-indexed`に限り0または1を許可する。待機中の再遷移、通常要求、無効署名対照で指定を保持し、原本AuthnRequestとTranscript要約に記録する。`dev/keycloak/import_metadata_batch.py --flow-run ... --attribute-service-index ...`から指定できる共通実行経路を追加した。製品固有の取込操作や判定はこの引数だけでは実施しない。

索引付きfixtureのpolling配布は、同じRunで元XMLを既存の容量制限付きキャッシュに保持する。再取得によるvalidUntil／XML署名の変化を避けるためである。ただしキャッシュの追出しや再起動があり得るので、比較する両要求に対応するMetadataPrepared原本のハッシュ一致を判定側で検査する必要は残る。

通常のpollingキャンペーンは応答後に進むため、索引比較の実行器には同じRunでの次キャンペーン準備と、固定した製品設定・ユーザー・元XMLの確認が必要である。この統合実行器と、署名検証・復号後の属性差を評価するoracleは未完了。

## 検証状態

以下は入力実装時点の記録。後続の隔離ビルド・実環境反映・固定ポリシー比較観測は[55](55-fixed-attribute-policy-observations.md)を参照。判定接続とJavaテストは引き続き未完了。

生成条件の位置・存在と不存在・isRequiredの差・索引ごとの属性差を検査するテストを追加した。要求についても署名検証、索引改変時の署名拒否、範囲外入力拒否、省略時の互換性、APIのfixture制限のテストを追加した。ユーザーのバッチ検証方針に従い、Javaテストと実機への反映は後続の実行経路・判定接続とまとめて実施する。現段階は未実行で、既存の稼働イメージを更新していない。G1の生成一致と構造検証のみ実施した。

<!--g1-literal--> 新規の判定確定はなく、台帳は470観測・157ケースIDを維持する。製品設定書込・製品再起動・本人操作は今回いずれも0回。
