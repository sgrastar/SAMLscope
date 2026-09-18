# 固定した属性公開ポリシーでの比較観測

Shibbolethで、属性resolver・公開filter・メタデータprovider設定を最初に適用し、比較中はそれらを変更せずにメタデータ入力と要求の索引を変える実行器を追加した。Runは`run_K737VNKMS7Y66MSGPCZ0F0PZSQ`。試験用SPのentityIDに限定し、独立した属性名を使用するため、既存の通常公開属性との混同を避ける。

ポリシーは製品の[EntityAttributeExactMatch](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199502013/EntityAttributeExactMatchConfiguration)と[AttributeInMetadata](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199501959/AttributeInMetadataConfiguration)を使う。後者では`onlyIfRequired`が異なる独立した属性を用意し、RequestedAttributeの存在と必須指定の効果を区別する。

## 署名検証・復号後に観測した属性

以下は`urn:samlscope:test:policy:`以下の属性名の末尾。値自体は抽出結果へ保存していない。`anchor`は同じresolver入力から常に公開する対照属性であり、この表だけで同一ユーザーの証明とは扱わない。

| 条件 | 観測した属性 |
|---|---|
| 通常対照 | anchor |
| EntityAttributesあり | anchor, entity |
| EntityAttributesなし | anchor |
| RequestedAttribute、isRequired=true | anchor, required, optional |
| RequestedAttribute、isRequired=false | anchor, optional |
| RequestedAttributeなし | anchor |
| 索引ゼロ | anchor, required, optional |
| 索引一 | anchor, surname |
| 索引ゼロへ戻す | anchor, required, optional |

比較ごとの設定ファイル読み戻しはすべて同じハッシュだった。索引比較では元XMLのSHA-256が一致し、後続のメタデータ書込・サービス再読込を省いた。通常応答の原本署名、暗号化Assertionの復号、内側の署名とIssuerをコンテナ内で検証した。秘密鍵や復号した属性値は外へ出していない。

実行器は`dev/shibboleth/attribute_policy_campaign.py`、暗号検証は`dev/reference-acceptance/VerifyAttributePolicy.java`、記録の整合確認は`verify_attribute_policy_experiment.py`。証拠は`build/acceptance/reference-20260918/shibboleth-attribute-policy-campaign/`。原本manifest、MetadataPreparedとfetch、署名付き要求／応答の相関、設定固定、索引の往復、復元記録を照合した。

## 判定と残作業

この観測は`IIP-IDP03-a-idp-01`、`IIP-IDP04-a-idp-01`、`IIP-IDP04-b-idp-01`の判定処理へ接続する候補証拠である。まだRunnerの各ケースはこの比較を評価しない。設定固定・元XML同一性・実行ユーザー／属性入力・要求相関・欠落対照を扱う判定と、その負の対照を実装する。索引比較は別キャンペーンにまたがるため、同一Runというだけで無関係な試行を結合しない設計が必要である。

### 比較判定部の追加

`AttributePolicyComparison`を追加した。検証済みSampleだけを受け取る内部比較処理で、各ケースの必須条件と試験用属性集合を照合する。固定ポリシー、実行ユーザー、SP entityID、比較対象外の入力、実験識別子が一致しない場合は未検証とする。索引比較は元メタデータの完全一致と、応答完了後に次要求を発行した順序を要求する。重複条件、使い回した証拠、不完全な対照、収集時の検証エラーもSuccessにしない。

Sampleの指紋値は収集側が原本と準備記録から検証して作る必要がある。ユーザーが入力したハッシュや確認チェックだけでは生成しない。実行ユーザーの照合値は一時的に比較へ用い、CaseOutcomeの詳細へ保存しない。現在の抽出ファイルは属性名しか含まないため、それだけからユーザーの一致を推定しない。

正常な比較と、各対照の欠落、常時公開、別実験、ポリシー変更、別ユーザー、別SP、元メタデータ変更、制御外入力変更、順序不整合、証拠重複を扱うテストを追加した。Javaテストはバッチ検証待ちで未実行。この内部比較処理はまだCONFIGケースのレジストリへ登録しておらず、判定が変わる稼働経路は追加していない。

次は原本署名・復号後の属性入力と、固定ポリシーの準備記録を結合する収集境界の実装である。既存観測の製品設定ハッシュは外部実行器の記録にあり、RunnerのTranscriptへ検証済み準備情報として接続されていない。この不足を残したまま比較関数へ定数の指紋を渡さない。

### 原本からの属性収集処理

`AttributePolicyAttributeReader`と`AttributePolicyProtocolEvidence`を追加した。既存のMetadataPrepared／fetch／要求／応答の相関検査を再利用し、正常応答の署名、広告された暗号化鍵と秘密鍵の対応、復号後のIssuerと内側署名を確認してから属性を読む。索引はTranscript要約の宣言ではなく原本AuthnRequestから取得し、メタデータの比較指紋も原本バイトから計算する。

属性の比較入力は同じAssertion内に限定する。anchor不在、値が異なるmarker、重複marker、未知のmarker、異なるNameFormat、空や構造化された値、未復号のEncryptedAttributeが残る場合は証拠不成立とする。暗号化された属性を無視して「不存在」と判定しない。例外文やObservationの文字列表現にも属性値を出さない。

Run内の属性入力照合には、Runと対象entityIDを含めた長さ付き入力のハッシュを一時的に使う。これは同じ属性入力の証拠であり、独立したログインユーザーの本人性確認ではない。比較判定部のprincipalFingerprintへそのまま代入しない。ネイティブ準備記録・実行ユーザーの結合と、比較対象以外の入力を検査する処理は依然として未完了である。

平文／暗号化応答の一致、Runごとの照合値の分離、不足・曖昧な属性、署名改変、復号鍵不足・鍵不一致を扱うテストを追加した。前項と同様にバッチ検証待ちであり、この追加を理由に稼働イメージや台帳の判定を更新していない。

### 本体収集処理での原本再読込

RunnerとAPIの`compileTestJava`をまとめて実行し、追加した本体コード・テストコードのコンパイル成功を確認した。テスト本体は実行していないため、負の対照検証が完了したとは扱わない。

`ObserveAttributePolicyExperiment.java`を追加し、上記Runの保存済み原本を`AttributePolicyProtocolEvidence`へ渡した。読み取り専用の実行で、鍵はコンテナ内の既存ファイルを参照し、存在しない鍵を生成しない。署名・復号を再検証し、外部検証ツールの観測と照合する。

<!--g1-literal--> 本体収集処理は9往復を読み取り、issuesは空だった。属性入力の照合値は全条件で一致したが、これを認証済みユーザーの一致とは宣言していない。結果は`production-observation.json`に保存し、原本ハッシュ・条件・索引・属性名・要求／応答参照を検査した。製品設定操作・アプリ再起動・新Run作成はいずれも0回。台帳は470観測のまま。

現在の補助鍵入力サービスはRunと対象メタデータへの固定を扱うが、比較実験の準備前後やユーザーの対応付けを表現しない。用途を流用せず、検証済み準備情報を受け渡す仕組みと正式ケースへの接続を残作業として維持する。

<!--g1-literal--> 正式なSuccessは追加しておらず、未検証は470観測・157ケースIDを維持する。実測した9条件を解消件数へ加算しない。

## 操作・ビルド記録

<!--g1-literal--> 製品設定等の操作14回（書込13、試験用メタデータ削除1）、サービス再読込14回、SSO9回、Run作成・preflight各1回、キャンペーン作成9回、準備確認0回。本人操作・製品再起動はいずれも0回。設定ファイルの元と復元後のSHA-256一致、一時メタデータ削除を確認済み。

署名済みコミット`2de509ec`のソースを隔離ディレクトリでビルドし、別件の未コミットAPI変更を含めず配布物を生成した。`api:installDist -x test --offline`成功。Javaテストはバッチ検証待ちであり、成功済みとは記録しない。暗号検証ツールの初回コンパイルは配布ディレクトリ指定を誤って失敗し、正しい`install/samlscope/lib`で再コンパイルして成功した。

<!--g1-literal--> イメージbuild1回、Suite／転送コンテナ再作成各1回。稼働イメージは`samlscope:reference-attribute-policy-v42`、digestは`sha256:45706f6b4ed6c5ec2d95643252aa0d3aedd15ac8cfde7f869d5f8d51104990b1`。G1生成一致・構造46/46。既存のG2保護ソース署名差分は未解消である。
