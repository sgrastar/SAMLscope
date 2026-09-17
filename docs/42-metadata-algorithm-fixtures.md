# メタデータのアルゴリズム順序・Role優先の実行条件

## 追加した入力と適用範囲

承認済みIIP-MD05.ea／ebと、参照仕様SAML2MetaAlgSupのMetadata Consumers節を確認し、メタデータキャンペーンへ方式選択の入力を追加した。署名方式とDigest方式を別々に扱う。Role側にDigestMethodだけがある場合、Entity側のSigningMethodまで無視する実装を見逃さないための条件も含む。

<!--g1-literal--> 追加したfixtureは12種類。通常のcontrolと合わせて13条件を一括実行できる。HTTP取込と事前配置の両生成経路へ接続した。判定オラクルへの登録はまだ行っておらず、SSO成立だけで該当義務をSuccessにしない。

| fixture接尾辞（共通接頭辞 `algorithm-`） | 入力 |
|---|---|
| entity-sha256／entity-sha384 | 単独の署名・Digest方式の対照 |
| entity-order-256-384／entity-order-384-256 | Entity側で両方式の順序を入替え |
| role-order-256-384／role-order-384-256 | SP Role側で両方式の順序を入替え |
| role-signing-384 | Entity側はSHA256、Role側は署名方式だけSHA384 |
| role-digest-384 | Entity側はSHA256、Role側はDigest方式だけSHA384 |
| role-both-384／role-both-256 | EntityとRoleで相反する方式を広告 |
| unsupported-first | 未知方式の後ろに既知のSHA256方式 |
| absent | 両方式の宣言がない対照。非対応とは解釈しない |

SAML層の回帰テストをまとめて実施した。既存の全variant署名検証により署名整合も検査し、順序入替え・片側だけのRole上書き・宣言なしの差を検証した。G1の承認済み定義は変更していない。

## 製品自身の取込による観測

SimpleSAMLphpで新Run `run_EF53BKR660XSH9Q27R8D4K1B41` を実行した。製品自身のメタデータパーサへ元fixtureを渡し、署名必須設定の読戻し、Suite発行の署名対照、通常AuthnRequestに相関するResponse、元設定への復元を記録した。

<!--g1-literal--> 全13条件で相関するSuccess Responseが観測された。ResponseとAssertionのSignedInfoはどの条件でもRSA-SHA256／SHA256を広告していた。SHA384を単独で指定した条件や、Role側だけで指定した条件でも変化しなかった。

`dev/reference-acceptance/observe_metadata_algorithm_batch.py`を追加した。元XMLとハッシュを保存し、正常要求のIDとの相関、fixtureのハッシュ、取込・復元記録を照合して、Entity／SP Roleの広告方式と応答SignedInfoを対応付ける。不正署名の対照要求への応答を正常観測へ混ぜない。出力は`signature_verified: false`と`affects_verdict: false`を明記した診断であり、暗号学的な検証や適合判定の代替ではない。

証拠は`build/acceptance/reference-20260918/simplesamlphp-algorithm-metadata/`。この観測だけから、製品全体のSHA384非対応、方式順序違反、Role優先違反はまだ確定しない。特に順序選択は承認済み定義のローカルポリシー例外を尊重する必要がある。

## 次の判定接続

- Runの対象メタデータにある信頼鍵で、対象Response／Assertionの署名を検証してからSignedInfoを観測する。
- メタデータを取得・取込した条件と、その条件に相関する要求応答の証拠を同一キャンペーン内で束ねる。
- MD05.eaでは単独方式の対照と順序入替え、ローカルポリシーの扱いを判定へ接続する。
- MD05.ebでは署名方式・Digest方式を別々に評価し、Role側に当該種類がある場合だけEntity側からの継承を止める。
- MD05.e全体のEncryptionMethod、KeySize、アルゴリズム固有拡張の条件は本fixture群では網羅していない。別途追加する。

## 作業コストと状態

<!--g1-literal--> ネイティブ取込13、Run作成1、preflight1、製品設定書込27（各投入・復元と最後の復元）、署名対照要求13、通常要求13、Docker build1、Suite／転送コンテナ再作成各1、本人操作0、製品再起動0。全設定の復元をSHA-256一致で確認した。

稼働イメージは`samlscope:reference-algorithm-metadata-v32`、digestは`sha256:40595feb47f0d34de4cdfeffa4315f27700b78b93211f1d8d32836cbc051fc08`。前の共有鍵入力イメージへSAML JARだけを重ねた。配備記録は`build/acceptance/reference-20260918/algorithm-metadata-runtime/`。

<!--g1-literal--> 本バッチの判定確定は0件。未検証は483観測・159ケースIDを維持する。G1生成一致・構造46/46を確認。G2の既存署名差分は未解消のままとし、リリース承認を意味しない。
