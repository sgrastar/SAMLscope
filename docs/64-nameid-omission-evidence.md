# NameID省略の証拠検査と比較処理

`IIP-IDP11-a-idp-01`の承認済み義務は、Subject内にNameIDを含まないAssertionを生成できること。既存のCONFIG確認だけでは実測から判定できないため、原本検査と内部比較を追加した。現段階ではRunnerへの登録・ネイティブ準備記録・製品での省略設定実証は未接続であり、正式な判定確定ではない。

## 原本検査

`VerifiedResponseAssertion`へ既存属性比較の署名・復号処理を抽出した。Response署名、Assertion署名がある場合の検証、対象issuer、準備済みSPメタデータと暗号化鍵の一致、単一Assertionを維持する。要求相関を指定した呼出しではDestination、InResponseTo、Audience、bearer Recipientも検査する。従来属性比較の任意相関呼出しは動作を変更しない。

`NameIdOmissionResponseEvidence`は相関入力を必須にし、検証済みAssertionの単一Subjectを検査する。NameID、BaseID、完全省略を区別する。EncryptedIDは準備済み鍵で復号し、NameIDが隠れている場合を省略とは認めない。Subject欠落、識別子重複、復号不能、署名不正や要求不一致は証拠不成立とする。識別子の値や暗号処理の例外原因は外へ返さない。

`NameIdOmissionComparison`は、同一実験・同一SP・固定したログイン入力と比較外入力の下で、通常のNameIDあり応答から完全省略応答への順序付き比較を要求する。各交換の原本参照は一意とする。これが揃えばSATISFIED、それ以外はNOT_VERIFIEDを返す。設定・実行経路がないことを製品FAILに変換しない。BaseIDを使う構成の適否は、この完全省略の実証経路から推定しない。

## 残る接続と検証

内部Sampleは、ネイティブ準備記録と原本collectorによる結合後にのみ作成する設計である。HTTP自己申告を証拠へ変換する経路は追加していない。次は製品の標準設定による省略経路、前後設定・復元の記録、要求原本と応答原本の照合、CONFIGケース接続を追加する。

<!--g1-literal--> 追加した境界テストは、平文／暗号化Assertionと平文／暗号化NameID、完全省略、Subject欠落、重複、鍵欠落、相関不一致、署名改変、入力混在、証拠再利用を対象とする。テストソースまでコンパイル済み。実行テストはバッチ確認へ保留し、未検証463件／156ケースIDを維持する。

<!--g1-literal--> 今回の製品操作はSimpleSAMLphpソース検索の読取2回のみ。製品設定書込・再読込・再起動・プロトコル往復・本人操作は0回。稼働製品のNameID生成経路を調べたが、この検索だけで省略機能の不存在は確定していない。

既存の稼働イメージは変更していない。共通署名処理を抽出したため、バッチ検証時には属性比較の既存境界テストと原本リプレイも含める。G2の保護実装署名差分は未解消であり、リリース完了とは扱わない。

## 原本collectorと正式CONFIG接続

`NameIdOmissionProtocolEvidence`は、準備記録で指定したメタデータ・要求・応答の参照を、同一RunのRecorder原本に照合する。事前取込のMetadataFetchとMetadataPrepared、元XMLのダイジェスト、SP entityID、要求先、広告済みACS、要求ID、唯一の応答、時系列を検査してから署名・復号検査へ進む。無関係な直近の応答を拾うことはしない。

`NameIdOmissionExperimentBinding`は通常条件と省略条件を設定記録の参照へ一意に結合する。両条件で取込メタデータを固定し、AuthnRequestもID・IssueInstant・署名以外の原本内容を一致させる。NameIDPolicyや認証要求が同時に変わった比較は採用しない。設定による省略を証明するネイティブアダプターは別途必要である。

`NameIdOmissionPreparationFile`はローカルの`nameid-omission-preparations/<run>.json`だけを読み、Run・対象entityID・固定対象メタデータのSHA-256と全選択原本のハッシュを固定する。シンボリックリンク、過大ファイル、不完全な条件、重複参照を拒否する。準備記録のHTTP投稿経路はない。

`NameIdOmissionConfigurationTestCase`とM1 registryへの接続を追加した。CONFIG確認時に結合済み実証が揃った場合だけOutcomeを返し、不成立なら既存の確認経路を維持する。以前の未検証結果に新しい原本が加わった場合の再評価も、既存の履歴付き更新経路を使用する。誤った過去結果の上書きや、証拠を増やさない再評価による確定は行わない。

<!--g1-literal--> API・テストソースまでコンパイル済み。結合処理の負の対照テストを追加し、実行はバッチ検証へ保留している。稼働イメージ未更新、製品実測未実施のため未検証463件を維持する。今回のShibboleth読取調査は設定検索・jar所在検索・API検索の3回。API検索は結果なしで終了し、機能不存在の根拠にはしていない。設定書込・再起動・本人操作は0回。

## 省略要求とShibboleth実行器の準備

既存の事前取込要求はNameIDPolicyでtransient形式を明示的に要求していた。生成器を無効化する比較でこの要求を残すと、要求を満たせないエラーと省略能力を混同する。そのため`VALID_NO_NAMEID_POLICY`と専用`nameid-omission`事前取込variantを追加した。要求全体は引き続き署名し、通常条件と無効化条件の両方で同じ要求形式を使用する。既存variantの要求を変更しない。

`dev/shibboleth/nameid_omission_preparation.py`はネイティブの`shibboleth.SAML2NameIDGenerators`リストだけを空にする設定を生成する。生成前のリストが空、同じIDが複数、リスト以外の要素が変更された場合は拒否する。これは隔離した参照IdP全体のSAML2生成設定を一時変更する試験であり、SP限定の変更ではない。

`nameid_omission_campaign.py`は専用メタデータの取込、通常ログイン、生成器設定の切替と再読込、同一要求でのログイン、設定の完全復元と再読込を記録する。前後の設定読戻し・原本参照・ログイン入力の固定記録を保持する。ACSの輸送完了を成功判定には使わない。標準設定で本当にNameIDなしの成功応答が得られるかは未実証であり、応答原本の検証後に判断する。

<!--g1-literal--> 稼働Shibbolethの設定・jar所在・サービス資源を読取調査し、公開設定APIのjarを3ファイル取得した。継承元の調査中、存在しないクラス名と存在しないディレクトリの検索も発生した。実装クラスのNameIDFormatPrecedenceとネイティブ生成器リストの所在を確認したが、これだけでは省略能力を確定しない。生成器を使わない場合の挙動も未実行である。

新しい実行器はPython構文とJavaテストソースのコンパイルを確認した。実行テストはバッチ確認へ保留。専用variantは稼働イメージへ未反映のため、今回製品設定を書き換えず、台帳も据え置く。

## Shibboleth実環境での正式採用

<!--g1-literal--> 署名済み`bf6b46aa`を隔離ビルドし、`samlscope:reference-nameid-omission-v51`へ反映した。イメージdigestは`sha256:5800c4056621e3c66d36d509ba82f5c73b83305a41e2eab7b63ccf22b423fc1e`。既存データを保持し、Suiteと転送コンテナを更新してhealthを確認した。別件の作業ツリー変更は含めていない。

<!--g1-literal--> Run `run_J7YRDB4T4J8FXKSRXG4K7ZNJ3Q`で、通常応答のNAME_IDと生成器無効化後のOMITTEDを確認した。両応答は正式collectorによる署名・復号・相関検証を通過し、要求の比較指紋も一致した。ネイティブ設定は元バイト列へ復元し、再読込と一時メタデータ削除を確認した。

`export_nameid_omission_preparation.py`は生成器リスト以外の同一性、設定前後の読戻し、ログイン入力固定、原本ハッシュと参照、元メタデータ、プロトコル条件の一致を監査して準備記録を作る。`ObserveNameIdOmissionExperiment`は正式collector・比較処理を使用する読取専用の補助プログラムで、Runの結果自体を書き換えない。

<!--g1-literal--> 欠落・重複・別応答・ログイン入力混在・比較入力混在の5種類を実測から作った負の対照として拒否した。通常ログインの前提確認後、CONFIG確認で`SATISFIED/PASS`・`attested=false`となった。採用検証器が設定復元、配置した準備記録の読戻し、正式比較、結果の証拠参照6件と原本不変性を照合した。

<!--g1-literal--> 未検証463→462件、ケースID156件は据え置き。他製品やECPプロファイルへは推定で採用していない。証拠は`build/acceptance/reference-20260918/shibboleth-nameid-omission/`、正式評価は`shibboleth-nameid-omission-evaluation/`。台帳と製品比較表は生成器から更新し、契約監査はエラーなし。

<!--g1-literal--> 比較実験と通常ログインの合計は、設定書込8回・再読込6回・一時ファイル削除2回・プロトコル往復3回。build1回、Suite／転送コンテナ再作成各1回、製品再起動・本人操作0回。補助プログラムの初回コンパイルは配布物パス指定を誤って失敗し、修正と負の対照追加後の再コンパイルを含め計3回実施した。失敗も操作台帳へ記録した。

実行テスト一式は引き続きバッチ確認へまとめる。今回の正式採用に必要な実製品原本・負の対照・生成台帳監査は実施した。既存のG2保護ソース署名差分は未解消であり、リリース完了ではない。
