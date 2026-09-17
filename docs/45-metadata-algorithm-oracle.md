# メタデータ方式選択の判定接続と実証

## 判定範囲

`MetadataAlgorithmConfigurationTestCase`をM2のMD05.ea／ebへ接続した。ネイティブ取込の準備完了だけを確認し、Outcomeは保存済み証拠から計算する。確認時にVerdictを入力する経路ではない。確認前は証拠が揃っていても自動完了せず、確認後も証拠不足ならNOT_VERIFIEDになる。

`MetadataAlgorithmEvidence`はRun固定のIdP署名鍵、メタデータ原本のSHA-256、取得記録、AuthnRequestのIssuer・ACS・ID、ResponseのDestination・InResponseToと検証済み署名を照合する。試験キャンペーンを跨いで不足条件を埋め合わせない。改変された応答・原本、別Run、曖昧な要求ID、取得との相関不足は未検証にする。

`MetadataAlgorithmSelection`は署名方式とDigest方式を別々に扱う。同じ種類のRole側広告がある場合だけEntity側を置き換え、Role側にDigestだけがあるときにEntity側の署名方式を捨てない。順序選択はローカルポリシーの例外を考慮し、順序不一致だけでWarningやFailedにしない。Caseが返すのはOutcomeであり、Verdict変換はEvaluatorが行う。

## 保存済み実機証拠の評価

Run `run_ZTEB6PCRWXJM0CZ6QWCZRR966T`の証拠を再利用した。対象はSimpleSAMLphpの製品ネイティブパーサによる静的メタデータ取込経路であり、他の取込モードや製品全体の適合性を確定するものではない。

| ケース | 判定 | 根拠・制限 |
|---|---|---|
| IIP-MD05-eb-idp-01 | Failed | Role側のSigningMethod、DigestMethod、両方にSHA384系を指定し、Entity側と競合させた条件で、SHA256系の検証済み署名応答を生成した。Role側SHA256の逆向き条件と独立した単一方式条件も実行済み。 |
| IIP-MD05-ea-idp-01 | NOT_VERIFIED | 広告順を交換してもSHA256を選んだが、SHA384の使用可能性とローカルポリシーが未確認。順序不一致をそのまま違反にしていない。 |

製品の`modules/admin/src/Controller/Federation.php`を確認し、`SAMLParser::parseDescriptorsString`→`getMetadata20SP`と、その後の`entityDescriptor`／`expire`除外が製品自身の静的変換処理と一致することを記録した。Suite独自の属性変換による情報欠落を製品の失敗としていない。取込時の原本一致・設定読戻し・復元は前回の証拠に結び付けた。

<!--g1-literal--> 台帳は483→482観測、異なるケースIDは159のまま。診断だけの更新や単体テストを解消件数に含めない。再試験前594観測からの確定数は112で、全件の完走を意味しない。

証拠は`build/acceptance/reference-20260918/algorithm-oracle-evaluation/`、取込原本とプロトコル証拠は`simplesamlphp-algorithm-recorded-metadata/`。`verify_metadata_algorithm_outcomes.py`が原本ハッシュ、準備確認、取込・復元、署名検証記録、Outcomeと証拠参照を照合してから、生成器が対象ケースだけを台帳へ採用する。

## 接続漏れと検証

実機接続時にM2レジストリへのTranscript依存関係の渡し忘れと、準備確認を既存の手動判定防止ガードが遮断する問題を検出・修正した。`requiresPreparationConfirmation`を明示したケースだけ準備確認を許可し、他のTranscript判定ケースの手動確認禁止は維持する。PendingInteractionもこの契約を参照する。

API統合テストは、リリース対象のmetadataプロファイルにケースが現れ、準備確認をAPI経由で受け付けても証拠なしでは未検証になることを検査する。署名検証付きの正負対照、片方の方式しかRoleにない条件、別キャンペーンの混合、改変応答・原本を含むRunnerテストも実施した。

<!--g1-literal--> Runner493、API88テストは失敗・スキップなし。G1生成一致・構造検証と台帳監査を実施。G2の既存G2-30署名差分は未解消で、リリース承認完了にはしていない。

## 作業量

<!--g1-literal--> 保存済み13条件を再利用。製品設定書込0、ネイティブ再取込0、新Run0、preflight0、新規プロトコル往復0、製品再起動0、本人操作0。準備確認成功2、失敗試行1。接続漏れの修正を含みDocker build3、Suite／転送コンテナ再作成各3。前回の取込操作は二重計上しない。

最終稼働イメージは`samlscope:reference-algorithm-oracle-v36`、digestは`sha256:eb97a0ff7e3c0e9f870fe3eb61877695143a0f80b9a5f1890ade796e344409a2`。APIの無関係なSOAP差分は配備に含めていない。操作回数は上記証拠フォルダの`operations.json`に保存した。
