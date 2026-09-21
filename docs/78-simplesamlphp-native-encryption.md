# SimpleSAMLphpの暗号化応答の実測

`dev/simplesamlphp/producer_algorithm_campaign.py`を追加した。署名モード比較と同じ設定復元・読み戻し基盤を使い、通常の元メタデータを製品自身のパーサーへ渡した一時SPで、非暗号化、暗号化、暗号化再実行を記録する。標準設定`assertion.encryption`を切り替え、ResponseとAssertionの署名は維持する。生成処理をSuite実装へ置き換えていない。

## 原本と正式判定

Run `run_BTJPR0GYG7H7FMBJRCJ7Z699RK`の原本は`build/acceptance/reference-20260918/simplesamlphp-native-producer-encryption-normal/`に保持する。暗号化応答は`aes128-cbc`、鍵輸送は`rsa-oaep-mgf1p`、DigestMethod省略時のSHA-1だった。この観測からAES-GCMや別のOAEP方式の対応を推定しない。

`VerifyNativeProducerAlgorithms.java`をSimpleSAMLphpの比較にも対応させた。秘密鍵はSuiteの読み取り専用ボリューム内で使用し、持ち出さない。元AuthnRequestのRedirect署名、固定対象鍵によるResponse署名、復号後のAssertion署名を検査する。別の秘密鍵による復号失敗とResponse改変時の署名不成立も確認する。平文Assertionは保存しない。既存Keycloak比較の必須条件数は維持した。

正式なprotocol-evidence判定で`IIP-ALG06-a-idp-01`が`SATISFIED / PASS / browser.encryption.rsa-oaep-mgf1p.decrypted`となった。`verify_ssp_producer_acceptance.py`が原本ハッシュ、対象とRunの一致、設定読み戻し、復元、暗号検証結果、正式判定の証拠参照を照合する。設定を受け付けたことやHTTP完了だけでSuccessにしていない。ただし現在の生成台帳では同ケースが既に別の実証で解消済みだった。今回の結果は追加実証として保持し、新規解消には数えず、既存の採用元も変更しない。

<!--g1-literal--> 未検証は429観測のまま。その他のアルゴリズムはこの実測から確定しない。新しい単体テスト群や全体テストはこの小単位では実行せず、関連実装のまとめた検証へ残す。追加実証の原本検証は実行した。

## 失敗試行と設定作業

初回の`simplesamlphp-native-producer-encryption/`は、Suite側で明示的な`variant=control`を使い、ACSがメタデータ試験経路になった。このため通常ログインが完了せず、profile開始APIが拒否した。製品の失敗には分類していない。通常メタデータURLへ修正して新Runで再実行し、初回の原本も保存した。

両試行で設定を元のバイト列へ復元し、ハッシュ一致を確認した。同時変更を検出した場合は上書きしない。実行中の設定は一時SPだけに追加し、既存SPの設定を変更しない。

<!--g1-literal--> 失敗試行を含む操作は、Run作成・preflight各2、製品設定書込8（復元2を含む）、ネイティブ読み戻し6、AuthnRequest・Response各6、profile開始試行2（失敗1）、正式証拠評価1。製品再起動、Docker build、Suite再作成、本人操作は0。原本検証用の一時コンテナは1回。`batch-operations.json`に記録した。コミットは作成していない。

前段で追加したMDIOP証明書アダプターと属性ポリシー再判定のソース変更は、この稼働イメージにはまだ含まれない。今回の確定は既存の暗号化判定処理を使っており、保留中の変更を検証済みとは扱わない。
