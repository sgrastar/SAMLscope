# 暗号化方式・OAEPパラメータ・鍵サイズの入力条件

## 実装した範囲

`MetadataEncryptionAlgorithmFixtures`を通常生成・polling・preloadedの生成経路へ接続した。暗号化用または用途省略のSP KeyDescriptorに`md:EncryptionMethod`を追加する。署名専用KeyDescriptorとIdP Roleへ誤って広告しない。

<!--g1-literal--> 新規入力は15種類。AES128/256のCBC/GCM単独広告、GCM順序交換、明示KeySize、旧／新RSA-OAEPとSHA1/SHA256、MGF明示／省略、署名方式のMaxKeySizeで先頭候補を除外する条件を含む。

鍵サイズの除外条件は故意に不適合な候補を作る入力であり、Suite独自の安全性しきい値ではない。後続の候補には制限を追加していない。MGF省略条件とMGF1-SHA1明示条件を区別し、旧RSA-OAEPにはMGF要素を追加しない。

`dev/shibboleth/import_metadata_batch.py`へ非baseline条件で観測が成立しなかった場合にも次の条件へ進めるオプションを追加した。設定読込自体の失敗とbaseline失敗は停止する。キャンペーンを進める操作だけで拒否やVerdictを確定しない。

## 実機観測

Run `run_054AFN63J7RV1NZNFRYS65PDN7`でShibbolethのネイティブFilesystemMetadataProviderへ元XMLを投入した。

<!--g1-literal--> 対照を含む16条件すべてで、元XMLとSuite保存原本の一致、正常SSO、Run固定IdP鍵によるResponse署名検証、設定復元を確認した。

暗号化応答は単独広告に合わせてCBC/GCMを切り替え、GCMの広告順交換にも追従した。RSA-OAEPも広告した方式・Digest・MGFに対応する応答を生成した。MGF省略を広告した条件では、応答にMGF1-SHA1を明示した。この観測を「応答でもMGFが省略された」とは記録していない。

`observe_metadata_encryption_batch.py`は署名付き応答内の暗号化ヘッダと広告を記録する。ヘッダだけでは復号成功を意味しないので、この診断自体にはVerdictを付けない。

## 復号と負の対照

`VerifyMetadataEncryptionDecryption.java`をSuiteコンテナ内で実行した。元fixtureの暗号化証明書と既存variant鍵の公開鍵一致を確認し、その鍵で元応答を復号した。別variantの鍵で同じ暗号文が復号できないことも確認した。秘密鍵をコンテナ外へコピーせず、復号平文は保存していない。結果に保存するのは条件ID、証拠参照、復号成立・別鍵失敗などの事実だけである。

<!--g1-literal--> 全16条件で対応鍵によるAssertion復号に成功し、別鍵による負の対照は全16条件で失敗した。初回は計算後の結果保存が証拠フォルダの所有権で失敗したため、出力先をコンテナ内の書込可能な一時ファイルへ変更して再実行した。初回の出力失敗を記録し、失敗した結果を採用していない。

## 残る接続と台帳

既存のALG04/06ブラウザ観測は通常SSOのRun鍵を使用し、metadata campaignの応答を対象外としている。今回の条件はvariantごとの鍵を使うため、復号鍵の供給と原本・応答の相関を判定経路へ明示的に接続する必要がある。元fixtureの広告を見ただけで共通鍵やRun鍵を推測してはならない。

MD05.e／e8の全条件・対照を揃えたCase判定、および該当プロファイルでのALG04/06判定への接続が継続対象である。今回の証拠はShibbolethの関連する未検証台帳へ追加観測として紐付けた。

<!--g1-literal--> 未検証は475観測・157ケースIDのまま。新入力15種類、正常フロー16条件、復号16条件を新規確定件数として数えていない。

証拠は`build/acceptance/reference-20260918/shibboleth-encryption-metadata/`。`encryption-selection-observations.json`と`verified-encryption-decryption.json`に観測・復号の結果と元証拠のハッシュを保存した。

## 検証・作業量

SAML回帰テストを実施し、通常／pollingの方式順序、KeySize、方式ごとのパラメータ、明示MGFと省略の区別を確認した。既存の全variant署名検証も通過した。G1生成一致・構造検証と台帳監査を実施。G2の既存署名差分は未解消である。

<!--g1-literal--> 製品メタデータ書込16、読込先設定投入・復元2、一時ファイル削除1（書込操作19）、メタデータサービス再読込17。通常SSO試行16・無効署名対照試行16、Run作成1、preflight1。Docker build1、Suite／転送コンテナ再作成各1、製品再起動0、本人操作0。復号検査は結果保存失敗を含め2回。

稼働イメージは`samlscope:reference-encryption-metadata-v38`、digestは`sha256:07f31932ce130b97f6e93ae8a17bba1682a381e6318a1a9f6b984dce46c9cde8`。SAML JARのみを更新した。
