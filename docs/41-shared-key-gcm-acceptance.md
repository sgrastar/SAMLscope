# SimpleSAMLphp共有鍵GCMの実機検証

## 結果と採用根拠

<!--g1-literal--> 未検証を485観測から483観測へ削減した。異なるケースIDは159のまま。SimpleSAMLphpのbrowser_sso_idpにおけるIIP-ALG04.aとIIP-ALG04.bをSuccessへ更新した。他の製品・プロファイルへ結果を転用していない。

製品自身のメタデータパーサで通常のSPメタデータを取り込み、製品設定の`assertion.encryption`、`sharedkey`、`sharedkey_algorithm`を一時設定した。通常のAuthnRequestに相関するSuccess ResponseからEncryptedAssertionを取得し、Suiteが共有鍵で復号できたことに基づく。元のRSA経路がAES-CBCを生成することは、製品全体のGCM非対応を意味しない。

| 条件 | 正常鍵のRun | 誤鍵のRun | 結果 |
|---|---|---|---|
| AES128-GCM | `run_00MKHH590BSDDG411ST76J02AD` | `run_ZNEH2027V46ZFCD76WXK8R5XZ6` | 正常鍵は復号を伴うPASS、誤鍵はNOT_VERIFIED |
| AES256-GCM | `run_30QS0MMCHGS3Q02VGHJ5VYEP9J` | `run_B3N52X36FKQN3RA05MD0D7S3SK` | 正常鍵は復号を伴うPASS、誤鍵はNOT_VERIFIED |

採用前に`dev/reference-acceptance/verify_shared_gcm_batch.py`で、元XMLのハッシュ、Runと要求応答の相関、暗号方式、結果の証拠参照、ネイティブ取込、製品設定の復元、誤鍵時の未確定、鍵差替え拒否を検査した。単体テストの成功や設定読戻しだけでは製品のSuccessにしていない。

## Run入力の寿命と固定

既存の認可済み評価API `POST /api/runs/{id}/protocol-evidence/evaluate`へ、任意の`sharedKeyBase64`入力を追加した。空の入力は従来の評価を維持する。共有鍵は当該リクエストの同期評価中、そのRun・スレッドだけに供給され、終了・例外時に参照を外し、受け取ったバイト配列を消去する。JVMや暗号ライブラリ内部の一時コピーの物理消去までは保証しない。

SQLiteには最初に渡した鍵のSHA-256だけを保存する。同じRunへ異なる鍵を渡す評価は拒否し、再起動後も入力の固定を維持する。元の共有鍵は保存せず、評価を再実行する場合は同じ鍵を再入力する。鍵を紛失した場合は新Runで再試験する。秘密鍵本体をCaseState、Transcript、結果JSON、操作記録へ保存しない。

この供給口は暗号アルゴリズム観測へ接続した。他の復号を要する観測が共有鍵を扱えることや、復号だけでprincipalの意味的同一性を判定できることは主張しない。UIの共有鍵入力パネルは本変更の対象に含まれない。

## 実行と操作負荷

<!--g1-literal--> ネイティブ取込5、製品設定書込10（投入・復元）、Run作成5、preflight5、通常SSO往復5、Docker build1、Suite／転送コンテナ再作成各1、本人操作0、製品再起動0。全試行で元設定のSHA-256一致を確認した。

<!--g1-literal--> 誤鍵の初回Run `run_XM00XBWDXACHFD2HH78BD1VGFP`では、鍵差替えをAPIが正しく拒否したが、ドライバがラップ済み例外を捕捉できず証拠収集が途中終了した。設定はfinallyで復元済み。この試行は確定根拠に採用せず、例外捕捉を修正して新Runで完走した。上記操作数にはこの試行も含む。

証拠は`build/acceptance/reference-20260918/simplesamlphp-shared-gcm*`、操作台帳・配備記録は`shared-key-input-runtime/`。証拠ファイルの秘密鍵混入検査も実施した。鍵は一時的な製品設定とプロセスメモリだけに存在し、保存したメタデータパーサ出力には追加していない。

稼働イメージは`samlscope:reference-shared-key-input-v31`、digestは`sha256:497fea94b6c8ffb1c6d3d04f6367fa1f88e7dd923c93b199a9fac91047012b95`。作業ツリーに以前から存在する無関係なSOAP差分を含めないよう、Applicationクラスは変更前の追跡ソースから再コンパイルした。ビルド入力のハッシュを配備記録に保存した。

## 検証と残件

Store・Runner・APIの回帰テストを実施した。AES共有鍵のRun／スレッド隔離、例外時の参照解除と入力バッファ消去、永続したダイジェストによる差替え拒否、未知Run拒否、秘密入力を反射しない固定エラーを検証した。API監査テストの既定ACS条件と自動オラクルの明示インベントリは、以前の実装追加へ追随する期待値に修正した。

<!--g1-literal--> G1生成一致・構造46/46、未検証台帳監査のエラー0を確認した。G2は既存のG2-30署名対象ソース差分により20/21のまま。全体完了・リリース承認とはしていない。

残るSimpleSAMLphpの鍵輸送アルゴリズムや組合せ義務は本共有鍵試験では検証できない。共有鍵の直接暗号化ではEncryptedKeyを生成しないため、RSA-OAEPの別方式・Digest／MGFの証拠として数えない。
