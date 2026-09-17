# 共有鍵GCM復号の基盤と不透明なAssertionの判定修正

## 完了した実装

SimpleSAMLphpの稼働ライブラリEncryptedAssertionを確認した。RSA鍵の場合はAES128-CBCのデータ鍵を生成するが、AES共有鍵を渡した場合はその鍵種別で直接Assertionを暗号化する。共有鍵GCMは調査した実装に存在し、前回の公開鍵経路の実測だけからGCM非対応とは判定できない。

SuiteにAES共有鍵による復号処理を追加した。SamlDecryptionKeyProviderにRun単位の共有鍵供給口を設け、暗号アルゴリズム観測から利用できるよう接続した。既存のRSA秘密鍵供給は維持する。共有鍵の供給がない既存実装では従来と同じ動作になる。レスポンスから鍵を取得したり、CaseStateへ鍵を保存したりしない。

AES128-GCM／AES256-GCMの実暗号文を使い、正しい鍵で復号できること、誤鍵と改変された認証タグでは失敗すること、保存対象の暗号文DOMを変更しないことを検証した。SAMLとRunnerの回帰テストもまとめて成功した。

この段階では、製品へ設定する共有鍵とSuiteのRunを結び付ける実行時入力経路は未実装。鍵の固定・寿命・秘密情報の非記録・製品設定の復元を伴う接続を次に実装する。単体テストのGCM成功は実製品のVerdictへ数えない。

## principal判定の修正と実環境確認

未復号EncryptedAssertionを読んだprincipal判定が、Subject要素を見つけられないことを理由にSATISFIED_WITH_NOTEとしていた。暗号化されていて確認できないことは、Subjectが存在しない証拠ではない。この経路をNOT_VERIFIEDへ修正した。

`build/acceptance/reference-20260918/simplesamlphp-opaque-principal-control/` の新Run `run_NXTAXWN71DEJF02ZNAQXS4AZA8` で確認した。IIP-SSO01.czは `saml.subject-principal.undetermined`、既存のIIP-ALG06.aは復号を伴うPASSを維持した。以前の不透明なAssertionに対する注記付き成功は台帳へ採用していなかったため、確定件数の取り消しはない。今回の未検証理由と次アクションを生成台帳へ更新した。

principalの意味的判定には、復号したAssertion内のSubjectConfirmation・属性を含め、Suiteが認証したprincipalとの対応付けが別途必要。暗号化を解除しただけでは同一principalと確定しない。

## 記録

<!--g1-literal--> 未検証は485観測・159ケースIDのまま。今回の製品設定書込2（投入・復元）、ネイティブ取込1、Run作成1、preflight1、Docker build1、Suite／転送コンテナ再作成各1、本人操作0、製品再起動0。元設定のSHA-256一致で復元を確認した。

製品ライブラリ原本とハッシュは `build/acceptance/reference-20260918/shared-key-foundation/`、配備記録は `shared-key-runtime/` に保存した。稼働Suiteは `samlscope:reference-shared-key-foundation-v30`、digestは `sha256:e312182078e8cf899a24a3c753cdcfe5c93f1e8f1c3f6200c853c4040c93e68c`。

G1生成一致・構造検証を実施。G2の既存署名差分は引き続き未解消として扱い、全件完了・リリース承認とはしない。
