# SimpleSAMLphp の共通署名試験

SimpleSAMLphp の共通署名試験へ、製品が直接返す署名検証エラーの観測を接続した。汎用 HTTP エラーを拒否へ変換せず、正常な署名の受理、署名付き成功応答の作成、本文・参照・署名値を破損した要求への具体的な検証エラーを組み合わせる。

<!--g1-literal--> ALG01 と ALG02 を browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp で実行し、8 観測を正式 PASS に確定した。未検証は 460 → 452 観測、異なるケース ID は 156。各プロファイルの共通 BROWSER 試験であり、ECP SOAP・SLO メッセージ固有の署名試験を代替したとは扱わない。

## 製品のエラーと Suite の証拠

稼働中の製品ソースで、IdP が `Message::validateMessage` を呼び、署名検証が有効な場合に `checkSign` を実行する経路を確認した。元の SP メタデータを製品自身のパーサーで取り込み、`validate.authnrequest=true` を確認した。Suite 側で署名ポリシーを模倣して判定したものではない。

実機の直接応答では、本文・参照先の破損に対して `SimpleSAML\Error\Exception: Validation of received messages enabled, but no signature found on message.` が現れた。署名値の破損は、対象要素が AuthnRequest の `NOTVALIDCERTSIGNATURE` だった。前者は単に「署名なし要求を送った」という意味ではなく、Suite の原文再生で署名を持つ指定の破損 fixture であることを別途検証する。

観測器は固定の署名エラー種別、要求 ID、要求原文 SHA-256、要求・応答 URL、応答時刻、応答本文のハッシュを保存する。Cookie、認証情報、フォーム入力、エラーページ全文は保存しない。一般的な `UNHANDLEDEXCEPTION`、画面の「Signature failed」という語、別種の SAML 要素、正常 HTTP 応答、script/style 内だけの文字列は、この分類の根拠にしない。

判定器は既存の outbox 原文を Run の鍵で再生成して一致させる。正常応答の実署名を対象メタデータの鍵で検証し、作成側のアルゴリズムを確認する。異常系は、元の要求を送った同じエンドポイントからの直接応答であり、要求ハッシュと時刻が一致し、当該 fixture に対応する明示的な署名エラーがある場合に限り採用する。汎用エラー、別 URL へのリダイレクト、無応答、衝突する SAML 応答は未検証のままにする。

## 実証と負の対照

<!--g1-literal--> 初回の観測では汎用エラーコードだけを記録していたため採用しなかった。診断用に破損要求 3 件を再送して具体的な製品エラーを調べた後、詳細な分類を接続して新しい Run で全マトリクスを再実行した。初回と診断用再送は正式判定の証拠に使っていない。

<!--g1-literal--> 各観測で、Run・ケース・要求・エラー・対象メタデータ・fixture・応答の取り違え／欠落に加え、HTTP status・原文ハッシュ・エンドポイントの取り違えを含む 12 種の負の対照を確認した。8 観測分、計 96 対照が NOT_VERIFIED となった。これらを製品観測の解消数へ加算していない。

分類器には、汎用エラーや別要素、正常応答、非表示スクリプトだけのエラー文字列を拒否する確認を追加した。本バッチはコンパイル、実機マトリクス、原文と対照の再生、正式 API 評価をまとめて実施した。全 Java/Web テストの再実行とコミットは行っていない。

## 設定操作と保存先

<!--g1-literal--> 初回・診断・再実行を含め、Run 作成 8、製品設定の書込は復元を含め 12、製品再起動 0、本人操作 0。Suite に記録された AuthnRequest は 80、Response は 32、これに未採用の診断用再送 3 件が加わる。Suite build、Suite 再作成、転送コンテナ再作成は各 1、receipt 配置 8、正式評価 API 呼出し 4。全プロファイルで設定の差分だけを適用し、最後に元のバイト列への復元を確認した。

採用した証拠は `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/<profile>/`。原文と対照は `verification/protocol-verification.json`、正式結果は `evaluation/result.json`。稼働製品の検証関数と呼出し元は親の `native-source/` にソースとハッシュを記録した。

操作記録は `native-ssp-signature-runtime-v57/acceptance-operations.json`、実行イメージは `samlscope:reference-native-ssp-signature-v57`。台帳は `verify_native_signed_acceptance.py` が設定復元、元 fixture、読み戻し、原文、対照、正式判定と証拠参照の一致を検査した結果を採用する。

```sh
.venv/bin/python dev/reference-acceptance/verify_native_signed_acceptance.py build/acceptance/reference-20260918 simplesamlphp
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```

Keycloak の同種ケースは引き続き未検証。今回の製品固有エラーを他製品へ流用しない。
