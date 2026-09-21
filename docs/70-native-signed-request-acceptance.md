# 共通署名試験の製品監査接続

無応答を成功扱いした過去結果を戻した後、Shibboleth の共通署名試験を要求原文と製品監査で再実施した。`NativeSignedRequestEvidence` を正式な browser registry と記録済み証拠の再評価へ接続した。ケースは Outcome を返し、Verdict は既存の Evaluator が決める。

<!--g1-literal--> ALG01（SHA-256 の作成・検証）と ALG02（RSA-SHA256 の作成・検証）を browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp で実施し、8 観測を正式 PASS に確定。台帳は 468 → 460 観測、異なるケース ID は 156 のまま。各プロファイルの共通 BROWSER ケースを実行しており、ECP SOAP や SLO メッセージ固有の署名を試したという主張ではない。

## 原文と判定条件

既存の outbox シナリオが作る VALID / TAMPERED_ACS / BAD_REFERENCE / BAD_SIGNATURE_VALUE をそのまま送信する。収集ツール自身は試験メッセージを作らず、Suite の active-probe 経路を実行する。

判定器は Run の署名鍵、要求 ID、時刻、登録済み送信先と ACS から元 fixture を再生成し、Transcript 原文とバイト一致を検査する。これにより、無関係な不正 XML を破損署名 fixture として扱わず、どの部分が変更された要求かを確認する。outbox action ID、ケース ID、fixture ID も相関させる。

正常系は相関する成功応答の実署名を対象メタデータの鍵で検証し、該当する DigestMethod または SignatureMethod を確認する。異常系は各要求 ID に一致する Shibboleth の `MessageAuthenticationError`、SP entityID、binding、profile、時刻を検査する。無応答だけ、一般的な実行エラー、別要求の監査記録では成功にならない。衝突する SAML 応答がある場合も採用しない。

ローカル receipt は対象メタデータ、Run、ケース、原文ハッシュに束縛する。不足箇所は receipt / originals / fixture / native-event / producer-signature の診断として返す。既存の手動「応答なし」報告は未検証のまま維持する。過去のシナリオ定義で進行中だったアルゴリズム試験を新しい試験と混同しないよう、シナリオの定義キーも更新した。

## 試験と収集時の修正

<!--g1-literal--> 要求マトリクスの原文検証に加え、wrong-run / wrong-case / wrong-request / wrong-event / wrong-metadata / missing-condition / duplicate-fixture / wrong-request-original / wrong-response の 9 種を各観測で検査した。計 72 の取り違え・欠落対照がすべて NOT_VERIFIED となった。これは実機記録の再生検証であり、新たな製品観測数には加算していない。

初回の収集では `case.in-progress` を完了と誤認し、通常ログインの後で要求マトリクスを実行せず終了していた。receipt 生成時に必要な原文がないため検出され、判定を採用する前に停止した。終了条件を明示した語彙へ修正し、新しい Run で再実施した。初回の試行も設定復元を確認して保存している。

本バッチはコンパイル、原文再生と負の対照、正式 API 評価、台帳整合検査を行った。全 Java/Web テストは繰り返していない。コミットも行っていない。

## 操作と証拠

<!--g1-literal--> 初回と修正後を合わせて Run 作成 8、製品ファイル書込 28（監査形式の変更・復元を含む）、metadata service 再読込 16、一時メタデータ削除 8、製品再起動と Tomcat 起動は各 4。記録された AuthnRequest は 44、Response は 20。Suite build、Suite 再作成、転送コンテナ再作成は各 1、receipt 配置は 8、正式評価 API は 4。ユーザー本人の操作は 0。

監査形式の変更を全プロファイルで共有して、ケースごとの再起動を避けた。各 Run の一時 provider は復元し、最後に監査形式も元のバイト列へ戻している。操作記録は `build/acceptance/reference-20260918/native-signed-request-runtime-v56/acceptance-operations.json`。

採用した証拠は `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/<profile>/`。`verification/protocol-verification.json` が原文と負の対照、`evaluation/result.json` が正式結果、`receipt-installation.json` が配置と読み戻し。最初の不採用試行は同階層の `shibboleth-native-signed-request/` に残した。

実行イメージは `samlscope:reference-native-signed-request-v56`。`verify_native_signed_acceptance.py` が設定復元、原文、対照結果、配置、正式判定と証拠参照の一致を検査し、比較表と台帳はこの検査を経たケースだけを採用する。旧結果の監査による差戻しは履歴として保存し、Keycloak と SimpleSAMLphp の証拠不足は未検証のまま残している。

```sh
.venv/bin/python dev/reference-acceptance/verify_native_signed_acceptance.py build/acceptance/reference-20260918
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```
