# EC署名の製品監査記録と正式評価

Shibboleth の ECDSA-SHA256 受理を、製品自身が取り込んだ元メタデータ、署名済み要求・応答の原文、要求 ID を持つ製品監査記録で確認した。ブラウザ SSO と metadata プロファイルの独立 Run を正式評価へ接続し、比較表と未検証台帳へ採用した。

<!--g1-literal--> 未検証はこのバッチで 458 → 456 観測。異なるケース ID は 156 のまま。新規確定は IIP-ALG03-a-idp-01 の Shibboleth / browser_sso_idp と metadata_idp の PASS 各 1 件で、製品 FAIL は追加していない。

## 判定に使った証拠

- RSA 対照要求と EC 要求に相関する成功応答を、対象メタデータの署名鍵で検証する。
- 正常 EC 要求と破損 EC 要求は同じ公開鍵を用いる。破損要求は本文 Reference の digest が有効で、SignatureValue の検証だけが失敗することを検査する。
- 破損要求に対し、製品監査の `MessageAuthenticationError` を要求 ID・SP entityID・時刻・binding・profile で照合する。ローカルエラーページ、無応答、キャンペーン終了だけでは拒否としない。
- 監査形式だけを一時変更し、署名検証ポリシーは変更しない。採用時に元の監査設定・メタデータ provider の復元を検査する。監査から保存するのは対象 Run の許可済み項目のみで、利用者名やセッション情報を保存しない。
- ローカル receipt は Run、対象メタデータ SHA-256、元 Transcript のハッシュに束縛する。証拠が不足した場合は NOT_VERIFIED を維持し、EC 非対応とは判定しない。

<!--g1-literal--> 原文再生では wrong-run / wrong-request / wrong-event / wrong-metadata / missing-condition の負の対照 5 種を両 Run で検査した。台帳採用器は原文、負の対照結果、復元記録、正式 PASS、attested=false、正式評価に使った Transcript 参照の一致を検査する。

## 実行経路と残る範囲

`signature_audit_campaign.py` は両プロファイルをまとめて収集可能にした。`NativeEcSignatureEvidence` を実ランタイムの browser registry に接続し、専用の `protocol-evidence/evaluate` 経路で評価する。通常ログイン完了が前提であり、証拠収集だけではその前提を満たさない。

<!--g1-literal--> 最初に手動 configure API を呼び 500 となった。プロトコル評価対象を手動確認で確定させない既存ガードが原因であり、ガードは維持した。その後の正規評価は通常ログイン未完了のため ready=0、ログイン完了後の再評価で PASS になった。これらも操作記録へ残した。

先行するローカルエラー経路と remote-error 設定試行の証拠も保存した。SAML エラー応答を得られなかった試行は確定根拠に使っていない。ECP、SLO、他製品へ今回の結果を流用していない。

## 保存先と再現

証拠は `build/acceptance/reference-20260918/` 以下の `shibboleth-ecdsa-native-audit/browser_sso_idp/` と `shibboleth-ecdsa-native-audit-metadata/metadata_idp/`。`evaluation/result.json` が採用した正式結果。操作は `native-ec-runtime-v54/acceptance-operations.json` に試行、設定変更・復元、再起動、プロトコル要求数、通常ログイン操作をまとめた。

```sh
.venv/bin/python dev/reference-acceptance/verify_native_ec_acceptance.py build/acceptance/reference-20260918
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```

EC 採用時の実行イメージは `samlscope:reference-native-ec-v54`。全 Java/Web テストの再実行やコミットは行っていない。その後の共通アルゴリズム監査による再検証対象への戻しと追加修正は [監査記録](69-algorithm-verification-evidence-audit.md) を参照。冒頭の件数は EC 採用時点の差分であり、最新台帳とは区別する。

## ECP・SLO プロファイルの共通試験経路

`import_metadata_batch.py` と `signature_audit_campaign.py` の CLI が ECP・SLO プロファイルを選択できなかったため、既存の共通 BROWSER 試験をそれらの Run でも実行可能にした。承認済み ALG03 の fixture と判定条件は変更していない。

<!--g1-literal--> ecp_idp と single_logout_idp の新しい Run で RSA 対照・正常 EC・破損 EC の 3 条件をそれぞれ実行し、通常ログインも完了した。元のメタデータ・要求・署名付き応答と要求単位の製品監査記録を検査して、2 観測が正式 PASS となった。Keycloak 共通署名の採用後から未検証は 444 → 442。異なるケース ID は 154 のまま。

<!--g1-literal--> 負の対照は各 Run 5 種、計 10 を確認した。追加の Transcript は AuthnRequest 12・Response 6。元の監査設定、メタデータ provider、通常ログイン用設定を復元した。監査変更と復元の製品再起動・Tomcat 起動はそれぞれ 2、本人操作は 0。Suite の追加ビルドは不要で、v58 の既存 EC 判定経路を使った。

証拠は `shibboleth-ecdsa-native-audit-additional/{ecp_idp,single_logout_idp}/`。`native-ec-verification.json`、`baseline/operations.json`、`receipt-installation.json`、`evaluation/result.json` を台帳採用器で照合する。他プロファイルの結果を流用せず、各 Run の原文と実測から採用した。

<!--g1-literal--> 追加バッチ全体の設定書込は 18（監査形式と復元、各メタデータ fixture、provider 登録・復元、通常ログイン準備を含む）、再読込 12、一時ファイル削除 4。集約記録は同じ親ディレクトリの `acceptance-operations.json`。
