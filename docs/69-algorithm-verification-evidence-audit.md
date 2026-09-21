# 共通署名アルゴリズム判定の証拠監査

EC 署名の証拠接続後に共通署名試験を点検し、`IdpSignedRequestScenarioTestCase.observeUnavailable` に、操作報告 `operator-reported-no-saml-response` をアルゴリズム検証の成功へ変換する分岐が残っていることを確認した。応答が観測されない理由は製品の署名拒否とは限らず、ALG01 / ALG02 の受信側検証能力を証明しない。

当該ケースでは、このイベントを `NOT_VERIFIED` とするよう修正した。署名が任意の構成で破損要求を受理したことも、非対応の証拠にはしない既存の扱いを維持している。正常な応答と、相関した拒否応答が揃う経路は引き続き評価できる。

## 過去結果の扱い

<!--g1-literal--> `IIP-ALG01-a-idp-01` と `IIP-ALG02-a-idp-01` の、全製品の browser_sso_idp、および Shibboleth の metadata_idp / ecp_idp / single_logout_idp、計 12 観測を再検証対象とした。それぞれの正式結果は `attested=false` の PASS だが、参照証拠は正常な成功応答 1 件のみで、破損要求の拒否を証明する参照がない。

元の `result.json` は変更していない。`audit_algorithm_verification_evidence.py` が元結果の Run・ハッシュ・判定・証拠数と参照 Transcript の成功応答を検査し、台帳・比較表で `audit.algorithm-verification-controls-unproven` として扱う。集計監査は、この特定の再検証対象一覧と全項目が一致する場合だけ、元結果と台帳の判定差を認める。任意の監査フラグによって結果検査を回避できる仕組みではない。

<!--g1-literal--> 同バッチの EC 署名の実証解消は 2 観測。更新前 458 → EC 採用後 456 → 過去判定の監査反映後 468 観測、異なるケース ID は 156 のまま。製品 FAIL を追加したのではなく、Suite の証拠不足を再検証対象へ戻した。

## 検証と運用

<!--g1-literal--> `IdpSignedRequestScenarioTestCaseTest` と `EcSignatureSupportTestCaseTest` をまとめて実行し、11 テストが成功した。追加した負の対照は、正常な SHA-256 / RSA-SHA256 応答の後で破損要求すべてを「応答なし」として進めても、最終結果が成功にならないことを検査する。全 Java/Web テストは再実行していない。

実行環境には `samlscope:reference-algorithm-evidence-guard-v55` を反映し、正常起動を確認した。証拠とビルド・配置記録は `build/acceptance/reference-20260918/algorithm-evidence-guard-v55/`。通常の操作記録とは別に、今回の監査による追加ビルドと Suite/転送コンテナの再作成が `deployment.json` に記録されている。製品設定変更や人手操作は追加していない。

<!--g1-literal--> G1 生成一致・構造 46/46 を確認。G2 は 20/21 で、保護された実装ソースと署名承認コミットの差分による既存の G2-30 が残る。リリースゲートの完了とはしていない。

## 継続する実装

Shibboleth の再実施・正式採用は [共通署名試験の製品監査接続](70-native-signed-request-acceptance.md) に記録した。本節と冒頭の差戻し件数は監査時点の履歴であり、現在の台帳と区別する。

共通署名試験に、要求ごとの製品監査による拒否の接続を進める。EC 用の正常要求・本文 digest・署名値・応答署名・要求 ID 付き監査の照合を土台にし、SHA-256 作成と検証、RSA-SHA256 作成と検証の各条件を独立に確認する。EC の PASS を共通アルゴリズムの PASS に流用しない。

同じ無応答イベントを扱う他の試験分岐についても、承認済みの条件付き義務と必要な観測を照合する監査が残っている。今回の修正を全試験の監査完了として扱わない。
