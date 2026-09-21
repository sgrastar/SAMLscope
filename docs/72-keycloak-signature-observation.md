# Keycloak の署名検証イベント観測

`dev/keycloak/signed_request_observation.py` は一時的なネイティブ SAML クライアントを作成し、通常ログインと既存 outbox の共通署名マトリクスを実行する。登録した公開鍵、署名必須設定、ACS を管理 API で読み戻し、処理後に自分が作成したクライアントだけを削除する。これは署名検証機能の試験準備であり、製品のメタデータ解釈を証明するものではない。

要求 ID・原文ハッシュ・直接応答の状態・応答本文ハッシュ・前後の製品イベント差分を記録する。認証情報と Cookie は保存せず、応答 URL のクエリとフラグメントも保存しない。イベント設定は実行前に保存し、読み戻しを含めて復元する。URI 集合とイベント種別集合の順序差は設定変更として扱わない。他者による設定変更を検出した場合は上書きしない。

## 実機で確認したこと

<!--g1-literal--> browser_sso_idp・metadata_idp・ecp_idp・single_logout_idp の ALG01/ALG02、計 8 ケース観測について、正常・本文改変・参照改変・署名値改変の計 32 条件を収集した。正常要求には相関する SAML 応答があり、異常条件 24 件の直接応答は HTTP 400、同じ送受信区間で製品の LOGIN_ERROR / invalid_signature が記録された。全条件で観測した要求のハッシュが Suite の outbox 原文と一致した。

ただし製品イベントには SAML 要求 ID がなく、clientId も null だった。前後の取得差分や時刻だけでは要求との相関を証明できない。この結果は診断用とし、汎用の「Invalid requester」表示を署名拒否の根拠にしない。正常応答の暗号学的検証と要求単位の製品イベント接続が正式採用の前提となる。

`dev/reference-acceptance/diagnose_keycloak_signed_requests.py` が、各 fixture の outbox 記録・HTTP 観測・相関応答・イベント内の要求 ID を照合し、欠けている証拠を `signature-diagnosis.json` へ出力する。製品 Verdict は変更しない。

<!--g1-literal--> この診断段階では未検証台帳を 452 観測に据え置いた。以下の正式接続では新しい Run の要求相関イベントを使い、この診断を解消数へ加算していない。

## 中断と復元

SLO プロファイルの初回は、Keycloak が ACS 一覧を並べ替えて返したため、厳密な配列比較が設定不一致を誤検出した。イベント種別一覧の復元確認にも同じ問題があった。集合として比較する実装へ修正し、残った一時クライアントの設定・識別子を照合して削除し、イベント設定の復元を確認した。失敗記録を上書きせず、`recovery.json` に追加の復元確認を残した。

その後の SLO 再試行は認証前に接続が閉じられ、設定変更に到達していない。Docker daemon の状態取得と Suite の HTTP 接続もタイムアウトした。通常の Desktop 再起動も停止不能で失敗したため、許可済みの強制終了を使用して再起動した。稼働していた試験コンテナだけを再開し、Shibboleth の Tomcat も起動した。Suite と各製品の HTTP 正常応答を確認後、新しい SLO Run でマトリクスを完走し、一時クライアント削除・イベント設定復元まで確認した。起動途中の認証失敗も記録に残し、試験成功として数えない。

<!--g1-literal--> 初回と復旧後の Run 作成は計 5、クライアント作成 5・削除 5（追加復元を含む）、イベント設定書込 4（復元を含む）。Docker Desktop 強制停止・起動は各 1、試験コンテナ起動 5、Tomcat 起動 1、本人操作 0。保存済み Transcript は AuthnRequest 40・Response 15。認証前に失敗した SLO 再試行 2 回は Run を作成していない。コミットと全 Java/Web テストは実施していない。

証拠は `build/acceptance/reference-20260918/keycloak-native-signed-request-observation/`、完走した SLO は `keycloak-native-signed-request-observation-slo-ready/`。各プロファイルの `native-http-observations.json`、`signature-diagnosis.json`、`decoded-manifest.json`、`restoration.json` と、親の `operations.json`・`recovery.json` を合わせて参照する。失敗した SLO 再試行の出力先は `keycloak-native-signed-request-observation-slo/` と `keycloak-native-signed-request-observation-slo-recovered/`。

## 要求単位のイベント接続と正式採用

`signature-listener/` の観測プラグインは製品の `EventListenerProvider` として動作し、製品が発行した `LOGIN_ERROR / invalid_signature` のコールバック内で、その HTTP 要求の SAML 原文ハッシュと要求 ID を記録する。Suite 用の一時クライアント・POST エンドポイント・AuthnRequest・固定の要求 ID 形式に限定する。イベント、HTTP 入力、クライアント設定、認証処理を変更しない。観測失敗は欠測として扱い、製品の検証結果を変更しない。

コンパイルには稼働中の Keycloak から取得した SPI ライブラリを使用した。観測プラグインは試験時だけ配置し、realm の listener 一覧を一時的に変更する。完了時には設定を復元し、配置した jar のハッシュを照合して削除し、製品再起動後の正常応答まで確認した。認証情報、Cookie、利用者名、セッション情報、要求 XML 全文を観測ログへ保存しない。

`NativeSignedRequestEvidence` の `keycloak-native-event` 経路は次を検査する。

- 元の outbox 要求を Run の鍵で再生成し、指定された改変 fixture と完全一致すること。
- イベントの要求 ID・原文ハッシュ・issuer と、送信した原文が一致すること。
- 製品イベントが署名エラーであり、イベント時刻が対応する送受信区間内であること。
- 異常要求への直接 HTTP 応答を元エンドポイントで受信し、相関する SAML 応答が存在しないこと。HTTP エラーだけでは確定しない。
- 正常要求への相関した Success 応答について、対象メタデータの鍵による Response 実署名と対象アルゴリズムを検証できること。

<!--g1-literal--> 新しい 4 Run で 32 条件を収集し、ALG01/ALG02 の 8 観測が正式 PASS になった。未検証は 452 → 444、異なるケース ID は 156 → 154。共通 BROWSER 試験であり、ECP SOAP や SLO メッセージ固有の検証を代替したものではない。

<!--g1-literal--> 各観測で 17 種、計 136 の負の対照を原文再生時に検査した。Run・ケース・要求・イベント・対象メタデータ・fixture・応答・HTTP status・原文ハッシュ・エンドポイントに加え、ネイティブ記録のハッシュ・issuer・時刻・イベント種別と、間接 HTTP 応答への置換を NOT_VERIFIED として退けた。台帳採用器は設定復元、原文、対照、正式判定、証拠参照の一致を検査する。

<!--g1-literal--> 正式採用バッチの操作はクライアント作成 4・削除 4、イベント設定書込 2、観測 jar 配置 1・削除 1、製品再起動 2。Suite build・Suite 再作成・転送コンテナ再作成は各 1、receipt 配置 8、正式評価 4、本人操作 0。操作記録は `native-keycloak-signature-runtime-v58/acceptance-operations.json`。収集した証拠は `keycloak-native-signature-audit/<profile>/`、製品内の観測ソースと配置・撤去記録はその親に保存した。

実行イメージは `samlscope:reference-native-keycloak-signature-v58`。`native_signature_campaign.py` はライブラリ取得・ビルド・配置・試験・設定復元・jar 撤去・再起動を一括実行する。既存プラグインの置換や、途中で変更された設定の上書きは拒否する。

<!--g1-literal--> 一括スクリプト自体も metadata_idp の追加 Run 1 件で実機確認した。ネイティブ署名エラー 6 件を収集し、クライアント削除・realm 設定復元・jar 撤去・再起動まで成功した。この動作確認は正式解消数へ加算していない。追加操作はクライアント作成 1・削除 1、イベント設定書込 2、jar 配置 1・削除 1、製品再起動 2。記録は `keycloak-native-signature-automation-check/`。

採用漏れ確認として、新しい正式結果と未検証台帳を製品・プロファイル・ケースで突き合わせた。今回採用分以外に PASS/FAIL/WARNING として残っている候補はなかった。結果は `native-keycloak-signature-runtime-v58/additional-adoption-candidates.json` に保存した。G1 と原文・対照・正式評価の確認をまとめて行い、全 Java/Web テストの再実行とコミットは行っていない。

<!--g1-literal--> G1 生成一致・構造検証 46/46。G2 は 20/21 で、既知の G2-30（保護された実装ソースと署名済み承認の差分）が残る。今回の実証解消を、リリース承認の完了とは扱わない。
