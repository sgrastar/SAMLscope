# 自己点検

> 追記（2026-10-31）：以下は当初のオフライン準備の記録。後続のユーザー承認に基づくKeycloak管理API調査とlive設定driverは[SELF-REVIEW-KC.md](SELF-REVIEW-KC.md)に記録した。SAML campaign全体と全4ケースの採用は引き続き保留。

2026-10-31。オフライン準備の記録。正式判定・台帳更新は行っていない。

## 作成物と到達点

- `PLAN.md`: case定義、全variant、正負対照、Shibbolethとの差分、保存製品コードに基づく設定仮説、未確定事項。
- `campaign.py`: 要求行列の再利用、Run/digest/前提の事前確認、元状態捕捉、normal/maximum群の適用、条件通信前後の製品read-back、finally復元、元状態照合、個別カウンター。
- `keycloak_campaign.py`: dry-run CLI、公開native設定のGET/compare/write/GETと復元を実装するbatch。書込みの応答喪失でも製品read-backで既知の変更か確認し、外部編集を上書きしない。
- `simplesamlphp_campaign.py`: dry-run CLI、既存ConfigurationBatchを使う公開設定fragmentのhost書込み・復元。inodeを維持し、Docker fallbackは禁止する。
- `test_campaign.py`: メモリdriver、公開fixtureファイル、CLIの単体テスト。
- `dry-run-keycloak/plan.json`、`dry-run-simplesamlphp/plan.json`: 条件、停止理由、条件付き回数見積。実施済み操作の記録ではない。

**ライブ用製品driverと製品別の独立receipt readerは未実装。実機で確定できる状態にはまだ達していない。**
保存資料が示す未実装・未確認機能を、推測による設定や独自の比較コードで補わなかった。
CLIは`--dry-run`必須で、実機実行フラグ・HTTP client・Docker呼出し・任意shell hookを持たない。
ライフサイクルは将来の信頼済みdriverの接続点とし、今回はメモリdriverでのみ検証した。
各driverのboolean前提や`product-runtime`ラベルは、その収集実装が独立に検証された場合だけ意味を持つ。
ラベルを含む任意JSONやオペレーターの自己申告を証明として受理するAPIは設けていない。

## 誤判定リスク

|点検項目|今回の対策 / 残る検証|
|---|---|
|全errorをg系成功扱い|reportは常にsupplemental-unadopted。case outcomeもVerdictも出さない。全error envelopeのテストでもconformance成功にならない。将来は既存AuthnContextComparisonの各kind成功選択対照を必須にする。|
|達成不能要求のerror対照|ga/gb/gcそれぞれClassRef/DeclRefのunachievableを要求行列に残す。原本の相関・署名・実際のSAML error検証は独立readerに必要。HTTP errorで代用しない。|
|maximumの弱すぎる選択|low/mediumのEXACT成功を同じmaximum設定で収集。high不達と利用可能集合の網羅性もnative前提。low返却を上限以下という理由で適合にしない。|
|先頭優先の検出力|low/high独立EXACT対照とforward/reverseの両方を各kindで予定。errorだけや片方の順序だけでは採用不可。|
|Suite独自の強度|ShibbolethのURNを計画テンプレートとして再利用するだけ。製品のmap/flow/sourceが実際に定めた順序でなければ送信前に保留。認証手段の一般的な強弱を仮定しない。|
|DeclRef未対応|ClassRefだけの部分実験を全caseの成功へ拡張しない。両製品とも現在は事前条件未成立。|
|沈黙/HTTP500/設定未適用|timeout、HTTP error、UNKNOWN_DELIVERY、native read-back不一致でincompleteに止まるテストを実施。製品FAILには変換しない。|
|直接HTTP送信|スクリプトは送信機能を持たない。将来driverは既存Runの永続outboxだけを消費する。preloaded-recorder-only receiptを拒否するテストあり。既存CONFIG gケースはaction keysが空なので経路整備前は保留。|
|重複送信/擬似成功|requestId/actionId/request/response参照の重複を拒否。同一mode/conditionを一度ずつ処理し、例外後の再試行はしない。実ブラウザ側の二重click防止は未検証。|
|別Run原本の付け替え|Run/hash/condition/modeの一致を確認。foreign Runは収集停止。保存Runのcase追加やTranscript書換え機能はない。IDP19.b専用bindingを流用しない。|
|証拠検証の過大主張|envelope照合は暗号検証ではない。署名・復号・metadata・宛先・issuer・request fingerprint・session/operationを検証する独立readerは別途必要。未検証receiptは正式evidenceに昇格しない。|
|正負対照の省略|caseとmutantのID・triggerをPLANへ記録。今回は製品の正負対照を実行していない。単体テスト成功をcontrol VERIFIEDへ書き換えない。|
|host書込みと製品適用の混同|host成功、native write成功、製品read-backで確認した群適用、復元試行/成功を別集計。既存ConfigurationBatch.applied_countはnative適用数として使わない。|
|復元失敗|最初のapply前にdirtyにし、途中例外でもfinally復元。元状態の実効fingerprintと一致しなければincomplete。外部編集は上書きせず手動確認対象。|
|プロセス停止/電源断|finallyだけでは対処できない。元公開状態は現在メモリ内のみ。将来ライブdriverには秘密を含まない復旧snapshot、write前journal、再開時のnative照合と重複action防止が必要。現コードをそのままライブ公開しない。|
|資格情報|今回は資格情報、鍵、.env、privateを読まない。ログに任意driverデータや例外本文を出さず、許可した公開envelopeだけを出す。将来driverの秘密除去は別に検証が必要。|
|case側Verdict|case実装は変更していない。準備コードもoutcome/Verdictを生成しない。既存caseはoutcomeのみ、Evaluatorが正式levelに従って変換する。|

## 実機前に確認するもの

1. 許可された環境で署名定義とG1/G2境界、profile・実Runのcase membership/digest、推移的linked variantsを検証する。保持定義の古いRunを新定義で再開しない。
2. native機能調査をログインより先に実施する。Keycloakの稼働版・SAML step-up feature・実際のURI/LoA属性名・flow/execution/config/mapperとDeclRef対応を確認する。
3. SimpleSAMLphpの稼働版標準selectorがminimum/better/maximumとDeclRefを扱えるか確認する。保存版の未実装を解消できなければNOT_VERIFIEDを維持する。独自PHPで製品動作を作らない。
4. 専用client/flowまたは公開selector fragmentの隔離範囲、元状態、依存、復元権限、保存可能な公開値を確定する。既存authsources全体や秘密を含むrealm exportは証拠にしない。
5. 製品自身が解釈した稼働設定のread-back方法を実装する。管理GETの設定値だけではflow実行を証明できない。PHP opcache・bind mount等の不反映はログイン前に診断する。
6. 比較全条件を既存Runnerの永続outbox actionと結び付ける実装・独立検証を用意する。CONFIGへのcase選択だけ、preloadedへのURL組立てだけでは要件を満たさない。
7. 現在のRun・metadata・ログイン入力を固定し、low/highとmaximum low/mediumの実成功、high不達、達成不能errorを原本で確認する。変わった設定間で可用性を流用しない。
8. visible browserで利用者が入力する。fresh/reuseをSuite指示どおりにし、passiveで入力しない。認証ヘッダー、Cookie、生のlogin HTML、storage、画面を保存しない。
9. Recorder decoded原本digest、元request/responseとactionの一意相関、署名・復号・issuer/ACS/Audience/SubjectConfirmation/RelayState、固定request fingerprintを独立readerで検証する。
10. caseごとの正負対照を再実行し、欠落・重複・foreign Run・不一致response・未検証controlの変異がNOT_VERIFIEDになることを検証する。
11. 復元後の製品read-backと同じRunの通常SSO対照を確認する。採用は独立検証後だけとし、comparison/inventoryは既存generatorで更新する。

必要な実機側のものは、隔離した製品、公開設定読取/変更/復元権限、対象caseを含む現行Run、互換な署名Suite、outbox対応経路、製品別read-back driver/独立reader、利用者のvisible browserである。
今回の資料から両製品の全機能成立を約束することはできない。

## 操作回数

|項目|今回の実測|全前提成立後・1製品・再試行なしの計画|
|---|---|---|
|製品設定書込試行/host成功/native成功/実効適用/復元|すべて0|2設定群＋復元1群。各群の実write数は依存オブジェクト数で増えるため未確定。1群1writeなら最低3試行。Keycloak管理API方式のhost設定writeは該当なし0。|
|条件通信|0|24。承認評価条件16、maximum可用性対照4、先頭候補可用性対照4。|
|通常SSO|0|復元後1、初期対照が未完了ならさらに1。計25〜26往復。|
|ログイン投入|0|全操作がfreshなら最大26を基準とする。MFA、re-auth、追加管理ログインが必要なら増える。実測値は未測定。|
|明示ログアウト|0|0予定。context破棄とlogoutは別。必要になれば追加計上。|
|利用者click/同意/管理画面操作|0|未測定。認証1回で最低1回の送信操作を想定する場合でも、画面遷移やMFA分が増えるため上限は確定しない。|
|製品実効read-back|0|共通エンジンの最低53呼出し。各呼出しの内部API/PHP読取数は依存ごとに別集計する。|

2製品では条件通信48、通常SSO込み50〜52を見積もる。現段階は前提が不成立なので、実機実行予定は0のまま。
dry-runとメモリfixtureのwrite数を製品設定変更数として数えていない。

## 検証結果と未実施チェック

追加25件と既存`dev/simplesamlphp/test_configuration_batch.py`6件、計31件が成功。
4つのPythonファイルのAST構文検査も成功。両CLIのdry-runで計画JSONを生成した。
テストの再実行ではPython audit hookでsocket/外部プロセス起動、禁止ファイル読取り、指定先外のwriteを拒否した。
既存テストのDocker呼出しはmockであり、実際のDockerプロセスは起動していない。

ログは指定jobディレクトリの`unit-tests.log`と`test-results.json`。外部操作audit付き実行で31 tests / 0 failures / 0 errors。
反映遅延、native機能、実HTTP、Chromeのsession動作、正負対照の暗号検証、署名承認の再検証はこのテストの対象外。

AGENTS.mdの通常チェック`g1_docgen.py --check`と`g1_validate.py --structural-only`は、今回明示的に読み取り禁止されたcoverage/specs/predicates/approvalsを読むため実行していない。
Gradle、ブラウザ統合、G1全比較、G2実行も、指定先外への出力・禁止入力・ネットワーク等を避けるため実行していない。
したがって構造チェック合格・release readiness・独立承認を主張しない。

既存ファイルは変更していない。作業開始時に`git status --short --untracked-files=no`で表示された既存AGENTS.mdの変更は触らず、その差分も読んでいない。
成果物のwrite先は指定sso01gとjobの子のみ。commit、push、Docker、ネットワーク、台帳更新は行っていない。
