# オフラインSLO readerの自己レビュー

対象は台帳の未検証14観測。今回の新規確定は0件であり、readerのテスト成功を製品の適合性・採用可能性として扱わない。

## 実装の境界

- `ReadSloStoredEvidence`はoffline専用の診断reader。DB、API、sender、Evaluator、Verdict、設定変更、Run更新の経路を持たない。保存outcomeと診断assessmentを分離し、assessmentは必ずNOT_VERIFIED。
- 有効なJSON/XMLが読めることやInResponseToの一致は、当該XMLの構造上の対応を示すだけ。暗号学的検証や送達・製品消費を示さない。出力の`wireBindingProven`と`nativeConsumptionProven`はfalseを維持する。
- `declaredBinding`はRecorder summaryのラベル。実際のmethod、rawQuery、HTTP Location、製品受信ログと照合したbindingの証明ではない。HTTP-Redirect queryを再構成しない。
- case membershipとresult hash・Runを照合。別Runの証拠の再ラベル、保存ケースの追加、source-Run bindingの新設は行わない。未対応native receiptを推測して採用しない。
- 重複JSON key、末尾JSON、重複tx/message ID、foreign Run、参照逃避、symlink、decoded hash/size不一致、DTD、曖昧SOAP Bodyを拒否。原本bundleの問題はNOT_VERIFIEDのgapとして保持し、製品VIOLATEDにしない。
- SOAPは全envelopeのbytesをhashしたまま、Bodyの唯一の要素をDOM参照する。再直列化・原本の差し替えは行わない。

## 誤判定しやすい原本

1. Keycloakの保存session終了はPOST交換に伴うもの。Redirect応答を受理した証明にしない。ローカルsessionの終了が応答到着前に起きる可能性も排除できていない。
2. Shibbolethの既存nativeResult=SuccessはPOST、別campaignはSOAP。Redirectへ読み替えない。古いRedirectラベル付き応答には不正な送付先があり、origin終了時刻も消費の因果関係を証明しない。
3. SimpleSAMLphpのContinue後のPartialLogoutから、当該参加者応答の受理を推測しない。参加者要求と失敗の同時到着は「失敗を知った後の続行」ではない。二重開始した旧campaignを対照に使わない。
4. SimpleSAMLphp v131iのorigin原本にはasyncと不正Destinationがある。既存採用17-sの再監査は今回範囲外だが、新しい正常同期campaignの代用にしない。
5. Keycloakの旧18-c/d VIOLATEDはそのまま採用しない。POSTも許容された設定でのPOST発行や、Suiteが選んだPOST応答はRedirect能力の反例にならない。
6. 17-b2のKeycloak/Shibboleth旧SATISFIEDは台帳で撤回済み。400、不正Destination、Suite到着ページをIdP自身のsession終了失敗feedbackに置き換えない。
7. SSP19-cの限定反例から19-a第1鍵の原本を作らない。Keycloakのmetadataに鍵が取得できない状態を製品の復号不能としない。
8. 沈黙、HTTPエラー、UNKNOWN_DELIVERY、session状態不明は製品違反の根拠にしない。今回のreaderには製品違反を生成する経路そのものがない。

## 検査結果と残る制限

JUnitは14/14成功。hash破損、Run取り違え、JSON重複、原本不在、DTD、symlink、曖昧SOAP、保存SATの誤採用、実保存bundleを検査した。製品controlは実行していない。承認済みmutantへの検出力を証明したテストではない。

19回の保存証拠再生では公開原本のbytes不変を照合した。Java readerは全messageの署名・issuer・destination・同一session・完全な参加者集合を証明しないので、相関したgraphだけで正式結論に利用してはいけない。receiptの真正性・独立性やsource definitionの互換性も別途必要。

Gradleのofflineテストはローカルsocket権限で起動失敗した。同じJUnitテストをローカルjarだけでコンパイル・実行し、Gradle成功とは報告していない。Gradle独立buildはリポジトリ本体のsettings/build/sourceを変更しない。

G1 docgen --check成功。G1 structuralとG2のblockingは既存Git設定が参照する`/tmp/samlier-g1-allowed-signers`の欠落による署名検証失敗。検証対象・validatorロジックは変更せず、書込先制約のためreportの出力先だけを変更した。チェック通過を主張せず、信頼鍵の追加やチェック回避も行わない。今回成果物は本体・採用・コミットへ組み込まない診断用の試作として残す。

`tests/`、本体ソース、既存reader、docs、正式台帳・保存Runは未変更。元から存在したAGENTS.md変更とsso01g/作業には触れていない。private/、.env、秘密鍵・鍵ストアを読まず、ネットワーク・Docker・実機・コミット・プッシュを使用していない。

## 再実行

リポジトリルートで実行。すべての出力は`build/acceptance/reference-20261031/slo/`へ置く。

```sh
.venv/bin/python dev/reference-acceptance/slo/inspect_saved_slo.py
python3 dev/reference-acceptance/slo/run_offline_checks.py
python3 dev/reference-acceptance/slo/replay_saved_slo.py
.venv/bin/python -I -B dev/reference-acceptance/slo/run_repository_checks.py
```

`run_offline_checks.py`はJDK21とローカルに既存のJackson/core/JUnit jarを使用する。依存hashを毎回記録し、replay時に再照合する。依存ファイルを取得しない。保存原本を読むだけで、成果物を台帳へ登録するコマンドは存在しない。

Gradle用入口は`dev/reference-acceptance/slo/build.gradle`。ローカルに既存のGradleを使い、user-home/project-cacheも指定出力先に置く。

```sh
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home \
/Users/yuta/.gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv/gradle-9.7.1/bin/gradle \
  --offline --no-daemon \
  -g /Users/yuta/Documents/SAMLscope/build/acceptance/reference-20261031/slo/gradle-home \
  --project-cache-dir /Users/yuta/Documents/SAMLscope/build/acceptance/reference-20261031/slo/gradle-project-cache \
  -p dev/reference-acceptance/slo test
```

単独readerの入口は`offline result.json sha256 Run Case [transcript.json decoded-manifest.json]`。候補原本から出る情報は診断であり、受理を証明するreceiptとして渡してはいけない。
