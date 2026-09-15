# SLO共通実行基盤と判定の実装計画

対象は、未検証546観測のうち`browser.oracle-unavailable`で終わっているSLOブラウザoracle未実装の42観測です。3製品の`single_logout_idp`で共通する14ケースを、Suiteが能動的に送出するfixture、相関、対照、判定、表示まで実装します。判定は`Evaluator`が行い、ケースは`outcome`のみを返します（AGENTS.md 3）。送出はoutbox経由です（AGENTS.md 4）。

## 1. 対象ケースと必要証拠

| ケース | 必須のfixture | 観測する事実 | 主な解釈制約 |
|---|---|---|---|
| `IIP-IDP17.b` | 非同期LogoutRequest（Destination不一致／未知SessionIndex）と正常対照 | 応答を返さず、セッションへ適用しない | セッション終了自体はSHOULD。b/b1/b2/b3で分離 |
| `IIP-IDP17.b1` | 有効署名＋認証済み送信元の信頼できる非同期LogoutRequest | samlp:LogoutResponseを返さない（front/back両方） | 同期の正常対照を併置。HTTPフィードバックはb2の義務 |
| `IIP-IDP17.b2` | 成功／失敗のfront-channel非同期要求 | user-facing HTTP応答が成功/失敗を示す | 固定「成功」ページを検出するため成功・失敗を対にする。失敗誘導不能時は`not_verified(session_termination_failure_not_inducible)` |
| `IIP-IDP17.c` | （informational）上流権限・secondary_peer登録 | 伝播の有無を情報記録。Verdictなし | 非伝播はNOT_SUPPORTED。FAILにしない |
| `IIP-IDP17.r` | 3参加者で最初がタイムアウト／エラー | 伝播実装時に残りへ試行する | 1参加者のみでは`satisfied_with_note`相当の確認ができない。伝播不実装はsatisfied_with_note。タイムアウト単独でFAILにしない |
| `IIP-IDP17.s` | 非同期でない要求＋参加者失敗 | 二段目StatusCode=PartialLogout | 全成功時にPartialLogoutを要求しない。トップレベルはエラーにしない |
| `IIP-IDP17.x` | Destination不一致のLogoutRequest（署名有効）＋正しいDestination対照 | セッションへ適用しない | Destination省略の受理を要求しない |
| `IIP-IDP17.y` | 署名値／署名対象を改変したLogoutRequest | セッションへ適用しない | Redirectのクエリ署名は対象外。LogoutResponse方向が未観測なら`satisfied_with_note` |
| `IIP-IDP17.z` | 無効署名のLogoutRequest（および任意のLogoutResponse） | 内容に依拠しない | yとの分離。応答抑止をasloで正当化しない |
| `IIP-IDP17.aa` | 無効署名LogoutRequest | 応答するならエラーLogoutResponse。無応答はWARNING | SHOULD_CLASS。内部処理不能ならnot_verified。応答方向未観測は`satisfied_with_note` |
| `IIP-IDP17.al` | 署名対象を空にするtransform／識別子等を除外した署名 | 拒否する | 受容のみ違反。Suiteがfixtureの暗号学的有効性と実際の除外を自己検証する |
| `IIP-IDP18.b` | Suite SPがRedirect応答エンドポイントのみ広告＋HTTP-Redirect LogoutRequest | IdPがHTTP-RedirectでLogoutResponseを返す | RedirectとPOST併記時はRedirectを強制しない |
| `IIP-IDP18.c` | Suite SLO要求エンドポイントをRedirect限定にし、IdPがRedirect LogoutRequestを送る | 受信できる | IdP発行が未観測なら`satisfied_with_note` |
| `IIP-IDP18.d` | IdPが通常LogoutRequestを発行し、SuiteがRedirectでLogoutResponse | IdPが消費する | 非同期のみのRunは`satisfied_with_note` |

## 2. 共通基盤

### 2.1 直接HTTP送出（outbox拡張）

front-channelのブラウザ配送では、応答が来ないことを「応答なし」と確定できません（配送自体がUNKNOWNのため。AGENTS.md 4）。非同期b/b1、署名無効z/aa、Destination不一致x、transform除外alは、**配送確認とHTTP応答本文の観測**が必要です。そこでoutboxに直接HTTP配送の種類を追加します。

- `OutboundKind.LOGOUT_PROBE`（Retry.UNSAFE）を追加。
- `HttpOutboundSender`が`LOGOUT_PROBE`を処理し、POST（`SAMLRequest`フォーム）またはGET（Deflate+Base64+署名クエリ）で送出、HTTP status・ヘッダ・本文（上限1MiB）をINBOUNDトランスクリプトへ記録。
- 応答本文にSAML LogoutResponseが含まれれば既存のSAML解析対象として扱い、含まれなければ「HTTP応答のみ」として記録。
- 接続失敗・タイムアウトは例外→`UNKNOWN_DELIVERY`（製品FAILにしない）。
- 応答の相関は`actionId`。ケースは`ScenarioActionId`で待機。

### 2.2 ActiveProbeCoordinatorの拡張

直接配送のoutboxアクションを、外部ユーザーエージェントを介さずSuiteが実行します。

- `status()`で、待機中アクションの種類が`LOGOUT_PROBE`の場合、`dispatcher.dispatch`で送出し、記録されたINBOUNDエントリを`InboundCaseRouter`で待機ケースへ`InboundMessage`として配送する。
- 送出が`UNKNOWN_DELIVERY`の場合は`CaseEvent.InboundUnavailable("unknown-delivery")`で再開し、ケースはNOT_VERIFIED相当を返す。
- 待機期限は`CaseTimeoutService`が`TimedOut`で再開する。直接配送でHTTP応答が記録済みの場合は、`TimedOut`に依存せず応答本文の有無で判断する。
- `Status`に`directProbe`フラグを追加し、ドライバとレポートがブラウザ操作の有無を区別できるようにする。

### 2.3 セッション生存の対照

x/y/z/alの「セッションへ適用しない」は、次の対照で観測します。

1. ブラウザで正常ログイン（既存`IdpBasicLogoutScenarioTestCase`と同一手順）。
2. 不正fixtureを直接配送し、応答（エラーLogoutResponse／無応答／HTTP応答のみ）を記録。
3. 正しいDestination・有効署名のLogoutRequestを直接配送し、Success LogoutResponseを確認。これが成功すればセッションは不正fixtureで失われていない。
4. 2でSuccess LogoutResponseが返っていた場合は、セッションが適用された強い証拠としてVIOLATED。

3が失敗（セッション消失・エラー）した場合は2が適用された証拠としてVIOLATED。3の配送自体が不明な場合はNOT_VERIFIED。

### 2.4 fixture生成

`SamlLogoutRequestFactory`を拡張し、以下を同一セッションで順に生成できるようにします。

- Destination差替え（署名前に設定し、署名は有効なまま）。
- 署名後の改変（署名値1バイト変更／署名対象要素のテキスト変更、XMLとして妥当なまま）。
- XPath transformでIDまたはSessionIndexを署名対象から除外した署名（自己検証付き）。
- 非同期（`aslo:Asynchronous`）の付与。

各fixtureは`fixture_id`と`ActionIds.derive`による決定的`actionId`を持ち、`CaseState`で段階を管理します。

### 2.5 判定と表示

- 判定は既存の`LogoutTranscriptProfileCase`の規則を拡張し、`Rule`ごとに以下を返します。
  - 直接配送応答の有無・HTTP status・SAMLメッセージ種別・Destination・署名検証結果。
  - 対照（正しいDestination）の成否。
  - セッション生存の成否。
- 結果は`PublicCaseDiagnostics`へ`fixture_id`、`probe_transport`、`response_kind`、`control_outcome`を追加して表示します。
- 理由コードはケース個別に定義し、`docs/26`と`docs/23`へ生成器で反映します。

## 3. 解釈判断が必要な項目（実装前に確認しないと誤判定になるもの）

1. **b2のHTTP応答観測**: 直接配送で得たHTML本文・HTTP statusを「user-facing応答」とみなすか。ブラウザと同一ではないが、応答本文の差（成功／失敗）を観測できます。承認済みvariantは「user-facing HTTP response」を要求するため、自動配送の応答をそのまま証拠にできると考えます。
2. **r/sの多参加者**: 「3参加者」「secondary_peer登録」は対象製品側に2つ目のSPを登録する運用操作が必要です。Suite側は2つ目のSPエンドポイントを公開できますが、対象IdPへの登録（Keycloak管理API、Shibboleth設定、SimpleSAMLphp設定）を操作として記録する必要があります。1参加者しか登録できない場合はrを`satisfied_with_note`にできません（試験経路の不備を任意機能未発動と扱わない）。NOT_VERIFIED（経路未整備）とし、多参加者登録を実装します。
3. **18-cの広告条件**: Suite SPのメタデータでSLO要求エンドポイントをRedirect限定にするfixtureを、既存のメタデータ公開機構に追加する必要があります。既存の公開メタデータを書き換えず、実験用の別Plan/エンドポイントとして追加します。
4. **b1の「応答なし」**: 直接配送のHTTP応答が返ったこと（status任意）を配送確認とし、SAML LogoutResponseが含まれない場合に「LogoutResponseを返さない」をSATISFIEDとします。HTTP応答自体がない場合（接続断）はUNKNOWN_DELIVERYでNOT_VERIFIEDです。

## 4. 実装順序

1. `OutboundKind.LOGOUT_PROBE`と`HttpOutboundSender`対応、セッション生存・改変fixture、Coordinator拡張、`LogoutProbeScenarioTestCase`（x/y/z/aa/al/b/b1）。
2. 実製品3社でx/y/z/aa/al/b/b1を実行し、証拠と台帳を更新。
3. 18-b（Redirect限定広告とbinding観測）、18-c/d（Suite応答binding fixture）。
4. b2（HTTP応答本文の成功／失敗対照）、c（informational）、r/s（多参加者登録）。
5. Keycloakメタデータ観測経路（別節で分類・実装）。

## 5. バッチ1の結果（IIP-IDP17.x / y / z / aa / al）

Suite側の直接HTTP送出（`LOGOUT_PROBE`）と、正しいDestinationの対照LogoutRequestによるセッション生存確認を3製品で実行しました。対照がSuccessを返せば、craftされた要求はセッションへ適用されていません。

| ケース | Keycloak | Shibboleth | SimpleSAMLphp | 観測した事実 |
|---|---|---|---|---|
| `IIP-IDP17-x` | Success | Success | Success | Destination不一致の要求は適用されず、対照の有効要求がSuccess |
| `IIP-IDP17-y` | Warning | Warning | Warning | 改変署名は適用されない。IdPが応答を消費する方向は未観測のため`satisfied_with_note` |
| `IIP-IDP17-z` | Warning | Warning | Warning | 無効署名の内容に依拠しない（セッション維持を対照で確認）。上と同じ注記 |
| `IIP-IDP17-aa` | Warning | Warning | Warning | 無効署名に対してSAMLエラー応答を返さない（SHOULD違反相当・無応答はvariant規定どおりWARNING） |
| `IIP-IDP17-al` | Success | Success | Success | SessionIndexを署名対象から除外した署名は受理されない |

- 実証による未検証解消: 15観測（546→531、異なるケースID 179→174）。
- 製品設定変更: 0回。環境のSPメタデータを確認し、KeycloakのSLO URLとSimpleSAMLphpのSingleLogoutServiceが相関なしの`/sp/slo`を指すことを確認しています。
- Suite再作成: 3回（実装修正と再デプロイの単位）。Run作成: 3回（製品別）。ユーザー本人のブラウザ操作: 0回（プロトコルクライアントが自動実行）。
- 判明した環境要因: ShibbolethのSP起点SLOは、ログアウト完了ページの隠しiframe（`_eventId=proceed`）を追従しないとLogoutResponseが送出されません。参照ドライバをiframe追従に修正しました（実ブラウザは自動取得します）。判定ロジック側ではありません。

次の実装対象は、非同期SLO（b/b1/b2）、HTTP-Redirect限定端点（18-b/c/d）、伝播（r/s・c）です。

## 6. バッチ2の結果（IIP-IDP17.b / b1 / b2 / x / y / z / aa / al）

バッチ1の直接HTTP探索は**ブラウザのセッションCookieを持たない**ため、セッション依存の検証を迂回していました（SimpleSAMLphpは未認証要求をログインへ転送し、xの「Destination不一致は適用されない」という結論は実際には未検証でした）。そこで配送を認証済みブラウザ経由に変更し、ブラウザが観測したHTTP応答を新しい`browser-response` APIで構造化証拠として記録する方式に置き換えました。Keycloakの署名無効fixtureは、IdPが返したLogoutResponseの`InResponseTo`と要求のDestinationを転記で照合し、Suiteの検証器で署名が無効であることも確認しています。

| ケース | Keycloak | Shibboleth | SimpleSAMLphp | 観測した事実 |
|---|---|---|---|---|
| `IIP-IDP17-b` | Success | Success | **Failed (Product)** | SSPはDestination不一致の非同期要求にもLogoutResponse(Success)を返す |
| `IIP-IDP17-b1` | **Failed (Product)** | Success | **Failed (Product)** | Keycloak/SSPは信頼できる非同期要求へLogoutResponse(Success)を返す |
| `IIP-IDP17-b2` | Success | Success | Not verified | SSPは成功/失敗ページを区別できる証拠を返さず（理由を更新） |
| `IIP-IDP17-x` | Success | Success | **Failed (Product)** | SSPはDestination不一致の同期要求を適用しSuccessを返す |
| `IIP-IDP17-y` | **Failed (Product)** | Warning | Warning | Keycloakは`SAML Client Signature`無効構成で提示された無効署名を検証せず適用 |
| `IIP-IDP17-z` | **Failed (Product)** | Warning | Warning | 同上（内容に依拠） |
| `IIP-IDP17-aa` | Warning | Warning | Warning | 3製品ともSAMLエラー応答を返さない（SHOULD相当） |
| `IIP-IDP17-al` | **Failed (Product)** | Success | Success | Keycloakは署名対象からSessionIndexを除外した署名を受理 |

- 実証による未検証解消: 23観測（531→523、異なるケースID 174→172）。残る`IIP-IDP17.b2`のSSP観測は、フィードバックページの意味が読み取れないためNot verifiedを維持。
- Keycloakのy/z/alは、対象クライアントの`saml.client.signature=false`（既定）という構成での観測です。構成を変更すれば挙動が変わり得るため、台帳の理由と併せて構成を記録します。仕様は「消費したメッセージに署名が存在すれば検証する」ことを要求しており、この構成はその義務に適合しません。
- 操作: 製品設定変更0回、Suite再作成4回（証拠APIと配送方式の修正）、Run作成3回、ユーザー本人のブラウザ操作0回。
- 検証: Keycloak y要求の署名はSuiteの検証器で`valid=false`、応答は`InResponseTo`一致のSuccess。SSP x要求のDestinationは`https://samlscope.invalid/sp/slo`、応答はSuccess。

次の実装対象は、HTTP-Redirect限定端点（18-b/c/d）と伝播（r/s・c）です。

## 7. バッチ3の結果（IIP-IDP18.b / c / d）

Suite SPがRedirect応答エンドポイントのみを広告する構成を、対象製品側の設定で作成しました（Shibboleth: `suite.xml`のSP SingleLogoutServiceをRedirectのみにしてMetadataResolverService再読込。Keycloak: クライアント属性`post`/`soap`を空文字で除去し`redirect`のみ残置。SimpleSAMLphp: 既にRedirectのみ）。Suiteは署名付きRedirect（GET）LogoutRequestを送出し、応答のbindingをトランスクリプトのHTTPメソッドから判定します。

| ケース | Keycloak | Shibboleth | SimpleSAMLphp | 観測した事実 |
|---|---|---|---|---|
| `IIP-IDP18.b` | Success | Success | Success | Redirect要求に対しLogoutResponseがHTTP-Redirectで返る |
| `IIP-IDP18.c` | 未確定 | Success | 未確定 | ShibbolethはIdP起点LogoutRequestをHTTP-Redirectで送出 |
| `IIP-IDP18.d` | 未確定 | Success | 未確定 | SuiteがRedirectで返したLogoutResponseをIdPが消費（ブラウザ観測200・失敗表示なし） |

- 実証による未検証解消: 5観測（523→518、異なるケースID 172→171）。
- Keycloak/SimpleSAMLphpの`IIP-IDP18.c/d`は、対象がIdP起点LogoutRequestを発行しないため（`docs/31`参照）、キャンペーンのケースが未起動のままです。variantの「発行されない場合は`satisfied_with_note`」を適用するには、キャンペーンの完了（未発行の確定）を記録する経路が必要で、これは未実装の残課題として記録します。
- 操作: ShibbolethのSPメタデータ書換え1回・再読込1回、Keycloakクライアント属性書換え1回（post/soap除去）、Suite再作成1回、Run作成4回（18-b用3、18-c/d用1）、ユーザー操作0回。

## 8. バッチ4の結果（IIP-IDP17.c とキャンペーン完了）

- `IIP-IDP17.c`（informational）: 伝播の有無を情報記録する規則を追加。ShibbolethはIdP起点LogoutRequestを送出（`propagated=true`）、Keycloak/SimpleSAMLphpは送出しない（`propagated=false`）。Verdictは情報記録のWarning。
- ターゲット起点ログアウトのキャンペーンは、対象が要求を発行しない場合に永久待機していました。`POST /api/runs/{id}/target-initiated/conclude` を追加し、未発行を確定して規則の観測（`not-issued`）を記録します。Suiteが自ら「発行なし」を観測できない場合でも、未発行の確定を運用者/ドライバの操作として記録する経路です。
- 実証による未検証解消: 7観測（518→511、異なるケースID 171→168）。

## 9. バッチ5の結果（IIP-IDP17.r / s）

| ケース | Keycloak | Shibboleth | SimpleSAMLphp | 観測した事実 |
|---|---|---|---|---|
| `IIP-IDP17.r` | Warning | 未確定 | Warning | Keycloak/SimpleSAMLphpは伝播自体を実装しないため、variant規定どおり`satisfied_with_note`（伝播不実装）。Shibbolethは伝播するが、単一参加者では「失敗後の継続」を証明できない |
| `IIP-IDP17.s` | Warning | 未確定 | Warning | 同上。Shibbolethは単一参加者のため失敗を誘導できず、PartialLogoutの観測経路がない |

- 実証による未検証解消: 4観測（511→507）。Shibbolethのr/sは理由を`slo.propagation.failure-induction-unavailable` / `slo.partial-logout.unobserved`へ精密化し、未確定を維持。
- Shibbolethの伝播継続・PartialLogoutを確定するには、**同一Run内に複数のSP参加者**が必要です。設計案: (1) Suiteが1つのPlanで第2・第3のSP entity（`/p/{plan}/sp2/*`, `/sp3/*`）とメタデータを公開、(2) 失敗誘導用のSLO SOAPエンドポイント（接続拒否/タイムアウト固定）を用意、(3) IdPメタデータへ3 entityを登録して同一ブラウザで順にログイン、(4) 1つ目を失敗させた上で残りに要求が届くこと（r）と開始SPへの応答にPartialLogoutが入ること（s）をトランスクリプト規則で判定。Suite側の複数SP対応が前提で、次の実装単位とします。

## 10. 操作コストの記録方針

製品設定の書き込み・復元、管理API操作、Suite再作成、Run回数をバッチごとに記録し、`docs/31`と各バッチの`operations.json`へ保存します。失敗試行も含めます。

## 11. 進捗の区分

- コード実装: Suite/コアの変更とテスト。
- 実環境への接続: Run作成、fixture送出、応答記録。
- 実証による未検証解消: Success/Failed/Warningへ到達した観測数。
- 診断だけの更新: Verdictを変えず理由・分類を更新した観測数。
