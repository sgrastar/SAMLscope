# Keycloak live driver 自己点検

2026-10-31。管理APIによる製品機能調査まで完了した。正式なSAML campaign、case outcome、Verdict、reference inventoryの更新は行っていない。調査結果は[実機FINDINGS](../../../build/acceptance/reference-20261031/sso01g-keycloak/FINDINGS.md)にある。

## 実装と境界

`keycloak_live.py`は専用client、標準LoA条件付きflow、ClassRef mapperを作り、normal/maximumの製品GETを保存し、finallyで削除・元公開状態照合を行う。`keycloak_campaign.py`は明示的な`--dry-run`または`--live`を要求する。`--live`は管理API設定調査だけを実行する。`run_campaign()`の`product-runtime` driverとは接続していない。

接続は`http://127.0.0.1:18180`へ固定し、localhost別名、別port、userinfo、外部host、redirect、proxyを拒否する。Cookieを保持しない。資格情報は固定の開発フィクスチャからASTで読む。認証モジュールをimportせず、環境変数・private/・.env・鍵ファイルへfallbackしない。tokenはメモリのみで、APIログはmethod/path/statusだけ。新規SAML clientの管理GETに混ざる製品生成秘密属性は公開投影前に削除する。未知の秘密属性は保存を止める。

`campaign.py`は出力許可先のjobを今回指定先へ更新し、SAML/outbox driverが未実装であることを明記した。以前のオフライン成果物は当時の記録として保持している。SimpleSAMLphpの実機操作はしていない。

## 誤判定・復元リスク

|項目|対策・残る制約|
|---|---|
|SAML対応をOIDC設定から推定|稼働SAML専用featureとSAML mapperを確認。同版保存bytecodeのSAML呼出元も調べた。map保存だけを解釈の証明にはしない。|
|DeclRefの取りこぼし|公開native経路を発見できず、保存版の比較・mapperはClassRefのみ。稼働Responseが未確認なので全4ケースを保留。部分ClassRef成功を全caseへ拡張しない。|
|設定GETを実行証拠と扱う|originを`product-management-api`、`executionObserved=false`とする。native認証実行観測0、従来の`product_effective_*`も0。正式receiptへ昇格しない。|
|maximumの弱い選択|high無効化だけではmedium利用可能・最強選択を証明できない。low/medium EXACT原本、high不達、同一入力と網羅性は利用者操作後の課題。|
|全error・HTTP失敗を成功扱い|管理HTTPエラーは調査incomplete。既知の404だけ不存在確認に使う。SAML error原本を持たず、適合・不適合を出さない。|
|先頭優先とLoA数値順の混同|保存関数のfindFirstは補助根拠。実機で両順序と各候補EXACT対照を確認するまでは保留。|
|直接送信・別Run付け替え|AuthnRequest sender、browser、Suiteアクセスを実装していない。outbox未整備なら完全campaignは開始できない。IDP19.b専用source bindingも流用しない。|
|既存realm/shared flowの変更|名前空間の既存衝突で停止。専用ID/aliasへのwrite guardを追加。realmのbindingへPUTしない。既存flowとclient一覧の公開投影を前後比較する。|
|応答喪失による二重write|write前にintentと試行回数、ACK後に成功回数をfsync journalへ保存。GETで元状態か意図した1変更だけか照合し、途中writeを再送しない。|
|設定変更の同時実行|write間と復元前に公開投影を比較。未知の差分は上書きせず停止する。APIにCASがないためGETとwriteの間の競合を完全には排除できない。隔離namespaceを他の管理操作で触らない運用が必要。|
|途中停止・復元失敗|finally復元、SIGINT/SIGTERMの初回を捕捉、`--live --recover`で削除だけ再開。SIGKILL・電源断はjournalからの再開が必要。外部編集や製品停止で安全な復元を証明できなければincompleteのまま停止する。|
|子flow/configの残留|config IDと子flow IDを保持し、不存在GETを確認。実機最終GETでも完走時の子flow3件・config3件が404。親flow削除時に製品がcascadeしたため、実機で追加config DELETEは不要だった。|
|「完全一致」の範囲|公開binding・共有flow定義/execution・client識別一覧・専用資源不存在が同値。全realm export、秘密値、監査ログ、session、生成ID列の一致は対象外。|
|初期の実装不足|alias付加、製品生成秘密属性で初期2試行が止まった。いずれも復元済み。失敗・復旧を省かずHTTP記録から65 write/65 ACK、復元5を集計。|
|旧journalのACK回数|最初の復旧Countersはread-back例外前のACKを欠く。元reportのstatus記録は保持。集計器はstatusから算出し、最終driverはACK直後保存と復旧時status照合を行う。|

復元の証拠を先に保存した完走試行の後、専用write guard、journal復旧の回数照合、子flow不存在確認を補強した。これらは単体テストで検証し、実機追加GETでも不存在を確認した。最終コードで設定writeを繰り返すことはしていない。

## 利用者操作数と未確認項目

今回の利用者操作、browserログイン、AuthnRequest、通常SSOはすべて0。管理APIのtoken取得は自動化し、値を保存しない。管理者の画面操作はない。

将来の評価行列は24条件と通常SSO1～2回。gjの達成不能補助要求を両reference種別で追加すると27～28往復になる。条件行列自体や承認caseを増やす意味ではない。

現flowは最初のUsername Formと、要求LoAまでの各Password Formを別送信する構成である。fresh操作の単純モデルでは、low/medium/highで認証関連のフォーム送信はそれぞれ最大2/3/4回になるが、step-upの実選択、error発生時点、session再利用を観測していないため実測値でも上限保証でもない。全28往復で各4送信なら112送信を仮の予算にできるが、MFA・同意・追加画面は別途必要になりうる。ログアウトは0予定、context破棄はlogoutとして数えない。

未確認なのは、稼働JARと保存版のbytes一致、実行時LoA、ClassRef/DeclRefのResponse出力、すべての成功選択・達成不能error・候補可用性、最大値選択、候補順反転、正負対照の検出力、Run/outbox/Recorderの一意相関と暗号検証、復元後通常SSOである。これらが揃う前に正式採用できない。

## 検証と再現

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s dev/reference-acceptance/sso01g -p 'test_*.py' -v

PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --dry-run --out build/acceptance/reference-20261031/sso01g-keycloak/dry-run-next

# 設定調査だけ。新しい名前と空の出力先を使う。
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --live --name kc-next \
  --out build/acceptance/reference-20261031/sso01g-keycloak/live-next

# 途中停止時の後片付けだけ。journalと同じname/outを指定する。
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --live --recover --name kc-next \
  --out build/acceptance/reference-20261031/sso01g-keycloak/live-next

# 保持された試行・復旧のHTTP記録から再集計。既存出力は上書きしない。
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/summarize_keycloak_operations.py \
  --out build/acceptance/reference-20261031/sso01g-keycloak/operational-totals-next.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r1/report.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r2/report.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r3/report.json
```

既存25件と追加20件の計45 testsが成功。追加では全27設定write箇所の適用前拒否・適用後ACK喪失、GET障害、削除ACK喪失後の復旧、journal先行保存、namespace衝突、外部編集保持、共有資源write拒否、秘密除去、127.0.0.1固定、redirect拒否、dry-run無通信を検証した。fixtureでの成功を製品の正負対照実行として数えない。

最終の監査付き実行でも45 tests / 0 failures / 0 errors。socket・外部プロセス起動、禁止入力、指定先外writeをaudit hookで拒否し、それぞれ試行0だった。job内`audited-tests.log`と`test-results.json`に記録した。ソースのAST検査も実施した。

`g1_docgen.py --check`は成功。`g1_validate.py --structural-only`と`g2_validate.py`は署名検証も内包し、Gitの鍵参照と指定先外のbuild出力を伴うため、今回の鍵参照禁止・書込み範囲内では実行していない。署名検証をmockして合格と扱うこともしない。G1全source比較は外部通信禁止のため未実施。Gradle、G1/G2 trusted wrapper、ブラウザ統合、release readinessの合格は主張しない。

protected artifacts、case実装、正式台帳、比較・inventoryは変更していない。開始時からのAGENTS.md変更も触れていない。commit、push、Docker操作は行っていない。書込み先は指定されたsso01g、acceptance evidence、jobの各範囲だけである。
