# 認証コンテキスト比較の実機接続と正式判定

<!--g1-literal--> 未検証は462→458観測、異なるケースIDは156のまま。Shibbolethのbrowser_sso_idpでminimum・better・候補優先順をSuccess、maximumをFailedとして正式採用した。他製品・別プロファイルへ横展開した判定ではない。

| ケース | 結果 | 実測 |
|---|---|---|
| IIP-SSO01.ga | Success | ClassRef／DeclRefとも成功時は要求したlow以上。達成不能要求には署名付きエラー。 |
| IIP-SSO01.gb | Success | 双方ともlowより強いmedium。達成不能要求には署名付きエラー。 |
| IIP-SSO01.gc | Failed (Product) | ClassRefはmediumだがDeclRefはlow。後続の同一設定・同一SP・同一ログイン入力でexact mediumの成功を確認し、より強い候補が利用可能だったことを実証。 |
| IIP-SSO01.gj | Success | 双方で候補順を反転すると、最初の候補に応答の選択値も追従。 |

## 実装と判定の根拠

`AuthnContextCampaignInputs`がローカルアダプターの入力をRunと対象メタデータのハッシュへ固定し、既存の事前取込ブラウザキャンペーンで署名付き要求を生成する。入力は送信条件のみであり、強度順位やVerdictの確認操作にはならない。元の経路の要求署名・RelayState・ACS相関を維持する。これは既存キャンペーンの要求生成経路であり、新たなケース内HTTP送信は追加していない。

Shibbolethの標準`shibboleth.AuthnComparisonRules`とPasswordフローの`supportedPrincipals`を使用した。ClassRefには`saml2`、DeclRefには実機同梱定義の`saml2declref`を使う。独自URNを比較用の識別子として登録し、製品自身の比較ルールへ順序を設定する。実在する認証方式の強度をSuiteが決めたものではない。最大値の試験ではlow／mediumのみを利用可能にし、highを上限として要求する。一般利用の設定に対する推奨ではなく、隔離した参照IdPの一時試験設定である。

設定方法は[Shibboleth AuthenticationFlowSelection](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199505253/AuthenticationFlowSelection)と、実機同梱の`authn-system.xml`を照合した。元設定・適用設定・各往復前後の読み戻し・復元ハッシュを保存する。有効な認証フローがPasswordだけであることも各読み戻し時に確認する。

原文collectorは、同じ事前取込メタデータ、公開されたACS／送信先、要求IDと応答、署名、復号、Audience、SubjectConfirmationを検査する。RequestedAuthnContext以外の要求入力は指紋で固定する。準備証拠はローカルファイルとして読み込み、原文のハッシュと参照を再照合する。maximumでは利用可能性対照の原文も正式判定で検証し、候補の存在を設定ラベルだけで判定しない。

`AuthnContextConfigurationTestCase`をCONFIG registryへ登録した。ケースはOutcomeを返し、正式なPASS／FAILはEvaluatorが変換する。今回の確定はいずれも`attested=false`。無応答、HTTP画面の見た目、設定保存成功だけを確定根拠にしていない。

## 証拠と検証

<!--g1-literal--> 正式Runは`run_FWMYG7PY9SWNNNMYQA39DS4B8D`。評価条件16往復＋利用可能性対照4往復の計20往復で署名・復号・相関が成立した。元設定へ復元後、通常SSOの前提を1往復実行してケースを開始し、証拠を使って正式評価した。

証拠は`build/acceptance/reference-20260918/shibboleth-authn-context-acceptance/`、正式結果は`shibboleth-authn-context-evaluation/`に置く。`verify_authn_context_acceptance.py`が準備証拠の再生成一致、インストールの読み戻し、正負対照、通常SSO前提、正式結果、原文参照の不変性を検査してから台帳へ採用する。原文やローカル証拠はGitのignore設定を維持する。

<!--g1-literal--> 認証コンテキスト関連の対象テストはSAML 2件＋Runner 13件が成功。集約処理の正対照4件、参照形式別の負対照8件、条件不足4件、対照未確認4件を実行した。さらに実測証拠への欠落・重複・応答取り違え・対照未確認の変形が全ケースでNOT_VERIFIEDに戻ることを確認した。全テスト一式の実行済みという意味ではない。

<!--g1-literal--> G1生成一致・構造46/46を確認。G2の既知の保護実装署名差分は別途残っており、リリース可能とは扱わない。

## 設定・操作の記録

<!--g1-literal--> 初回は参照コンテナの起動コマンドが`sleep infinity`であることを見落とし、コンテナ再起動後のTomcat起動が不足した。プロトコル0往復で終了。設定を全バイト復元し、Tomcatを起動してメタデータHTTP 200を確認した。続く試行で16往復を観測し、利用可能性対照を加えた最終試行で20往復を観測した。失敗試行も操作総数に含む。

<!--g1-literal--> この実装バッチ全体は製品側ファイル書込28回（設定24回・一時メタデータ4回）、製品コンテナ再起動8回、Tomcat明示起動7回、サービス再読込2回、一時メタデータ削除4回、プロトコル往復37回。Suite入力書込3回・準備証拠配置4回。イメージビルド2回、Suite／転送コンテナ再作成は各2回。本人操作0回。CONFIG APIの余分なnoteによる拒否1回、結果取得URLの誤り1回も記録し、いずれも製品操作ではない。

設定回数は少なくない。最終キャンペーンは条件を同じ設定ごとにまとめ、通常比較・maximum・復元の切替で実行する。今回増えた初回起動失敗と対照追加の再試行は今後の定常手順には含めない。次の改善対象は通常SSO前提の取込をキャンペーン準備と共用することと、ケース別の小さな再起動を増やさず製品別にまとめて実行することである。

<!--g1-literal--> 実機イメージは`samlscope:reference-authn-context-v53`、digestは`sha256:10f435a8289e3ea733fb8b54a06c8513e7f9eeac70f3804997c6cf5a1bb75241`。ソースハッシュは`authn-context-runtime-v53/source.json`。無関係な既存SOAP差分を隔離ビルドから除外した。細分化したコミットは作成していない。
