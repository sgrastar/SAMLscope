# UI URLスキームの比較入力

`IIP-MD05-fh-idp-01`の承認済み条件に対応する入力を追加した。Logo、InformationURL、PrivacyStatementURLを個別に変え、各要素へhttp、https、data、javascript、fileを指定する。他のURL要素を同時に変更せず、どの要素が製品で使われたかを区別できる構成にする。

<!--g1-literal--> 共通入力は3要素×5スキームの15種類。`ui-url-{logo|information|privacy}-{http|https|data|javascript|file}`で通常・polling双方のメタデータ生成から利用できる。UIInfoはSPロールのExtensionsへ配置し、固定DisplayNameを画面の対象SP識別用に添える。fixtureを生成・取り込めたことだけではケースを解消しない。

data入力とネットワーク画像は同一の固定SVGを使う。`/metadata-lab/ui-fixture.svg`へ専用の固定配信ルートを追加した。ファイル名や入力本文を受け取らず、ファイルシステム参照・リダイレクト・スクリプトはない。画像Content-Type、nosniff、制限したCSPを返す。

http／httpsのURLはSuiteの公開ホストとポートから組み立てる。両方の到達性は別途準備・検証が必要で、ローカルHTTPポートをhttpsに書き換えてもTLSが有効になるわけではない。追加当初は参照環境のHTTPS配信経路が未整備だったが、下記の専用配信経路で実証した。ネットワーク失敗やCSPによる未読込を、対象製品のURLスキーム判断の違反にしない。

後続実装で、`SAMLSCOPE_UI_ASSET_HTTP_URL`と`SAMLSCOPE_UI_ASSET_HTTPS_URL`による独立した配信先指定を追加した。両方を指定する場合だけ上書きし、片方のみ・スキーム不一致・ユーザー情報・query・fragment・固定画像以外のpathは拒否する。通常とpollingのMetadataServiceへ同じ設定を渡す。未指定時は上記の公開ホスト／ポートを使うが、到達性を自動的に証明した扱いにはしない。

javascript入力は`javascript:void(0)`、file入力は存在を想定しない専用パスを使う。XSSペイロード実行のケースとは別である。ブラウザ観測にlink種別を追加し、表示されたアンカーの宛先を候補と照合するが、クリックもスキームハンドラーの実行も行わない。製品ページの全文や認証情報は保存しない。

## 判定へ接続する際の条件

承認済み定義ではdataを一律拒否する必要はなく、URLを使用しないRunはsatisfied_with_noteである。ただし単に対象要素が見つからないことを、URLの不使用が証明できたことに置き換えない。対象画面・SP・取込原本の結合、利用可能な対照、対象要素の使用／抑止の観測を整備する必要がある。現時点ではこの入力からOutcomeを返す処理は追加していない。

UIリンクの消費と画像の描画は別に観測する。リンクが示すURLを確認するためにそのリンクを開く必要はない。一方、画像の正の対照はURL文字列がDOMにあることだけでは足りず、配信・読込・可視性を確認する。

<!--g1-literal--> Javaの入力網羅・配信ルートの検証コードと、Playwrightの非クリック観測検証を追加した。コンパイル・構文確認成功、機能テスト実行は次の統合バッチ待ち。初回コンパイルで登録引数をJavalin本体としていた誤りを修正し、既存のJavalinConfig形式へ合わせた。

<!--g1-literal--> 未検証は466観測のまま。稼働イメージへの反映・製品設定書込・本人操作は0回。この入力追加時点の稼働版はv46だった。後続のv47反映は下記参照。

## ループバックでの配信実証

`ui_asset_server.mjs`は固定画像だけをループバックHTTP/TLSで配信する。別々の非特権ポートを使い、固定pathのGET/HEAD以外は拒否する。要求のURL・ヘッダー・本文・利用者情報はログに出さず、画像取得回数だけを記録する。停止シグナルで両リスナーを閉じる。

`verify_ui_asset_transport.py`で、提供した証明書とホスト名を検証したHTTPS取得、およびHTTP取得が、Javaの固定画像本体と完全一致することを確認した。検証を無効化したTLS取得ではない。さらにChromeで両画像の自然寸法・読込完了・応答バイト一致を確認した。Chromeの自己署名証明書例外は生成した専用証明書のSPKIハッシュに限定し、汎用の証明書エラー無視は使っていない。

証拠は`build/acceptance/reference-20260918/ui-asset-transport/transport-proof.json`と`browser-proof.json`。証明書・秘密鍵はGit対象外のローカル試験ファイルである。画像のSHA-256は`db4b28bd16f9a91bfe96c1e17a503b2396c37aafcd2b14f41c6c1e378f417a00`。この配信実証を製品のSuccessとして採用しない。

Shibbolethブラウザアダプターにも任意の`SAMLSCOPE_UI_ASSET_SPKI`を追加した。指定形式を検査し、使ったpinを観測記録に残す。今後のURLスキーム比較では証明書の取扱いも入力条件として固定する必要がある。

<!--g1-literal--> 専用画像サーバー起動・停止各1回、HTTP/HTTPS取得各2回（証明書検証付きクライアントとChrome）、Chrome起動1回。製品設定変更・Suiteコンテナ変更・本人操作は0回。配信サーバーは確認後に停止済み。設定検証のテストコードを追加し、JavaコンパイルとJavaScript構文確認は成功。機能テスト群は次の統合バッチ待ち。

## Shibbolethの実画面への接続

<!--g1-literal--> `samlscope:reference-ui-url-v47`へ反映し、Run `run_5YP6SFER5ZAXEGPBJ2K32WZ35E`で15条件を一括実行した。イメージは署名済み`570d78eb`の隔離チェックアウトからビルドし、作業ツリーにある別件のSOAP変更を含めていない。イメージdigestは`sha256:fc83fc2c70d94a894fe1e814b2ee2c58094c9d468e60cc56b77981ca7216ef8f`。

| URL要素 | http | https | data | javascript | file |
|---|---|---|---|---|---|
| Logo | 描画確認 | 描画確認 | 描画確認 | 要素未観測 | 要素未観測 |
| InformationURL | 要素未観測 | 要素未観測 | 要素未観測 | 要素未観測 | 要素未観測 |
| PrivacyStatementURL | 要素未観測 | 要素未観測 | 要素未観測 | 要素未観測 | 要素未観測 |

表は画面観測であり、ケースのSuccess/Failedではない。ロゴは可視性・読込完了・自然寸法・候補URLを確認した。全条件で固定DisplayNameの見出しを確認し、ブラウザが実際に送信したAuthnRequestをRecorder原本と照合した。画像待機のタイムアウトは運用上の上限であり、仕様上の違反条件にしない。

`bind_ui_consumer_evidence.py --url-schemes`は既存の原本照合へ、対象URL要素・スキーム・候補URL・観測種別・対象画面の見出しを追加する。要素未観測は不使用の証明に昇格させない。javascriptのリンクは汎用的な値なので、将来の判定では無関係な同値アンカーとの区別も必要である。現状はクリックせず、診断としてのみ保存する。

<!--g1-literal--> 全15観測のfixture・取込読戻し・MetadataFetch/Prepared・送信要求・ブラウザ記録を結合した。候補URL改変、見出し不成立、別要求、観測種別改変、不使用証明の偽装という5負の対照を拒否した。証拠は`build/acceptance/reference-20260918/shibboleth-ui-url-scheme-campaign/`の`ui-evidence-binding.json`と`binding-controls.json`。この照合検証は判定oracleの完成やG2承認の代わりではない。

<!--g1-literal--> 操作はイメージbuild 1、Suite/転送コンテナ再作成各1、Run/preflight各1、製品側ファイル書込17（復元を含む）、一時ファイル削除1、Resolver再読込16、ブラウザ開始15、本人操作0。専用画像サーバー起動・停止各1。製品設定は元のSHA-256へ完全復元し、言語設定に変更がないことも確認済み。これらの設定操作はスクリプトで自動実行した。

<!--g1-literal--> 未検証は466観測・157ケースIDのまま。Logoで許可スキームを利用できる証拠は得られたが、残るURL要素の消費範囲と負の対照を含む正式oracleが未完成であり、台帳から削除しない。次はこの範囲を確定して判定へ接続する。G1生成一致・構造46/46を確認。URL入力のJava機能テスト群は引き続き統合バッチ待ち。

## URL設定と描画を分ける追加観測

描画確認だけでは、禁止スキームをそのまま画像のsrcへ渡す製品でもブラウザの読込失敗により「未観測」になる。`observeUiUrlConsumer`を追加し、可視性・画像読込とは独立して、指定したネイティブ要素のsrc/hrefが既知の候補と一致するかを記録する。未知の属性値は保存せず、クリック・URL実行も行わない。

未配置、複数要素、未知の割当、候補の割当、観測不能を区別する。画像はネイティブのロゴ要素を指定する。リンクは候補URLによる検索であり、ネイティブ表示位置が確定した扱いにしない。どの状態も単独では消費／不使用の判定根拠にしない。証拠結合はこの区別と採取時刻を保持し、要素ごとに正常対照不足と正式oracle不足を診断する。

<!--g1-literal--> Run `run_XV5F7Z0A6B4W8Q9KPYFEJ122S0`で15条件を追加観測。Logoのhttp/https/dataはURL割当と描画を確認、javascript/fileは画像要素が採取時点に存在しなかった。InformationURL/PrivacyStatementURLは全条件で候補リンクが存在せず、利用可能な正常対照がない。正式Verdictは変更していない。

証拠は`build/acceptance/reference-20260918/shibboleth-ui-url-assignment-campaign/ui-evidence-binding.json`。URL描画だけでなく割当の結果も原本ハッシュへ結合した。未読込・非表示・複数要素・未知URL・別ページを区別するブラウザ検証コードを追加し、構文検査を実施。機能テスト群の実行は統合バッチへ保留する。

<!--g1-literal--> 追加操作はRun/preflight各1、製品側書込17（復元を含む）、削除1、Resolver再読込16、ブラウザ開始15、画像サーバー起動・停止各1、HTTP/HTTPS画像取得各1、本人操作0。build・Suite再作成は0。全製品設定を元のハッシュへ復元済み。

<!--g1-literal--> 未検証台帳の定期監査では466観測・157ケース、承認済み410variant・310controlとの対応と実結果原本を照合し、不整合0。これは実装完成の証明ではない。未検証件数を維持する。
