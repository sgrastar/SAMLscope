# UI URLスキームの比較入力

`IIP-MD05-fh-idp-01`の承認済み条件に対応する入力を追加した。Logo、InformationURL、PrivacyStatementURLを個別に変え、各要素へhttp、https、data、javascript、fileを指定する。他のURL要素を同時に変更せず、どの要素が製品で使われたかを区別できる構成にする。

<!--g1-literal--> 共通入力は3要素×5スキームの15種類。`ui-url-{logo|information|privacy}-{http|https|data|javascript|file}`で通常・polling双方のメタデータ生成から利用できる。UIInfoはSPロールのExtensionsへ配置し、固定DisplayNameを画面の対象SP識別用に添える。fixtureを生成・取り込めたことだけではケースを解消しない。

data入力とネットワーク画像は同一の固定SVGを使う。`/metadata-lab/ui-fixture.svg`へ専用の固定配信ルートを追加した。ファイル名や入力本文を受け取らず、ファイルシステム参照・リダイレクト・スクリプトはない。画像Content-Type、nosniff、制限したCSPを返す。

http／httpsのURLはSuiteの公開ホストとポートから組み立てる。両方の到達性は別途準備・検証が必要で、ローカルHTTPポートをhttpsに書き換えてもTLSが有効になるわけではない。特に参照環境ではHTTPS配信経路の準備が残っている。ネットワーク失敗やCSPによる未読込を、対象製品のURLスキーム判断の違反にしない。

後続実装で、`SAMLSCOPE_UI_ASSET_HTTP_URL`と`SAMLSCOPE_UI_ASSET_HTTPS_URL`による独立した配信先指定を追加した。両方を指定する場合だけ上書きし、片方のみ・スキーム不一致・ユーザー情報・query・fragment・固定画像以外のpathは拒否する。通常とpollingのMetadataServiceへ同じ設定を渡す。未指定時は上記の公開ホスト／ポートを使うが、到達性を自動的に証明した扱いにはしない。

javascript入力は`javascript:void(0)`、file入力は存在を想定しない専用パスを使う。XSSペイロード実行のケースとは別である。ブラウザ観測にlink種別を追加し、表示されたアンカーの宛先を候補と照合するが、クリックもスキームハンドラーの実行も行わない。製品ページの全文や認証情報は保存しない。

## 判定へ接続する際の条件

承認済み定義ではdataを一律拒否する必要はなく、URLを使用しないRunはsatisfied_with_noteである。ただし単に対象要素が見つからないことを、URLの不使用が証明できたことに置き換えない。対象画面・SP・取込原本の結合、利用可能な対照、対象要素の使用／抑止の観測を整備する必要がある。現時点ではこの入力からOutcomeを返す処理は追加していない。

UIリンクの消費と画像の描画は別に観測する。リンクが示すURLを確認するためにそのリンクを開く必要はない。一方、画像の正の対照はURL文字列がDOMにあることだけでは足りず、配信・読込・可視性を確認する。

<!--g1-literal--> Javaの入力網羅・配信ルートの検証コードと、Playwrightの非クリック観測検証を追加した。コンパイル・構文確認成功、機能テスト実行は次の統合バッチ待ち。初回コンパイルで登録引数をJavalin本体としていた誤りを修正し、既存のJavalinConfig形式へ合わせた。

<!--g1-literal--> 未検証は466観測のまま。稼働イメージへの反映・製品設定書込・本人操作は0回。現在の稼働版は前回のv46であり、本入力追加はまだ配布していない。

## ループバックでの配信実証

`ui_asset_server.mjs`は固定画像だけをループバックHTTP/TLSで配信する。別々の非特権ポートを使い、固定pathのGET/HEAD以外は拒否する。要求のURL・ヘッダー・本文・利用者情報はログに出さず、画像取得回数だけを記録する。停止シグナルで両リスナーを閉じる。

`verify_ui_asset_transport.py`で、提供した証明書とホスト名を検証したHTTPS取得、およびHTTP取得が、Javaの固定画像本体と完全一致することを確認した。検証を無効化したTLS取得ではない。さらにChromeで両画像の自然寸法・読込完了・応答バイト一致を確認した。Chromeの自己署名証明書例外は生成した専用証明書のSPKIハッシュに限定し、汎用の証明書エラー無視は使っていない。

証拠は`build/acceptance/reference-20260918/ui-asset-transport/transport-proof.json`と`browser-proof.json`。証明書・秘密鍵はGit対象外のローカル試験ファイルである。画像のSHA-256は`db4b28bd16f9a91bfe96c1e17a503b2396c37aafcd2b14f41c6c1e378f417a00`。この配信実証を製品のSuccessとして採用しない。

Shibbolethブラウザアダプターにも任意の`SAMLSCOPE_UI_ASSET_SPKI`を追加した。指定形式を検査し、使ったpinを観測記録に残す。今後のURLスキーム比較では証明書の取扱いも入力条件として固定する必要がある。

<!--g1-literal--> 専用画像サーバー起動・停止各1回、HTTP/HTTPS取得各2回（証明書検証付きクライアントとChrome）、Chrome起動1回。製品設定変更・Suiteコンテナ変更・本人操作は0回。配信サーバーは確認後に停止済み。設定検証のテストコードを追加し、JavaコンパイルとJavaScript構文確認は成功。機能テスト群は次の統合バッチ待ち。
