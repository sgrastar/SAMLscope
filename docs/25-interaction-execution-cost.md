# 追加試験と設定・操作コストの記録

この記録は2026-09-14の追加試験だけを計測対象にしています。それ以前の環境構築・試行の回数や時間は未計測であり、ゼロとは扱いません。既存Runに追加の証拠を集め、同じケース定義で判定の差分を比較しています。

ユーザー本人の操作、エージェントが代行したブラウザ操作、API・ファイルによる設定変更を別々に数えます。設定書き込みは復元も含めて1回ずつ数え、サービス再読み込みは別計上します。ブラウザ操作はページを開く・項目入力・クリック・手動継続をそれぞれ1回と数え、自動リダイレクトは含めません。スクリプトによる代行は、設定作業自体の消滅を意味しません。

## 判定の変化

| 製品 | Not verified：前 | 後 | 減少 |
|---|---:|---:|---:|
| Keycloak | 209 | 207 | 2 |
| Shibboleth | 200 | 185 | 15 |
| SimpleSAMLphp | 203 | 202 | 1 |

上の差分は最初の追加試験の記録です。その後の全件監査では共通ケースを別Runで再試験し、追加で5件のSuccessを確認しました。さらに追加実装後の再試験で、現在の未検証件数は全件台帳で集計しています（[実装記録](27-additional-implementation.md)）。詳細と製品別の再試験結果は [全件台帳](26-unverified-case-inventory.md) を参照してください。以下の作業量・明細には、この再試験と不成功だった署名必須設定の試行も含めます。

この件数は製品・プロファイル・ケース単位の延べ観測数です。操作や設定の回数とは異なります。

## 作業量

| 製品 | 設定書き込み（復元含む） | サービス再読込 | 代行ブラウザ操作 | ユーザー本人の操作 |
|---|---:|---:|---:|---:|
| Keycloak | 5 | 0 | 4 | 0 |
| Shibboleth | 27 | 16 | 7 | 0 |
| SimpleSAMLphp | 7 | 0 | 6 | 0 |

補助接続コンテナの起動は5回です。一時スクリプトの誤りによる設定再試行も台帳に含め、製品の不具合とは扱いません。

Suiteのローカル検証環境の再起動は15回、転送コンテナの再起動は15回です。製品の設定操作とは別計上しています。

操作時間はツール呼び出しの実測時間またはスクリプト内の経過時間です。調査・判断・コード作成・呼び出し間の時間を含まず、人間が手作業した場合の所要時間としては使えません。未計測は「—」と表示します。

## 操作明細

| # | 製品 | 作業 | 実行手段 | 設定書込 | 再読込 | ブラウザ操作 | 実測秒 |
|---:|---|---|---|---:|---:|---:|---:|
| 1 | Keycloak | Signed plaintext assertion fixture; assertion and response signatures retained | api | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 2 | Keycloak | Signed plaintext assertion fixture; assertion and response signatures retained | api | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 3 | Keycloak | Signed plaintext response recorded via real in-app browser | browser | 0 | 0 | 4 | 32.6 | <!--g1-literal-->
| 4 | Shibboleth | Per-SP signed plaintext Assertion fixture | file_and_service_reload | 1 | 1 | 0 | 0.4 | <!--g1-literal-->
| 5 | SimpleSAMLphp | Additional signed SSO response recorded via real in-app browser | browser | 0 | 0 | 4 | 55.9 | <!--g1-literal-->
| 6 | Shibboleth | Per-SP signed plaintext Assertion fixture | file_and_service_reload | 1 | 1 | 0 | 0.3 | <!--g1-literal-->
| 7 | Shibboleth | Signed plaintext response recorded via real in-app browser | browser | 0 | 0 | 4 | 18.7 | <!--g1-literal-->
| 8 | SimpleSAMLphp | Preloaded aggregate for 20 metadata variants | native_metadata_parser | 1 | 0 | 0 | 0.5 | <!--g1-literal-->
| 9 | Shibboleth | Preloaded aggregate for 20 metadata variants | file_and_service_reload | 1 | 1 | 0 | 0.8 | <!--g1-literal-->
| 10 | SimpleSAMLphp | 20 variants attempted; KeyValue-only stopped at index 8; continued at index 9 and reached final page | browser | 0 | 0 | 2 | 23.9 | <!--g1-literal-->
| 11 | Shibboleth | Preloaded aggregate for 20 metadata variants | file_and_service_reload | 1 | 1 | 0 | 0.7 | <!--g1-literal-->
| 12 | Shibboleth | 20 variants attempted; final page reached without operator continuation | browser | 0 | 0 | 1 | 13.9 | <!--g1-literal-->
| 13 | SimpleSAMLphp | Restored original metadata; immediate container readback lagged, subsequent hash matched without another write | native_metadata_parser | 1 | 0 | 0 | — | <!--g1-literal-->
| 14 | Shibboleth | Native HTTP metadata provider; automatic fixture refresh | file_and_service_reload | 1 | 1 | 0 | 0.9 | <!--g1-literal-->
| 15 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 16 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 27.5 | <!--g1-literal-->
| 17 | Shibboleth | HTTP campaign browser start stalled; closed owned tab before protocol-only continuation | browser | 0 | 0 | 2 | — | <!--g1-literal-->
| 18 | Keycloak | Prepared Suite batch; stopped before any target write because expected existing client was absent | api | 0 | 0 | 0 | — | <!--g1-literal-->
| 19 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 20 | suite | Deploy metadata request correlation fix; preserve prior containers and persisted Run data | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 21 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 113.3 | <!--g1-literal-->
| 22 | Shibboleth | Reuse native HTTP configuration for redirect 301/302/307 and control | api | 0 | 0 | 0 | 0.0 | <!--g1-literal-->
| 23 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 9.4 | <!--g1-literal-->
| 24 | environment | Resolve localhost Suite redirect URLs from inside the IdP container without rewriting HTTP bytes | docker | 0 | 0 | 0 | 0.1 | <!--g1-literal-->
| 25 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 26 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 27 | Shibboleth | Temporary helper serialized namespace prefixes incorrectly; resolver rejected reload and retained previous configuration | file_and_service_reload | 1 | 1 | 0 | — | <!--g1-literal-->
| 28 | Shibboleth | Correct namespace serialization and activate token-bearing fetch URL for Suite redirect key consistency | file_and_service_reload | 1 | 1 | 0 | 0.8 | <!--g1-literal-->
| 29 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 15.4 | <!--g1-literal-->
| 30 | Shibboleth | Native HTTP metadata provider; automatic fixture refresh | file_and_service_reload | 1 | 1 | 0 | 0.5 | <!--g1-literal-->
| 31 | environment | Stop temporary IdP loopback bridge after restoring original metadata provider configuration | docker | 0 | 0 | 0 | 1.1 | <!--g1-literal-->
| 32 | Keycloak | 既存SLO Runの開始・再開を確認。期限切れ終了であり試験成功には計上しない | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 33 | Keycloak | 新Runで共通ケースを再試験。製品設定変更なし | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 34 | Keycloak | 署名必須を一時設定。正常系開始で停止した不成功の試行。設定復元・readback済み | protocol_client_with_native_configuration | 2 | 0 | 0 | 0.1 | <!--g1-literal-->
| 35 | Shibboleth | 既存SLO Runの開始・再開を確認。期限切れ終了であり試験成功には計上しない | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 36 | Shibboleth | 新Runで共通ケースを再試験。製品設定変更なし | protocol_client | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 37 | SimpleSAMLphp | 既存SLO Runの開始・再開を確認。期限切れ終了であり試験成功には計上しない | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 38 | SimpleSAMLphp | 新Runで共通ケースを再試験。製品設定変更なし | protocol_client | 0 | 0 | 0 | 3.8 | <!--g1-literal-->
| 39 | SimpleSAMLphp | 署名必須を一時設定。正常系開始で停止した不成功の試行。設定復元・readback済み | protocol_client_with_native_configuration | 2 | 0 | 0 | 0.4 | <!--g1-literal-->
| 40 | Keycloak | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 274.9 | <!--g1-literal-->
| 41 | Keycloak | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 0.7 | <!--g1-literal-->
| 42 | Shibboleth | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 274.2 | <!--g1-literal-->
| 43 | Shibboleth | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 0.8 | <!--g1-literal-->
| 44 | SimpleSAMLphp | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 62.3 | <!--g1-literal-->
| 45 | SimpleSAMLphp | 追加実装の再試験。既存Planで新Runを作成し正常系と承認済み試験を実行 | protocol_client | 0 | 0 | 0 | 0.6 | <!--g1-literal-->
| 46 | Shibboleth | 取得確認後に送信する連続メタデータ試験。追加URLトークン・送信後固定待機を除去。設定復元済み | native_http_provider_and_protocol_client | 2 | 2 | 0 | 10.0 | <!--g1-literal-->
| 47 | suite | 変更クラス限定の検証イメージを配置。承認済み定義と旧コンテナを保持 | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 48 | suite | 検証済み追加クラスのみ反映。ライブラリと埋め込みカタログの不変を照合 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 49 | Keycloak | 統合追加実装後のブラウザSSO試験列。プロトコルクライアントで実行 | protocol_client | 0 | 0 | 0 | 362.8 | <!--g1-literal-->
| 50 | Shibboleth | 統合追加実装後のブラウザSSO試験列。プロトコルクライアントで実行 | protocol_client | 0 | 0 | 0 | 369.8 | <!--g1-literal-->
| 51 | SimpleSAMLphp | 統合追加実装後のブラウザSSO試験列。プロトコルクライアントで実行 | protocol_client | 0 | 0 | 0 | 87.4 | <!--g1-literal-->
| 52 | Shibboleth | メタデータ検証Run作成と正常系確認 | protocol_client | 0 | 0 | 0 | 0.4 | <!--g1-literal-->
| 53 | Shibboleth | ネイティブHTTP取得でメタデータ46入力を連続実行。設定復元済み | native_http_provider_and_protocol_client | 2 | 2 | 0 | 97.7 | <!--g1-literal-->
| 54 | Shibboleth | 拡張属性と既定ACSの17入力を連続実行。設定復元済み | native_http_provider_and_protocol_client | 2 | 2 | 0 | 37.2 | <!--g1-literal-->
| 55 | suite | 暗号化・ECDSA・公開診断の統合クラスを反映。既存JARと承認済み定義の不変を確認 | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 56 | SimpleSAMLphp | 暗号化Subject入力・公開診断を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 96.0 | <!--g1-literal-->
| 57 | Keycloak | 暗号化Subject入力・公開診断を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 358.1 | <!--g1-literal-->
| 58 | Shibboleth | 暗号化Subject入力・公開診断を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 436.9 | <!--g1-literal-->
| 59 | Shibboleth | ECDSA正常・不正署名試行。不正署名でHTTP400停止、SAML拒否応答なし。設定復元済み | protocol_client | 2 | 2 | 0 | 8.2 | <!--g1-literal-->
| 60 | suite | 文字列型観測と拡張入力の統合クラス・固定スキーマを反映。既存JARと承認済み定義の不変を確認 | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 61 | SimpleSAMLphp | 拡張文字列入力・NameID型観測を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 116.5 | <!--g1-literal-->
| 62 | Keycloak | 拡張文字列入力・NameID型観測を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 477.8 | <!--g1-literal-->
| 63 | Shibboleth | 拡張文字列入力・NameID型観測を含む統合版SSO試験列 | protocol_client | 0 | 0 | 0 | 538.9 | <!--g1-literal-->
| 64 | suite | 要求生成を実行順まで遅延する修正を反映。既存JARと承認済み定義の不変を確認 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 65 | SimpleSAMLphp | 要求生成タイミング修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 118.2 | <!--g1-literal-->
| 66 | Keycloak | 要求生成タイミング修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 476.1 | <!--g1-literal-->
| 67 | Shibboleth | 要求生成タイミング修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 574.5 | <!--g1-literal-->
| 68 | suite | G02受理条件とリテラル文字列入力・署名保持を反映。既存JARと承認済み定義の不変を確認 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 69 | Keycloak | G02受理条件とリテラル文字列入力修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 511.1 | <!--g1-literal-->
| 70 | Shibboleth | G02受理条件とリテラル文字列入力修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 617.5 | <!--g1-literal-->
| 71 | SimpleSAMLphp | G02受理条件とリテラル文字列入力修正後のSSO試験列 | protocol_client | 0 | 0 | 0 | 124.2 | <!--g1-literal-->
| 72 | suite | SLO証拠検査・要求生成・送受信接続・基本ケースを反映。既存JARと承認済み定義の不変を確認 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 73 | Keycloak | 旧Run固定のSLO応答先をPlan固定URLへ変更し、Runごとの設定変更を不要にする | Keycloak admin API | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 74 | suite | Status URI修正を反映。既存ライブラリー不変を検証 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 75 | Shibboleth | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 76 | SimpleSAMLphp | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 4.4 | <!--g1-literal-->
| 77 | Keycloak | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 3.8 | <!--g1-literal-->
| 78 | Shibboleth | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 3.4 | <!--g1-literal-->
| 79 | Keycloak | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 2.8 | <!--g1-literal-->
| 80 | Keycloak | SP起点SLO基本シナリオ実行。途中停止も作業量へ含める | protocol_client | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 81 | SimpleSAMLphp | 旧Run固定SLO応答先をPlan固定へ変更 | local metadata file | 1 | 0 | 0 | 0.3 | <!--g1-literal-->
| 82 | Shibboleth | 旧Run固定SLO応答先をPlan固定へ変更しメタデータを再読込 | local metadata file and reload | 1 | 0 | 0 | 0.4 | <!--g1-literal-->
| 83 | suite | 署名付きRedirect SLO送信を追加し稼働クラス・既存ライブラリー不変を検証 | docker | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 84 | SimpleSAMLphp | 署名を検証できるSLO試験前提として当該SPのsign.logoutを有効化。直後の読戻し解析エラー後、ハッシュ一致・PHP構文・設定値を再確認 | local metadata file | 1 | 0 | 0 | — | <!--g1-literal-->
| 85 | Shibboleth | Redirect SLO追加後の実通信。途中停止も記録 | protocol_client | 0 | 0 | 0 | 2.6 | <!--g1-literal-->
| 86 | Shibboleth | Redirect SLO追加後の実通信。途中停止も記録 | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 87 | SimpleSAMLphp | Redirect SLO追加後の実通信。途中停止も記録 | protocol_client | 0 | 0 | 0 | 3.0 | <!--g1-literal-->
| 88 | SimpleSAMLphp | Redirect SLO追加後の実通信。途中停止も記録 | protocol_client | 0 | 0 | 0 | 4.6 | <!--g1-literal-->
| 89 | suite | Redirect署名とSOAP本文範囲の修正を反映し稼働クラスを検証 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 90 | SimpleSAMLphp | Redirect応答署名の実通信試験のため当該SPのSLO応答方式をRedirectへ変更 | local metadata file | 1 | 0 | 0 | 0.7 | <!--g1-literal-->
| 91 | SimpleSAMLphp | 署名付きRedirect LogoutResponseの実通信と関連受理ケースの確認 | protocol_client | 0 | 0 | 0 | 4.0 | <!--g1-literal-->
| 92 | suite | 専用Redirect受理ケースを反映しクラス・ライブラリーを検証 | docker | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 93 | Keycloak | 基本SLOと専用Redirect受理ケースの連続実行 | protocol_client | 0 | 0 | 0 | 5.1 | <!--g1-literal-->
| 94 | Shibboleth | 基本SLOと専用Redirect受理ケースの連続実行 | protocol_client | 0 | 0 | 0 | 5.1 | <!--g1-literal-->
| 95 | SimpleSAMLphp | 基本SLOと専用Redirect受理ケースの連続実行 | protocol_client | 0 | 0 | 0 | 5.3 | <!--g1-literal-->
| 96 | suite | EncryptedID復号確認ケースを反映し稼働クラスとライブラリーを検証 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 97 | Keycloak | EncryptedID復号対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 5.2 | <!--g1-literal-->
| 98 | Shibboleth | EncryptedID復号対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 5.8 | <!--g1-literal-->
| 99 | SimpleSAMLphp | EncryptedID復号対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 5.9 | <!--g1-literal-->
| 100 | Shibboleth | 既存ロールオーバー設定で復号鍵を追加し公開メタデータへ掲載 | docker | 3 | 0 | 0 | 0.8 | <!--g1-literal-->
| 101 | suite | 複数復号鍵のシナリオを反映し稼働クラスを確認 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 102 | Shibboleth | 非稼働インストールの変更を復元。最初の設定3ファイルは稼働IdPへ未適用だった | docker | 3 | 0 | 0 | — | <!--g1-literal-->
| 103 | Shibboleth | 既存ロールオーバー設定で復号鍵を追加し公開メタデータへ掲載 | docker | 3 | 0 | 0 | 0.8 | <!--g1-literal-->
| 104 | Shibboleth | 再起動時も試験用idp.homeを使用するよう起動設定へ明記 | docker | 1 | 0 | 0 | — | <!--g1-literal-->
| 105 | Shibboleth | Tomcat停止ポート無効で旧プロセスが残ったため、確認した2プロセスを終了し正しいホームで起動 | docker | 0 | 0 | 0 | — | <!--g1-literal-->
| 106 | Keycloak | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 4.8 | <!--g1-literal-->
| 107 | Shibboleth | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 5.9 | <!--g1-literal-->
| 108 | SimpleSAMLphp | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 4.7 | <!--g1-literal-->
| 109 | suite | 設定能力確認・証拠整合性クラスの切替と検証 | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 110 | Keycloak | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 4.9 | <!--g1-literal-->
| 111 | Shibboleth | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 7.3 | <!--g1-literal-->
| 112 | SimpleSAMLphp | 複数復号鍵の対照を含むSLO連続実行 | protocol_client | 0 | 0 | 0 | 5.2 | <!--g1-literal-->

## 判定が変わったケース

| 製品 | Profile | Test | 前 | 後 | 根拠コード |
|---|---|---|---|---|---|
| Keycloak | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |
| Keycloak | browser_sso_idp | `IIP-SSO01-es-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.assertions-protected` |
| Shibboleth | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |
| Shibboleth | browser_sso_idp | `IIP-SSO01-es-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.assertions-protected` |
| Shibboleth | metadata_idp | `IIP-MD02-b-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD02-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD02-d-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD03-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-a4-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-a5-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-cd-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-g-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD06-a1-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-a-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-b-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-d-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| SimpleSAMLphp | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |

## 作業削減に直結する課題

| 優先度 | 課題 | 今回確認できたこと | 改善案 |
|---|---|---|---|
| 高 | 操作しても判定できない項目が操作待ちに見える | BrowserEvidenceTestCaseは完了操作後もoracle-unavailableを返す。CONFIGの一部は自己申告へ進む | 開始前に自動判定・証拠確認・未実装を表示し、判定できない設定作業を要求しない |
| 高 | メタデータ取得待ちの順序 | ネイティブHTTP取得が動いていても、試験開始後の取得より応答が先に到着するとSuiteが400で止まる | 試験開始→取得確認→要求送信の順をSuiteで制御する。固定の待ち時間に依存しない |
| 高 | メタデータ手動取り込みの証拠が判定に接続されない | 一括取り込み後の応答があっても、手動downloadはfetched証拠に数えられない | 取り込んだファイルdigestと対象側の取り込み記録を結び、HTTP取得と異なる証拠種別で扱う |
| 高 | リダイレクト後の鍵が一致しない | tokenのない安定URLからのリダイレクト先が通常鍵を返し、polling用の要求署名と不一致になる | 取得URLにtokenを明示して試験継続。Suite側でモードを正しく引き継ぎ、追加設定をなくす |
| 中 | localhostの意味がホストとコンテナで異なる | リダイレクト先へ接続できず補助転送が必要になった | ブラウザ・製品・Suiteで共通の到達可能ホスト名を使う検証構成にする |
| 中 | 途中エラーで連続試験が停止する | SimpleSAMLphpのKeyValue-onlyで停止し、後続試験への継続が1回必要 | エラー証拠を保存し、独立した後続試験を再開できるようにする |
| 修正済み | メタデータ方式の切り替えで古い要求IDを優先する | 一括取り込み後のHTTP更新で正しい応答をSuiteが誤って相関不一致にした | 発行済み要求の対応付けを修正。回帰テスト後に検証イメージへ反映し、同じRunで継続完了 |
| 中 | 同じ正常系の追加実行・設定往復 | 追加SSOでAudienceの反復観測と非暗号化Assertionの署名確認が進む | 必要な正常系を初回の実行計画にまとめ、設定のスナップショット・復元を製品アダプタで扱う |
| 中 | IdP起点SSOを受信できない | 通常受信経路が既存AuthnRequestのInResponseTo一致を要求する | 明示的に許可されたRun専用のIdP起点受信経路と正負対照を設計する |

ShibbolethのHTTP取得方式は[公式のFileBackedHTTPMetadataProvider資料](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506865)を参照しました。「修正済み」と明記した要求IDの対応付け以外は、今回の実測・コード調査からの改善提案です。

## 検証と残る範囲

今回変更した製品設定は復元済みです。要求IDの対応付け修正はSpPeerRoundTripTestに同じvariantが両方式に存在する回帰条件を加えて検証し、ローカル検証イメージに反映しました。ケース定義や判定レベルは変更していません。実行前後のHTML/JSON一致と、新たなPASSが参照するTranscriptの存在も検証しました。

未検証項目は残っています。操作だけで解消できない自動判定未実装、拒否の証明が不足する試験、運用・設定の裏付けが必要な自己申告などを含みます。追加の試行を完了したことと、全試験・製品全体の適合確認が完了したことは区別します。

## 証拠と再生成

操作台帳、設定の変更前バックアップ、実行前後のresult.json、試験スクリプトはローカルの `build/acceptance/reference-20260914/interaction-followup/` に保存しています。設定バックアップは公開・コミット対象にしません。

再生成: `.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup`。
