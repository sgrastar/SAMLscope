# Keycloakの属性名・NameFormat生成の実測

`IIP-IDP01-a-idp-01`を、標準User Property mapperの明示的なクライアント設定で再試験した。これは属性生成能力の試験であり、メタデータXMLを製品自身が解釈した証拠としては扱わない。

## 実測経路

`dev/keycloak/attribute_name_capability.py`は既存クライアントへの上書きを拒否し、試験固有のentityIDでクライアントを作成する。最初はmapperなしで通常ログインし、対象の属性がないことをSuiteの原本判定で確認する。続いて標準`saml-user-property-mapper`を設定し、同じユーザー入力元`firstName`からURI属性名と任意文字列属性名を生成する。NameFormatには専用の独自URIを指定する。

設定は管理APIで読み戻して完全一致を確認し、その後の署名・暗号化されたSAML応答をSuiteの既存判定処理で検査する。実験後は作成したクライアントIDとentityIDを再照合して削除し、検索で不存在を確認する。トークン・資格情報・属性値を診断結果へ保存しない。

## 結果と残条件

<!--g1-literal--> Run `run_8EC5HRA77MZWGCHCXR1DKB9ADE`で通常／設定後の2往復を実行した。設定後の応答では`urn-name`と`non-uri-name`を確認できた。`unknown-name-format`は未観測であり、正式Outcome／VerdictはNOT_VERIFIEDを維持した。原本読取や署名検証のエラーは記録されていない。

独自NameFormatは設定読戻しには残ったが、署名付き応答で確認できなかった。設定が保存できることを生成能力の成功にはしない。また、このmapper経路の結果を、製品全体で独自NameFormatを生成できない証拠にも使わない。次は他の標準mapperやネイティブ設定経路を確認する。

`verify_keycloak_attribute_name_diagnosis.py`は、正常系の対象属性欠落、mapper設定前後の同一性、設定変更点、元応答のダイジェストと参照、復元、正式な未検証結果を照合する。台帳は古い操作待ちから、この実測に基づいた残条件へ更新した。

<!--g1-literal--> 未検証462件／156ケースIDは不変。部分条件の確認をケース全体のSuccessとして数えていない。証拠は`build/acceptance/reference-20260918/keycloak-attribute-name-capability/`。

## 操作費用と検証範囲

<!--g1-literal--> 製品設定書込3回（クライアント作成、mapper更新、クライアント削除）、管理API読取8回、プロトコル往復2回。サービス再読込・製品再起動・Suite更新・本人操作は0回。既存クライアント上書きなし、作成クライアントの削除確認済み。

Python構文、ネイティブ読戻しと復元、正式ケース結果、原本参照、生成台帳の契約監査を確認した。テスト一式は追加実装のバッチ確認へまとめる。G2の既存署名差分は未解消である。
