# メタデータ原本のRun内記録

## 実装

試験用メタデータの生成時に、HTTP応答へ渡すものと同一のバイト列をTranscriptへ保存する。`MetadataResponseEvidence`が`MetadataPrepared`を記録し、取得／エクスポート記録のID、variant、feed、原本のSHA-256を保持する。decodedSamlRefから元XMLを読めるため、variant名から配信内容を推定する必要がなくなる。

<!--g1-literal--> 対象はvariant指定のmetadata、live、live/content、preloaded、preloaded/downloadの5経路。Runへ結び付かない通常のメタデータ取得を任意のRunへ割り当てない。リダイレクトだけの応答にはXML原本を記録せず、後続のcontent取得へ紐付ける。エクスポートと取得はsourceTypeで区別する。

記録時点はServletが送信する前なので、deliveryを`PREPARED`とする。保存に成功しただけでは、HTTP配送成功・製品による取込・メタデータ消費を確定しない。要求のAuthorization／Cookieなどをこの応答記録へコピーしない。

## 実機での照合

新Run `run_ZTEB6PCRWXJM0CZ6QWCZRR966T`で、SimpleSAMLphpのアルゴリズム広告条件を一括実行した。`verify_prepared_metadata_batch.py`により、Suite原本、取得記録、製品自身のパーサへ渡したfixture、設定読戻し、復元を照合した。

<!--g1-literal--> 全13条件の元XMLがバイト単位で一致した。Run固定のIdP鍵によるResponse署名も13条件すべてで検証できた。広告と異なるSHA256選択の観測は再現したが、case判定への接続が残るため、未検証は483観測・159ケースIDのまま。

証拠は`build/acceptance/reference-20260918/simplesamlphp-algorithm-recorded-metadata/`。`prepared-metadata-verification.json`、`verified-algorithm-signatures.json`、`algorithm-selection-diagnosis.json`を保存し、MD05.ea／ebの追加観測をこの新Runへ更新した。既存ケースのVerdictは変更していない。

保存済みRunに原本と相関を揃えたため、今後の判定処理追加ではこの証拠を再評価できる。製品設定・ログインを毎回やり直すことを前提にしない。

## 検証と配備

APIの回帰テストを実施し、HTTPで受信したバイト列と保存原本の一致、SHA-256、取得記録への参照、OUTBOUND方向、PREPARED状態、リダイレクトだけの記録との区別を確認した。G1生成一致・構造検証と台帳監査も確認した。G2の既存署名差分は未解消。

稼働イメージは`samlscope:reference-metadata-response-v33`、digestは`sha256:009c94ba10599f298720703560592652ac4fb0e2384dde12049edfa897dd74e0`。今回のApplication変更を含め、以前からの無関係なSOAP差分だけを除いたソースからApplicationクラスを再コンパイルした。原本とJARのハッシュは`build/acceptance/reference-20260918/metadata-response-runtime/`に保存した。

<!--g1-literal--> 今回のネイティブ取込13、製品設定書込27（投入・復元と最後の復元）、Run作成1、preflight1、署名対照要求13、通常要求13、Docker build1、Suite／転送コンテナ再作成各1、本人操作0、製品再起動0。全設定の復元をSHA-256一致で確認した。
