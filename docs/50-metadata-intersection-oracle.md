# メタデータの暗号・署名・パラメーター共通部分の判定

## 正式判定へ接続した範囲

`IIP-MD05-e8-idp-01`をM2 CONFIGの実測判定へ接続した。`MetadataAlgorithmEvidence`から原本メタデータ、取得記録、送信要求、検証済みResponseを関連付けた交換記録を取り出し、`MetadataIntersectionEvidence`で承認済みの暗号方式、署名方式、Digest、鍵長／方式固有パラメーターを照合する。

取込の準備確認は製品自身の経路へfixtureを投入した事実の確認に限る。確認操作そのものやXML取込成功をSuccessにはしない。応答署名はRun固定の対象メタデータの鍵で検証し、fixture別の復号鍵は元SPメタデータの公開鍵と照合する。暗号化Assertionを実際に復号し、内包する署名があればそれも検証する。秘密鍵や復号平文は証拠へ保存しない。

<!--g1-literal--> 必須fixtureは対照を含む13条件。SHA256/384の署名・Digest、AES128/256 GCM、明示KeySize付きCBC、旧／新RSA-OAEPのSHA1/SHA256とMGF、MaxKeySizeによる署名候補の除外を同一キャンペーンで要求する。

異なるキャンペーンの部分証拠は合成しない。原本不一致、署名未検証、復号不成立、条件不足、対照不足はNOT_VERIFIED。SHA256/384の生成能力が実測で成立することも確認し、能力未確認を製品の違反へ変換しない。鍵サイズの除外値は試験入力であり、Suite独自の安全性しきい値ではない。CaseはOutcomeを返し、Verdictへの変換は既存Evaluatorに任せる。

## 実機結果と台帳

Shibboleth Run `run_6E5BWBMYHJFZS31AKS9Q1WCP72`、Plan `plan_G5ZG6VA64WK6T2RTS6ACYCCT50`で元fixtureを一時FilesystemMetadataProviderへ投入し、各条件のSSOを実行した。読込先と元設定は復元済みで、一時ファイルの削除と元設定ハッシュ一致を確認した。

<!--g1-literal--> 全13条件で原本・署名・対応鍵復号を確認した。別鍵による復号は全13条件で拒否された。判定の不足条件・証拠問題・選択不一致は空で、MD05.e8は`SATISFIED / PASS`、理由は`metadata.algorithms.intersection-observed`となった。

証拠は`build/acceptance/reference-20260918/shibboleth-intersection-metadata/`、正式結果と準備確認根拠は隣接する`shibboleth-intersection-evaluation/`。元結果を上書きせず、判定前後を保存した。`verify_metadata_intersection.py`が原本ハッシュ、ネイティブ取込・復元、署名、復号、全条件、結果参照を確認してから台帳へ採用する。

<!--g1-literal--> 未検証は475から474観測へ減少、異なるケースIDは157のまま。条件数や追加テスト数を解消件数として数えていない。新たな製品FAILはない。

## 検証と操作負担

判定テストで完全な対照、鍵長制限を無視するmutant、条件欠落、キャンペーン混在、破損入力、異なる鍵、誤ったOAEPパラメーターを検査した。既存の署名方式／Role優先の判定回帰も実施。APIテストではM2への登録と、証拠なしの準備確認だけではSuccessにならないことを検査した。

<!--g1-literal--> 製品メタデータ書込13、読込先の投入・復元2、一時ファイル削除1、合計16書込操作。サービス再読込14、正常SSO試行13、無効署名試行13。Run作成・preflight各1。Docker build1、Suite／転送コンテナ再作成各1、製品再起動0、本人操作0。復号検査1回、準備確認POST1回。結果読取URLの誤りによる404を1回記録し、正しいURLへ修正した。

実行イメージは`samlscope:reference-intersection-v39`、digestは`sha256:17c47a45e48bcefde75e45b500a4f823248a41f124e39cb0428cab9d699ee31a`。既存の未コミットSOAP変更は実行イメージから除外した。

<!--g1-literal--> 対象Runnerテスト12・APIテスト8が成功。G1生成一致・構造46/46、台帳監査エラーなし。G2は20/21で、既存のG2-30署名差分のみが残る。

## 継続対象

この判定はメタデータ消費側の共通部分選択を対象にする。MD05.eの全拡張点、別製品への展開、ALG04/06の該当ブラウザ／ECPプロファイルでの判定接続を解消済みとは扱わない。G2の既存保護ソース署名差分は残り、リリース可能とはしていない。
