"""Generate operation-cost and result deltas from the recorded local follow-up evidence."""
import argparse
from collections import Counter
import json
from pathlib import Path

PRODUCTS = ('keycloak', 'shibboleth', 'simplesamlphp')
NAMES = dict(zip(PRODUCTS, ('Keycloak', 'Shibboleth', 'SimpleSAMLphp')))

def cases(path):
    return {c['id']: c for r in json.loads(path.read_text())['requirements'] for c in r['cases']}

def render(root, output):
    operations = [json.loads(line) for line in (root / 'operations.jsonl').read_text().splitlines() if line]
    totals = {p: Counter() for p in PRODUCTS}
    transitions = []
    for before in sorted((root / 'before').glob('*/*/result.json')):
        product, profile = before.parent.parent.name, before.parent.name
        after = root / 'after' / product / profile / 'result.json'
        old, new = cases(before), cases(after if after.exists() else before)
        if old.keys() != new.keys():
            raise ValueError('Case set changed: compare equivalent definitions first')
        totals[product]['before'] += sum(c['verdict'] == 'NOT_VERIFIED' for c in old.values())
        totals[product]['after'] += sum(c['verdict'] == 'NOT_VERIFIED' for c in new.values())
        for key, case in new.items():
            if old[key]['verdict'] != case['verdict']:
                transitions.append((product, profile, key, old[key]['verdict'], case['verdict'], case['reason_code']))
    lines = ['# 追加試験と設定・操作コストの記録', '',
             'この記録は2026-09-14の追加試験だけを計測対象にしています。それ以前の環境構築・試行の回数や時間は未計測であり、ゼロとは扱いません。既存Runに追加の証拠を集め、同じケース定義で判定の差分を比較しています。', '',
             'ユーザー本人の操作、エージェントが代行したブラウザ操作、API・ファイルによる設定変更を別々に数えます。設定書き込みは復元も含めて1回ずつ数え、サービス再読み込みは別計上します。ブラウザ操作はページを開く・項目入力・クリック・手動継続をそれぞれ1回と数え、自動リダイレクトは含めません。スクリプトによる代行は、設定作業自体の消滅を意味しません。', '',
             '## 判定の変化', '', '| 製品 | Not verified：前 | 後 | 減少 |', '|---|---:|---:|---:|']
    for p in PRODUCTS:
        t=totals[p]; lines.append(f"| {NAMES[p]} | {t['before']} | {t['after']} | {t['before']-t['after']} |")
    lines += ['', '上の差分は最初の追加試験の記録です。その後の全件監査では共通ケースを別Runで再試験し、追加で5件のSuccessを確認しました。さらに追加実装後の再試験で、現在の未検証件数は全件台帳で集計しています（[実装記録](27-additional-implementation.md)）。詳細と製品別の再試験結果は [全件台帳](26-unverified-case-inventory.md) を参照してください。以下の作業量・明細には、この再試験と不成功だった署名必須設定の試行も含めます。', '', 'この件数は製品・プロファイル・ケース単位の延べ観測数です。操作や設定の回数とは異なります。', '',
              '## 作業量', '', '| 製品 | 設定書き込み（復元含む） | サービス再読込 | 代行ブラウザ操作 | ユーザー本人の操作 |', '|---|---:|---:|---:|---:|']
    for p in PRODUCTS:
        rows=[r for r in operations if r['product']==p]
        counts=[sum(r.get(k,0) for r in rows) for k in ('configuration_writes','service_reloads','browser_actions','human_actions')]
        lines.append('| '+NAMES[p]+' | '+' | '.join(map(str,counts))+' |')
    lines += ['', f"補助接続コンテナの起動は{sum(r.get('environment_helper_starts',0) for r in operations)}回です。一時スクリプトの誤りによる設定再試行も台帳に含め、製品の不具合とは扱いません。"]
    lines += ['', f"Suiteのローカル検証環境の再起動は{sum(r.get('suite_restarts',0) for r in operations)}回、転送コンテナの再起動は{sum(r.get('forward_restarts',0) for r in operations)}回です。製品の設定操作とは別計上しています。", '', '操作時間はツール呼び出しの実測時間またはスクリプト内の経過時間です。調査・判断・コード作成・呼び出し間の時間を含まず、人間が手作業した場合の所要時間としては使えません。未計測は「—」と表示します。', '',
              '## 操作明細', '', '| # | 製品 | 作業 | 実行手段 | 設定書込 | 再読込 | ブラウザ操作 | 実測秒 |', '|---:|---|---|---|---:|---:|---:|---:|']
    for i,r in enumerate(operations,1):
        duration=r.get('duration_seconds')
        if r.get('duration_seconds_measured') is False: duration=None
        seconds='—' if duration is None else f'{duration:.1f}'
        lines.append(f"| {i} | {NAMES.get(r['product'],r['product'])} | {r['description'].replace('|','/')} | {r.get('execution','—')} | {r.get('configuration_writes',0)} | {r.get('service_reloads',0)} | {r.get('browser_actions',0)} | {seconds} | <!--g1-literal-->")
    lines += ['', '## 判定が変わったケース', '', '| 製品 | Profile | Test | 前 | 後 | 根拠コード |', '|---|---|---|---|---|---|']
    for product,profile,key,old,new,reason in transitions:
        lines.append(f'| {NAMES[product]} | {profile} | `{key}` | {old} | {new} | `{reason}` |')
    lines += ['', '## 作業削減に直結する課題', '',
              '| 優先度 | 課題 | 今回確認できたこと | 改善案 |', '|---|---|---|---|',
              '| 高 | 操作しても判定できない項目が操作待ちに見える | BrowserEvidenceTestCaseは完了操作後もoracle-unavailableを返す。CONFIGの一部は自己申告へ進む | 開始前に自動判定・証拠確認・未実装を表示し、判定できない設定作業を要求しない |',
              '| 高 | メタデータ取得待ちの順序 | ネイティブHTTP取得が動いていても、試験開始後の取得より応答が先に到着するとSuiteが400で止まる | 試験開始→取得確認→要求送信の順をSuiteで制御する。固定の待ち時間に依存しない |',
              '| 高 | メタデータ手動取り込みの証拠が判定に接続されない | 一括取り込み後の応答があっても、手動downloadはfetched証拠に数えられない | 取り込んだファイルdigestと対象側の取り込み記録を結び、HTTP取得と異なる証拠種別で扱う |',
              '| 高 | リダイレクト後の鍵が一致しない | tokenのない安定URLからのリダイレクト先が通常鍵を返し、polling用の要求署名と不一致になる | 取得URLにtokenを明示して試験継続。Suite側でモードを正しく引き継ぎ、追加設定をなくす |',
              '| 中 | localhostの意味がホストとコンテナで異なる | リダイレクト先へ接続できず補助転送が必要になった | ブラウザ・製品・Suiteで共通の到達可能ホスト名を使う検証構成にする |',
              '| 中 | 途中エラーで連続試験が停止する | SimpleSAMLphpのKeyValue-onlyで停止し、後続試験への継続が1回必要 | エラー証拠を保存し、独立した後続試験を再開できるようにする |',
              '| 修正済み | メタデータ方式の切り替えで古い要求IDを優先する | 一括取り込み後のHTTP更新で正しい応答をSuiteが誤って相関不一致にした | 発行済み要求の対応付けを修正。回帰テスト後に検証イメージへ反映し、同じRunで継続完了 |',
              '| 中 | 同じ正常系の追加実行・設定往復 | 追加SSOでAudienceの反復観測と非暗号化Assertionの署名確認が進む | 必要な正常系を初回の実行計画にまとめ、設定のスナップショット・復元を製品アダプタで扱う |',
              '| 中 | IdP起点SSOを受信できない | 通常受信経路が既存AuthnRequestのInResponseTo一致を要求する | 明示的に許可されたRun専用のIdP起点受信経路と正負対照を設計する |', '',
              'ShibbolethのHTTP取得方式は[公式のFileBackedHTTPMetadataProvider資料](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506865)を参照しました。「修正済み」と明記した要求IDの対応付け以外は、今回の実測・コード調査からの改善提案です。', '',
              '## 検証と残る範囲', '',
              '今回変更した製品設定は復元済みです。要求IDの対応付け修正はSpPeerRoundTripTestに同じvariantが両方式に存在する回帰条件を加えて検証し、ローカル検証イメージに反映しました。ケース定義や判定レベルは変更していません。実行前後のHTML/JSON一致と、新たなPASSが参照するTranscriptの存在も検証しました。', '',
              '未検証項目は残っています。操作だけで解消できない自動判定未実装、拒否の証明が不足する試験、運用・設定の裏付けが必要な自己申告などを含みます。追加の試行を完了したことと、全試験・製品全体の適合確認が完了したことは区別します。', '',
              '## 証拠と再生成', '',
              '操作台帳、設定の変更前バックアップ、実行前後のresult.json、試験スクリプトはローカルの `build/acceptance/reference-20260914/interaction-followup/` に保存しています。設定バックアップは公開・コミット対象にしません。', '',
              '再生成: `.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup`。', '']
    output.write_text('\n'.join(lines))
    (root/'result-delta.json').write_text(json.dumps({'totals':totals,'transitions':transitions},ensure_ascii=False,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('docs/25-interaction-execution-cost.md'))
    args=parser.parse_args();render(args.evidence_root,args.output)
