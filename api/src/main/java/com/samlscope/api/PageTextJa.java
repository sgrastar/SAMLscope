package com.samlscope.api;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;

/** Japanese text for the static parts of the server-rendered pages; the English text is the key. */
final class PageTextJa {
    private PageTextJa() {}

    /** Longest key first, so a short key never rewrites part of a longer sentence. */
    static final Map<String, String> ENTRIES = build();

    private static Map<String, String> build() {
        var e = new ArrayList<Map.Entry<String, String>>();
        e.add(Map.entry("Response recorded | SAMLscope", "応答を記録しました | SAMLscope"));
        e.add(Map.entry("BROWSER ROUND TRIP", "ブラウザーのラウンドトリップ"));
        e.add(Map.entry("SAML Response recorded", "SAML Responseを記録しました"));
        e.add(Map.entry("Your IdP response has reached SAMLscope. Return to your Run to review the evidence and continue testing.", "IdPのレスポンスがSAMLscopeに届きました。Runに戻って証拠を確認し、テストを続けてください。"));
        e.add(Map.entry("Recorded does not mean conformance PASS. The approved checks determine the result.", "記録されたことは、適合（PASS）を意味しません。結果は承認済みのチェックによって決まります。"));
        e.add(Map.entry("Return to Run workspace", "Runワークスペースに戻る"));
        e.add(Map.entry("Next: run the initial checks (M1), then follow the pending interactions.", "次の手順：最初のチェック（M1）を実行し、保留中の操作に従ってください。"));
        e.add(Map.entry("Technical response details", "レスポンスの技術的な詳細"));
        e.add(Map.entry("PRIVATE SESSION REQUIRED", "プライベートセッションが必要です"));
        e.add(Map.entry("Start without an existing IdP session", "既存のIdPセッションなしで開始してください"));
        e.add(Map.entry("Move this page to a new private browser window before continuing. Keep the original Run workspace open.", "続ける前に、このページを新しいプライベートブラウザーウィンドウに移してください。元のRunワークスペースは開いたままにしてください。"));
        e.add(Map.entry("If the IdP shows a sign-in or consent screen during this IsPassive request, do not enter credentials.", "このIsPassiveリクエストの間にIdPがサインイン画面または同意画面を表示しても、認証情報は入力しないでください。"));
        e.add(Map.entry("Return to the workspace and record that no SAML Response was returned.", "ワークスペースに戻り、SAML Responseが返されなかったことを記録してください。"));
        e.add(Map.entry("This private browser context has no active session with the target IdP.", "このプライベートブラウザーには、対象のIdPとの有効なセッションがありません。"));
        e.add(Map.entry("Keep the current IdP session.", "現在のIdPセッションを維持してください。"));
        e.add(Map.entry("Sign in only if the target asks during a normal control. SAMLscope does not intentionally clear the session between checks.", "通常のチェックの間に対象製品から求められた場合にのみサインインしてください。SAMLscopeは、チェックの間にセッションを意図的に消去しません。"));
        e.add(Map.entry("Browser check | SAMLscope", "ブラウザーチェック | SAMLscope"));
        e.add(Map.entry("BROWSER-ASSISTED CHECK", "ブラウザー操作を伴うチェック"));
        e.add(Map.entry("Run one SAML check", "SAMLチェックを1件実行"));
        e.add(Map.entry("SAMLscope sends one request at a time. After its Response is recorded, this tab stops and lets you return to the Run workspace before the next request.", "SAMLscopeはリクエストを1件ずつ送信します。そのResponseが記録されると、このタブは停止し、次のリクエストの前にRunワークスペースへ戻れるようになります。"));
        e.add(Map.entry("CURRENT CHECK", "現在のチェック"));
        e.add(Map.entry("What SAMLscope will verify", "SAMLscopeが検証する内容"));
        e.add(Map.entry("Continue with this request", "このリクエストで続ける"));
        e.add(Map.entry("Quick is one browser campaign containing multiple protocol checks. It does not mean one SAML request or repeated forced sign-ins.", "「Quick」は、複数のプロトコルチェックを含む1回のブラウザーキャンペーンです。SAMLリクエスト1件や、強制サインインの繰り返しを意味するものではありません。"));
        e.add(Map.entry("The next browser check is ready. Start it from the workspace when you are ready.", "次のブラウザーチェックの準備ができました。準備ができたら、ワークスペースから開始してください。"));
        e.add(Map.entry("This browser campaign has no immediately ready check.", "このブラウザーキャンペーンには、すぐに実行できるチェックはありません。"));
        e.add(Map.entry("BROWSER CHECK PAUSED", "ブラウザーチェックは一時停止中です"));
        e.add(Map.entry("The response reached SAMLscope. The next request was not sent automatically.", "レスポンスがSAMLscopeに届きました。次のリクエストは自動では送信されていません。"));
        e.add(Map.entry("Close this tab and return to workspace", "このタブを閉じてワークスペースに戻る"));
        e.add(Map.entry("Returning to the existing workspace… If this tab remains open, use the button above or close it manually.", "既存のワークスペースに戻っています… このタブが開いたままの場合は、上のボタンを使うか、手動で閉じてください。"));
        e.add(Map.entry("Your browser kept this tab open. Close it manually to return to the existing workspace.", "ブラウザーがこのタブを開いたままにしました。手動で閉じて、既存のワークスペースに戻ってください。"));
        e.add(Map.entry("Continue SAML sign-in", "SAMLサインインを続行"));
        e.add(Map.entry("Continuing to the service provider…", "サービスプロバイダーに接続しています…"));
        e.add(Map.entry("Run active SAML probe", "アクティブSAMLプローブを実行"));
        e.add(Map.entry("Sending the next active probe to the identity provider…", "次のアクティブプローブをIdentity Providerに送信しています…"));
        e.add(Map.entry("<noscript><button type=\"submit\">Continue</button></noscript>", "<noscript><button type=\"submit\">続行</button></noscript>"));
        e.add(Map.entry("Automatic metadata campaign completed", "自動メタデータキャンペーンが完了しました"));
        e.add(Map.entry("The Target fetched the final fixture but did not return a correlated SAML response. SAMLscope recorded no target outcome from this continuation.", "対象製品は最後のフィクスチャーを取得しましたが、対応するSAMLレスポンスを返しませんでした。この続行からは、SAMLscopeは対象製品の結果を記録していません。"));
        e.add(Map.entry("Signature control response recorded", "署名コントロールのレスポンスを記録しました"));
        e.add(Map.entry("The fixture remains selected for its normal signed request.", "このフィクスチャーは、通常の署名付きリクエスト用に選択されたままです。"));
        e.add(Map.entry("This polling fixture did not produce a correlated Success response", "このポーリング用フィクスチャーでは、対応するSuccessレスポンスが得られませんでした"));
        e.add(Map.entry("The metadata fetch and response were recorded. SAMLscope does not convert the missing Success response into a target violation.", "メタデータの取得とレスポンスは記録されました。SAMLscopeは、Successレスポンスがないことを対象製品の違反とは見なしません。"));
        e.add(Map.entry("Continue with the next polling fixture", "次のポーリング用フィクスチャーに進む"));
        e.add(Map.entry("Return to the Run page to evaluate the recorded evidence. Only correlated Success responses count as metadata-use evidence.", "Runのページに戻り、記録された証拠を評価してください。メタデータ使用の証拠として数えられるのは、対応するSuccessレスポンスだけです。"));
        e.add(Map.entry("This fixture did not produce a correlated Success response", "このフィクスチャーでは、対応するSuccessレスポンスが得られませんでした"));
        e.add(Map.entry("SAMLscope recorded the response without turning it into a target violation. Continue only after reviewing the target's result.", "SAMLscopeはレスポンスを記録しましたが、対象製品の違反とは見なしていません。対象製品の結果を確認してから続けてください。"));
        e.add(Map.entry("Continue with the next imported fixture", "次のインポート済みフィクスチャーに進む"));
        e.add(Map.entry("Preloaded metadata campaign attempts completed", "事前読み込みメタデータキャンペーンの試行が完了しました"));
        e.add(Map.entry("Waiting for the target metadata refresh window", "対象製品のメタデータ更新ウィンドウを待っています"));
        e.add(Map.entry("Fixture accepted", "フィクスチャーを受け付けました"));
        e.add(Map.entry("SAMLscope recorded the correlated metadata fetch and Success response.", "SAMLscopeは、対応するメタデータ取得とSuccessレスポンスを記録しました。"));
        e.add(Map.entry("The next signed request starts automatically in ", "次の署名付きリクエストは"));
        e.add(Map.entry(" seconds. This pacing lets a target's standard metadata-key refresh window elapse; it does not affect the conformance outcome.", "秒後に自動で開始されます。この間隔は、対象製品が標準で行うメタデータ鍵の更新ウィンドウが経過するのを待つためのもので、適合性の結果には影響しません。"));
        e.add(Map.entry("Continue now", "今すぐ続ける"));
        e.add(Map.entry("Waiting for metadata retrieval", "メタデータの取得を待っています"));
        e.add(Map.entry("The next fixture is ready. The authentication request will start automatically after the target retrieves it. Keep this page open.", "次のフィクスチャーの準備ができました。対象製品が取得すると、認証リクエストが自動で開始されます。このページは開いたままにしてください。"));
        e.add(Map.entry("This wait does not determine the test result.", "この待機は、テストの結果を決めるものではありません。"));
        e.add(Map.entry("Check again", "もう一度確認"));
        e.add(Map.entry("Login failed", "ログインに失敗しました"));
        e.add(Map.entry("Login could not be completed", "ログインを完了できませんでした"));
        e.add(Map.entry("The request expired or was rejected.", "リクエストの有効期限が切れたか、拒否されました。"));
        e.add(Map.entry("Try signing in again", "もう一度サインインする"));
        e.sort(Comparator.comparingInt((Map.Entry<String, String> entry) -> entry.getKey().length()).reversed());
        var ordered = new LinkedHashMap<String, String>();
        for (var entry : e) ordered.put(entry.getKey(), entry.getValue());
        return java.util.Collections.unmodifiableMap(ordered);
    }
}
