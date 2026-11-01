package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PageTextTest {
    @Test
    void choosesJapaneseOnlyWhenItIsTheMostPreferredLanguage() {
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("ja"));
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("ja-JP,ja;q=0.9,en;q=0.8"));
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("en;q=0.5, ja;q=0.8"));
        assertSame(PageText.ENGLISH, PageText.of("en-US,en;q=0.9,ja;q=0.8"));
        assertSame(PageText.ENGLISH, PageText.of("ja;q=0"));
        assertSame(PageText.ENGLISH, PageText.of("*"));
        assertSame(PageText.ENGLISH, PageText.of("jam"));
        assertSame(PageText.ENGLISH, PageText.of(""));
        assertSame(PageText.ENGLISH, PageText.of(null));
        assertSame(PageText.ENGLISH, PageText.of("ja;q=oops"));
    }

    @Test
    void localizesOnlyTheStaticTemplateNeverTheRecordedValues() {
        var text = PageText.of("ja");
        var html = PeerCompletionPage.render(text, URI.create("https://app.example/manage/run_test"),
                "/p/plan_test/ui/completion.css", Map.of("note", "Return to Run workspace"));
        assertTrue(html.contains("<html lang=\"ja\">"));
        assertTrue(html.contains("Runワークスペースに戻る</a>"));
        assertTrue(html.contains("記録されたことは、適合（PASS）を意味しません。"));
        assertTrue(html.contains("<pre>{note=Return to Run workspace}</pre>"), html);
        assertFalse(html.contains("Recorded does not mean"));
    }

    @Test
    void japaneseEntriesAreCompleteAndKeepTheSafetyMeaning() {
        for (var entry : PageTextJa.ENTRIES.entrySet()) {
            assertFalse(entry.getValue().isBlank(), entry.getKey());
        }
        assertEquals("記録されたことは、適合（PASS）を意味しません。結果は承認済みのチェックによって決まります。",
                PageTextJa.ENTRIES.get(
                        "Recorded does not mean conformance PASS. The approved checks determine the result."));
    }

    @Test
    void japaneseStandalonePagesTranslateStaticTextAndKeepDynamicValues() {
        var page = SamlScopeApplication.metadataFetchWaitingPage(PageText.of("ja"), "/p/plan/next?a=1&b=2");
        assertTrue(page.contains("<html lang=\"ja\">"), page);
        assertTrue(page.contains("メタデータの取得を待っています"), page);
        assertTrue(page.contains("a=1&amp;b=2"), page);
        var transition = SamlScopeApplication.metadataPollingTransitionPage(PageText.of("ja"), "/x", 17);
        assertTrue(transition.contains("次の署名付きリクエストは17秒後に自動で開始されます。"), transition);
    }
}
