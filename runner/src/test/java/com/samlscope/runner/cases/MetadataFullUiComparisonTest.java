package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MetadataFullUiComparisonTest {
    static final String INPUT = """
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
             xmlns:u="urn:oasis:names:tc:SAML:metadata:ui" xmlns:x="urn:test:foreign" entityID="https://suite.example/sp">
            <md:SPSSODescriptor><md:Extensions><u:UIInfo>
             <u:DisplayName xml:lang="en">Service</u:DisplayName><u:DisplayName xml:lang="ja">サービス</u:DisplayName>
             <u:Description xml:lang="en">Complete service description</u:Description>
             <u:Description xml:lang="ja">完全な説明</u:Description>
             <u:Keywords xml:lang="en">saml interop</u:Keywords>
             <u:Logo xml:lang="en" width="180" height="48">https://suite.example/logo</u:Logo>
             <u:InformationURL xml:lang="en">https://suite.example/info</u:InformationURL>
             <u:PrivacyStatementURL xml:lang="en">https://suite.example/privacy</u:PrivacyStatementURL><x:Probe>unknown</x:Probe>
            </u:UIInfo><u:DiscoHints><u:IPHint>192.0.2.0/24</u:IPHint><u:IPHint>2001:db8::/32</u:IPHint>
             <u:DomainHint>example.org</u:DomainHint><u:GeolocationHint>geo:37.78,-122.39</u:GeolocationHint>
             <x:Hint>unknown hint</x:Hint></u:DiscoHints></md:Extensions></md:SPSSODescriptor></md:EntityDescriptor>
            """;
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    @Test void completeNativeValuesMatchAcrossSerializationAndUnknownMeaningMayBeIgnored() throws Exception {
        var input = MetadataFullUiComparison.input(bytes(INPUT));
        var nativeModel = INPUT.replace("<x:Probe>unknown</x:Probe>", "")
                .replace("<x:Hint>unknown hint</x:Hint>", "").replace("xmlns:u=", "xmlns:mdui=")
                .replace("<u:", "<mdui:").replace("</u:", "</mdui:");
        assertTrue(MetadataFullUiComparison.matches(input, MetadataFullUiComparison.output(bytes(nativeModel))));
    }
    @Test void NativeModelIgnoringBothExtensionsDoesNotPass() throws Exception {
        var ignored = INPUT.replaceAll("(?s)<md:Extensions>.*?</md:Extensions>", "");
        assertFalse(MetadataFullUiComparison.matches(MetadataFullUiComparison.input(bytes(INPUT)),
                MetadataFullUiComparison.output(bytes(ignored))));
    }
    @Test void LossOfLanguageOrLogoDimensionsDoesNotPass() throws Exception {
        var input = MetadataFullUiComparison.input(bytes(INPUT));
        assertFalse(MetadataFullUiComparison.matches(input, MetadataFullUiComparison.output(bytes(
                INPUT.replace("<u:Description xml:lang=\"ja\">完全な説明</u:Description>", "")))));
        assertFalse(MetadataFullUiComparison.matches(input,
                MetadataFullUiComparison.output(bytes(INPUT.replace("width=\"180\"", "width=\"181\"")))));
    }
    @Test void IncorrectDiscoHintsPlacementAndReservedNamespaceUnknownAreRejected() {
        var hints = INPUT.substring(INPUT.indexOf("<u:DiscoHints>"), INPUT.indexOf("</u:DiscoHints>") + 15);
        assertThrows(IllegalArgumentException.class, () -> MetadataFullUiComparison.input(bytes(
                INPUT.replace(hints, "").replace("</u:UIInfo>", hints + "</u:UIInfo>"))));
        assertThrows(IllegalArgumentException.class, () -> MetadataFullUiComparison.input(bytes(
                INPUT.replace("<x:Probe>unknown</x:Probe>", "<u:Unknown>unknown</u:Unknown>"))));
    }
    @Test void ForeignEntityAndOneHintFamilyCannotSatisfyCompleteInput() throws Exception {
        var input = MetadataFullUiComparison.input(bytes(INPUT));
        assertFalse(MetadataFullUiComparison.matches(input,
                MetadataFullUiComparison.output(bytes(INPUT.replace("https://suite.example/sp", "https://another.example/sp")))));
        assertThrows(IllegalArgumentException.class, () -> MetadataFullUiComparison.input(bytes(
                INPUT.replace("<u:IPHint>2001:db8::/32</u:IPHint>", ""))));
    }
}
