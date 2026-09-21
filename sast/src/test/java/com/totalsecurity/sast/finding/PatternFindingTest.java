package com.totalsecurity.sast.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.SourceLocation;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class PatternFindingTest {
    private static final SourceLocation LOCATION =
            new SourceLocation(Path.of("Example.java"), 1, 1, 1, 10);

    @Test
    void existingCweBearingConstructorPreservesCweMetadata() {
        PatternFinding finding = cweFinding("CWE-798");

        assertEquals("CWE-798", finding.cwe());
        assertEquals(Optional.of("CWE-798"), finding.cweReference());
    }

    @Test
    void existingCweBearingConstructorRejectsBlankCwe() {
        assertThrows(IllegalArgumentException.class, () -> cweFinding(""));
        assertThrows(IllegalArgumentException.class, () -> cweFinding("  "));
    }

    @Test
    void explicitCweReferenceRejectsBlankPresentValue() {
        assertThrows(IllegalArgumentException.class, () -> checklistFinding(Optional.of(" ")));
    }

    @Test
    void checklistFindingRepresentsAbsentCweExplicitly() {
        PatternFinding finding = checklistFinding(Optional.empty());

        assertTrue(finding.cweReference().isEmpty());
        assertEquals("", finding.cwe());
    }

    private static PatternFinding cweFinding(String cwe) {
        return new PatternFinding(
                "HARDCODED_CREDENTIAL",
                "Hardcoded Credential",
                cwe,
                FindingSeverity.HIGH,
                LOCATION,
                "password",
                PatternOccurrenceKind.FIELD_DECLARATION,
                "string_literal",
                "value redacted");
    }

    private static PatternFinding checklistFinding(Optional<String> cwe) {
        return new PatternFinding(
                "AUTHN_06_HARDCODED_SIGNING_MATERIAL",
                "Hardcoded Signing Key Material",
                cwe,
                FindingSeverity.HIGH,
                LOCATION,
                "jwtSecret",
                PatternOccurrenceKind.FIELD_DECLARATION,
                "string_literal",
                "AUTHN-06 value redacted");
    }
}
