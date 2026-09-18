package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.TypeKind;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.model.RecordAccessorMethodTaintModel;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RecordEnumSemanticsTest {
    private static final String PACKAGE = "fixtures.recordenum";
    private static final String CONTROLLER = PACKAGE + ".RecordEnumController";
    private static final String SERVICE = PACKAGE + ".RecordEnumService";
    private static final String DUPLICATE = PACKAGE + ".duplicate.DuplicateRecord";

    private static List<JavaFileInfo> files;
    private static ProjectClassIndex index;
    private static CrossClassInterproceduralResult result;

    @BeforeAll
    static void analyze() throws Exception {
        List<JavaFileInfo> extracted = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : List.of(
                    "fixtures/recordenum/RecordEnumFixture.java",
                    "fixtures/recordenum/duplicate/one/DuplicateRecord.java",
                    "fixtures/recordenum/duplicate/two/DuplicateRecord.java")) {
                try (ParsedJavaFile parsed = parser.parse(fixturePath(resource))) {
                    assertFalse(parsed.hasSyntaxErrors(), resource);
                    extracted.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
        }
        files = List.copyOf(extracted);
        index = new ProjectClassIndex(files);
        result = new CrossClassInterproceduralAnalysis()
                .analyze(files, RuleRegistry.javaSpringBackendDefaults());
    }

    @Test
    void extractsTopLevelRecordsEnumsClassesAndInterfacesWithExactFqns() {
        assertEquals(TypeKind.RECORD, type(PACKAGE + ".User").kind());
        assertEquals(TypeKind.ENUM, type(PACKAGE + ".Status").kind());
        assertEquals(TypeKind.CLASS, type(PACKAGE + ".PlainType").kind());
        assertEquals(TypeKind.INTERFACE, type(PACKAGE + ".PlainContract").kind());
    }

    @Test
    void preservesRecordComponentsTypesAndLocations() {
        ClassInfo user = type(PACKAGE + ".User");
        assertEquals(List.of("name", "id"),
                user.recordComponents().stream().map(component -> component.name()).toList());
        assertEquals(List.of("String", "Long"),
                user.recordComponents().stream().map(component -> component.declaredType()).toList());
        assertTrue(user.recordComponents().stream()
                .allMatch(component -> component.location().startLine() > 0));
    }

    @Test
    void exactZeroArgumentRecordAccessorProvidesDeclaredReturnType() {
        CallSiteContext name = call("access", "name");
        assertEquals("java.lang.String",
                name.recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals(SameClassCallStatus.MODELED, resolution("access", "name").status());
    }

    @Test
    void chainedRecordAccessorsUseIntermediateDeclaredReturnType() {
        CallSiteContext accessToken = call("chain", "accessToken");
        CallSiteContext token = call("chain", "token");
        assertEquals(PACKAGE + ".AccessToken",
                accessToken.recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals(PACKAGE + ".AccessToken", token.receiverQualifiedType().orElseThrow());
        assertEquals("java.lang.String",
                token.recordAccessor().orElseThrow().qualifiedReturnType());
        assertResolved("chain", "acceptToken", SERVICE, "acceptToken");
    }

    @Test
    void wrongNameAndNonZeroArityDoNotUseRecordAccessorSemantics() {
        assertTrue(call("wrongName", "unknown").recordAccessor().isEmpty());
        assertTrue(call("wrongArity", "name").recordAccessor().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                resolution("wrongName", "unknown").unsupported().orElseThrow().reason());
        assertEquals(UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                resolution("wrongArity", "name").unsupported().orElseThrow().reason());
    }

    @Test
    void typeNameReceiverIsNotModeledAsARecordAccessor() {
        CallSiteContext accessor = call("invalidTypeReceiver", "name");
        assertFalse(accessor.receiverBoundToValue());
        assertTrue(accessor.recordAccessor().isEmpty());
        assertTrue(new RecordAccessorMethodTaintModel().match(accessor).isEmpty());
        assertEquals(SameClassCallStatus.UNSUPPORTED,
                resolution("invalidTypeReceiver", "name").status());
        assertEquals(UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                resolution("invalidTypeReceiver", "name").unsupported().orElseThrow().reason());
    }

    @Test
    void unresolvedSameNamePatternVariableIsNotTreatedAsAProvenValueReceiver() {
        CallSiteContext accessor = call("unresolvedPattern", "name");
        assertFalse(accessor.receiverBoundToValue());
        assertTrue(accessor.recordAccessor().isEmpty());
        assertTrue(new RecordAccessorMethodTaintModel().match(accessor).isEmpty());
        assertEquals(UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                resolution("unresolvedPattern", "name").unsupported().orElseThrow().reason());
    }

    @Test
    void ordinaryClassZeroArgumentMethodUsesNormalResolution() {
        CallSiteContext label = call("arbitraryClass", "label");
        assertTrue(label.receiverBoundToValue());
        assertTrue(label.recordAccessor().isEmpty());
        assertResolved("arbitraryClass", "label", PACKAGE + ".PlainType", "label");
    }

    @Test
    void explicitAccessorBodyWinsOverSyntheticComponentSemantics() {
        CallSiteContext accessor = call("explicit", "value");
        assertTrue(accessor.recordAccessor().isEmpty());
        assertResolved("explicit", "value", PACKAGE + ".Value", "value");
        MethodCallExpression call = accessor.call();
        assertEquals(TaintState.CLEAN,
                analysis("explicit").taintResult().taintOf(call).state());
    }

    @Test
    void duplicateRecordFqnDoesNotSelectAccessorOrProjectType() {
        assertEquals(2, index.candidates(DUPLICATE).size());
        assertTrue(call("duplicate", "name").recordAccessor().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                resolution("duplicate", "name").unsupported().orElseThrow().reason());
    }

    @Test
    void enumConstantHasExactEnumTypeAndBaseMethodResolution() {
        CallSiteContext enabled = call("enumBase", "enabled");
        assertEquals(PACKAGE + ".Status", enabled.receiverQualifiedType().orElseThrow());
        assertEquals("ACTIVE",
                enabled.enumConstantReceiver().orElseThrow().constant().name());
        assertTrue(enabled.receiver().orElseThrow() instanceof FieldAccessExpression);
        assertResolved("enumBase", "enabled", PACKAGE + ".Status", "enabled");
    }

    @Test
    void enumConstantSpecificBodyRemainsDynamicAndUnsupported() {
        CallSiteContext enabled = call("enumDynamic", "enabled");
        assertTrue(enabled.enumConstantReceiver().orElseThrow()
                .constant().constantSpecificClassBody());
        assertEquals(UnsupportedInterproceduralReason.DYNAMIC_RECEIVER,
                resolution("enumDynamic", "enabled").unsupported().orElseThrow().reason());
    }

    @Test
    void exactRecordAccessorPropagatesRequestBodyTaintAcrossProjectCall() {
        CallSiteContext username = call("login", "username");
        assertEquals(TaintState.TAINTED,
                analysis("login").taintResult().taintOf(username.call()).state());
        assertTrue(result.findings().stream()
                .anyMatch(finding -> finding.cwe().equals("CWE-89")
                        && finding.sink().methodName().equals("executeQuery")));
    }

    private static ClassInfo type(String fqn) {
        return index.uniqueClass(fqn).orElseThrow().type();
    }

    private static RuleAwareTaintResult analysis(String methodName) {
        return result.methodAnalyses().entrySet().stream()
                .filter(entry -> entry.getKey().ownerQualifiedName().equals(CONTROLLER))
                .filter(entry -> entry.getKey().method().name().equals(methodName))
                .map(java.util.Map.Entry::getValue)
                .findFirst().orElseThrow();
    }

    private static CallSiteContext call(String callerMethod, String calledMethod) {
        ProjectClassEntry owner = index.uniqueClass(CONTROLLER).orElseThrow();
        MethodInfo method = owner.type().methods().stream()
                .filter(candidate -> candidate.name().equals(callerMethod))
                .findFirst().orElseThrow();
        CallSiteContextResolver calls = new CallSiteContextResolver(
                owner.file(), owner.type(), method,
                analysis(callerMethod).taintResult().dataFlow(), index);
        return calls.callSites().stream()
                .filter(context -> context.methodName().equals(calledMethod))
                .findFirst().orElseThrow();
    }

    private static ProjectCallResolution resolution(String callerMethod, String calledMethod) {
        return result.callResolutions().stream()
                .filter(item -> item.caller().ownerQualifiedName().equals(CONTROLLER))
                .filter(item -> item.caller().method().name().equals(callerMethod))
                .filter(item -> item.call().call().methodName().equals(calledMethod))
                .findFirst().orElseThrow();
    }

    private static void assertResolved(
            String callerMethod, String calledMethod, String owner, String targetMethod) {
        ProjectCallResolution resolution = resolution(callerMethod, calledMethod);
        assertEquals(SameClassCallStatus.RESOLVED, resolution.status());
        assertEquals(owner, resolution.target().orElseThrow().ownerQualifiedName());
        assertEquals(targetMethod, resolution.target().orElseThrow().method().name());
    }

    private static Path fixturePath(String resource) throws URISyntaxException {
        var value = RecordEnumSemanticsTest.class.getClassLoader().getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 23 fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
