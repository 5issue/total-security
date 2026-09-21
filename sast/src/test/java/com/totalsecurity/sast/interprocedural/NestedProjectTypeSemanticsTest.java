package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.TypeKind;
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

class NestedProjectTypeSemanticsTest {
    private static final String PACKAGE = "fixtures.nestedtypes";
    private static final String CONTROLLER = PACKAGE + ".NestedController";
    private static final String CART = PACKAGE + ".CartResponseDto";
    private static final String ADDRESS = CART + ".Address";
    private static final String STORAGE = PACKAGE + ".ProductSpec.StorageType";
    private static final String IMPORT_COLLISION_OUTER = PACKAGE + ".ImportCollisionOuter";
    private static final String IMPORT_COLLISION_ADDRESS = IMPORT_COLLISION_OUTER + ".Address";
    private static final String JAVA_LANG_COLLISION_OUTER = PACKAGE + ".JavaLangCollisionOuter";
    private static final String JAVA_LANG_COLLISION_STRING = JAVA_LANG_COLLISION_OUTER + ".String";
    private static final String IMPORTED =
            PACKAGE + ".imported.ImportedNestedCaller";
    private static final String QUALIFIED =
            PACKAGE + ".qualified.QualifiedNestedCaller";
    private static final String DUPLICATE_OUTER =
            PACKAGE + ".duplicate.DuplicateOuter";
    private static final String DUPLICATE_ADDRESS = DUPLICATE_OUTER + ".Address";
    private static final String DUPLICATE_CALLER =
            PACKAGE + ".duplicate.DuplicateNestedCaller";

    private static List<JavaFileInfo> files;
    private static ProjectClassIndex index;
    private static CrossClassInterproceduralResult result;

    @BeforeAll
    static void analyze() throws Exception {
        List<JavaFileInfo> extracted = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : List.of(
                    "fixtures/nestedtypes/NestedTypeFixture.java",
                    "fixtures/nestedtypes/shadow/Address.java",
                    "fixtures/nestedtypes/imported/ImportedNestedTypeFixture.java",
                    "fixtures/nestedtypes/qualified/QualifiedNestedTypeFixture.java",
                    "fixtures/nestedtypes/duplicate/one/DuplicateOuter.java",
                    "fixtures/nestedtypes/duplicate/two/DuplicateOuter.java")) {
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
    void indexesDirectMemberRecordWithExactSourceCanonicalName() {
        ClassInfo address = type(ADDRESS);
        assertEquals(TypeKind.RECORD, address.kind());
        assertEquals("Address", address.name());
        assertEquals(List.of("CartResponseDto"), address.enclosingTypeNames());
        assertEquals("CartResponseDto.Address", address.sourceName());
        assertTrue(index.uniqueClass(PACKAGE + ".DeepOuter.Middle.Hidden").isEmpty());
    }

    @Test
    void nestedRecordPreservesComponentsAndModelsExactAccessor() {
        ClassInfo address = type(ADDRESS);
        assertEquals(List.of("addressId", "address"), address.recordComponents().stream()
                .map(component -> component.name()).toList());
        assertEquals(List.of("Long", "String"), address.recordComponents().stream()
                .map(component -> component.declaredType()).toList());
        CallSiteContext accessor = call(CONTROLLER, "recordAccessor", "addressId");
        assertEquals("java.lang.Long",
                accessor.recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals(SameClassCallStatus.MODELED,
                resolution(CONTROLLER, "recordAccessor", "addressId").status());
    }

    @Test
    void sameEnclosingSimpleNameResolvesNestedRecord() {
        CallSiteContext accessor = call(CART, "sameEnclosing", "addressId");
        assertEquals(ADDRESS, accessor.receiverQualifiedType().orElseThrow());
        assertTrue(accessor.recordAccessor().isPresent());
    }

    @Test
    void exactEnclosingMemberShadowsConflictingExplicitImport() {
        CallSiteContext accessor = call(IMPORT_COLLISION_OUTER, "flow", "id");
        assertEquals(IMPORT_COLLISION_ADDRESS, accessor.receiverQualifiedType().orElseThrow());
        assertEquals("java.lang.Long",
                accessor.recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals(SameClassCallStatus.MODELED,
                resolution(IMPORT_COLLISION_OUTER, "flow", "id").status());
    }

    @Test
    void exactEnclosingMemberShadowsImplicitJavaLangType() {
        CallSiteContext accessor = call(JAVA_LANG_COLLISION_OUTER, "flow", "id");
        assertEquals(JAVA_LANG_COLLISION_STRING, accessor.receiverQualifiedType().orElseThrow());
        assertEquals("java.lang.Long",
                accessor.recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals(SameClassCallStatus.MODELED,
                resolution(JAVA_LANG_COLLISION_OUTER, "flow", "id").status());
    }

    @Test
    void nestedEnumConstantKeepsExactEnumIdentityAndNormalDeclaredMethodResolution() {
        ClassInfo storage = type(STORAGE);
        assertEquals(TypeKind.ENUM, storage.kind());
        assertEquals(List.of("ROOM", "COLD"), storage.enumConstants().stream()
                .map(constant -> constant.name()).toList());
        CallSiteContext enabled = call(CONTROLLER, "enumConstant", "enabled");
        assertEquals(STORAGE, enabled.receiverQualifiedType().orElseThrow());
        assertEquals("ROOM", enabled.enumConstantReceiver().orElseThrow().constant().name());
        assertResolved(CONTROLLER, "enumConstant", "enabled", STORAGE);
    }

    @Test
    void sameSimpleNestedNamesRemainSeparateExactTypes() {
        assertEquals(2, index.classesNamed("Result").size());
        assertEquals("java.lang.String",
                call(CONTROLLER, "sameSimple", "value", 0)
                        .recordAccessor().orElseThrow().qualifiedReturnType());
        assertEquals("java.lang.Long",
                call(CONTROLLER, "sameSimple", "value", 1)
                        .recordAccessor().orElseThrow().qualifiedReturnType());
    }

    @Test
    void explicitImportAndFullyQualifiedNestedTypesResolveExactly() {
        assertEquals(ADDRESS,
                call(IMPORTED, "call", "addressId").receiverQualifiedType().orElseThrow());
        assertEquals(ADDRESS,
                call(QUALIFIED, "call", "addressId").receiverQualifiedType().orElseThrow());
        assertTrue(call(IMPORTED, "call", "addressId").recordAccessor().isPresent());
        assertTrue(call(QUALIFIED, "call", "addressId").recordAccessor().isPresent());
    }

    @Test
    void duplicateOuterMakesNestedDeclarationAmbiguousEvenWithOneOccurrence() {
        assertEquals(2, index.candidates(DUPLICATE_OUTER).size());
        assertEquals(1, index.candidates(DUPLICATE_ADDRESS).size());
        assertTrue(index.isAmbiguous(DUPLICATE_ADDRESS));
        assertTrue(index.uniqueClass(DUPLICATE_ADDRESS).isEmpty());
        assertTrue(call(DUPLICATE_CALLER, "call", "id").recordAccessor().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                resolution(DUPLICATE_CALLER, "call", "id")
                        .unsupported().orElseThrow().reason());
    }

    @Test
    void nestedTypeNameReceiverIsNotModeledAsAnInstanceAccessor() {
        CallSiteContext accessor = call(CONTROLLER, "typeReceiver", "addressId");
        assertTrue(accessor.recordAccessor().isEmpty());
        assertTrue(new RecordAccessorMethodTaintModel().match(accessor).isEmpty());
        assertEquals(SameClassCallStatus.UNSUPPORTED,
                resolution(CONTROLLER, "typeReceiver", "addressId").status());
    }

    @Test
    void explicitNestedRecordAccessorBodyWins() {
        CallSiteContext accessor = call(CONTROLLER, "explicit", "value");
        assertTrue(accessor.recordAccessor().isEmpty());
        assertResolved(CONTROLLER, "explicit", "value", PACKAGE + ".ExplicitOuter.Address");
        assertEquals(TaintState.CLEAN,
                analysis(CONTROLLER, "explicit").taintResult().taintOf(accessor.call()).state());
    }

    @Test
    void nestedRecordAccessorReusesExistingReceiverTaintSemantics() {
        CallSiteContext accessor = call(CONTROLLER, "tainted", "address");
        assertTrue(new RecordAccessorMethodTaintModel().match(accessor).isPresent());
        assertEquals(TaintState.TAINTED,
                analysis(CONTROLLER, "tainted").taintResult().taintOf(accessor.call()).state());
        assertTrue(result.findings().stream().anyMatch(finding -> finding.cwe().equals("CWE-89")
                && finding.sink().methodName().equals("executeQuery")));
    }

    @Test
    void nestedEnumCompilerMethodsRemainUnsupportedAndUnmodeled() {
        CallSiteContext values = call(CONTROLLER, "enumCompilerMethods", "values");
        CallSiteContext name = call(CONTROLLER, "enumCompilerMethods", "name");
        assertTrue(values.recordAccessor().isEmpty());
        assertTrue(name.recordAccessor().isEmpty());
        assertEquals(SameClassCallStatus.UNSUPPORTED,
                resolution(CONTROLLER, "enumCompilerMethods", "values").status());
        assertEquals(UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                resolution(CONTROLLER, "enumCompilerMethods", "name")
                        .unsupported().orElseThrow().reason());
    }

    private static ClassInfo type(String fqn) {
        return index.uniqueClass(fqn).orElseThrow().type();
    }

    private static RuleAwareTaintResult analysis(String ownerName, String methodName) {
        return result.methodAnalyses().entrySet().stream()
                .filter(entry -> entry.getKey().ownerQualifiedName().equals(ownerName))
                .filter(entry -> entry.getKey().method().name().equals(methodName))
                .map(java.util.Map.Entry::getValue)
                .findFirst().orElseThrow();
    }

    private static CallSiteContext call(
            String ownerName, String callerMethod, String calledMethod) {
        return call(ownerName, callerMethod, calledMethod, 0);
    }

    private static CallSiteContext call(
            String ownerName, String callerMethod, String calledMethod, int occurrence) {
        ProjectClassEntry owner = index.uniqueClass(ownerName).orElseThrow();
        MethodInfo method = owner.type().methods().stream()
                .filter(candidate -> candidate.name().equals(callerMethod))
                .findFirst().orElseThrow();
        CallSiteContextResolver calls = new CallSiteContextResolver(
                owner.file(), owner.type(), method,
                analysis(ownerName, callerMethod).taintResult().dataFlow(), index);
        return calls.callSites().stream()
                .filter(context -> context.methodName().equals(calledMethod))
                .skip(occurrence)
                .findFirst().orElseThrow();
    }

    private static ProjectCallResolution resolution(
            String ownerName, String callerMethod, String calledMethod) {
        return result.callResolutions().stream()
                .filter(item -> item.caller().ownerQualifiedName().equals(ownerName))
                .filter(item -> item.caller().method().name().equals(callerMethod))
                .filter(item -> item.call().call().methodName().equals(calledMethod))
                .findFirst().orElseThrow();
    }

    private static void assertResolved(
            String callerOwner, String callerMethod, String calledMethod, String targetOwner) {
        ProjectCallResolution resolution = resolution(callerOwner, callerMethod, calledMethod);
        assertEquals(SameClassCallStatus.RESOLVED, resolution.status());
        assertEquals(targetOwner, resolution.target().orElseThrow().ownerQualifiedName());
    }

    private static Path fixturePath(String resource) throws URISyntaxException {
        var value = NestedProjectTypeSemanticsTest.class.getClassLoader().getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 27 fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
