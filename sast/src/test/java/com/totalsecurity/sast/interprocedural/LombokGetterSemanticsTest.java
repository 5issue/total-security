package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LombokGetterNamingContext;
import com.totalsecurity.sast.runner.LombokConfigurationDiscovery;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.model.LombokGetterMethodTaintModel;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class LombokGetterSemanticsTest {
    private static final String PACKAGE = "fixtures.lombokgetter";
    private static final String CONTROLLER = PACKAGE + ".LombokController";
    private static final String WRONG_CALLER = PACKAGE + ".wrong.WrongCaller";
    private static final String DUPLICATE = PACKAGE + ".duplicate.DuplicateOwner";
    private static final String CONFIG_FLUENT = PACKAGE + ".config.fluent.ConfigFluentCaller";
    private static final String CONFIG_PREFIX = PACKAGE + ".config.prefix.ConfigPrefixCaller";
    private static final String CONFIG_NO_IS = PACKAGE + ".config.noisprefix.ConfigBooleanCaller";
    private static final String CONFIG_IMPORT_RELATIVE =
            PACKAGE + ".config.importrelative.ImportRelativeController";
    private static final String CONFIG_IMPORT_DEFAULT =
            PACKAGE + ".config.importdefault.ImportDefaultCaller";
    private static final String CONFIG_IMPORT_ARCHIVE =
            PACKAGE + ".config.importarchive.ImportArchiveCaller";
    private static final String CONFIG_IMPORT_TEXT =
            PACKAGE + ".config.importtext.ImportTextCaller";

    private static ProjectClassIndex index;
    private static CrossClassInterproceduralResult result;
    private static LombokGetterNamingContext lombokNaming;

    @BeforeAll
    static void analyze() throws Exception {
        List<JavaFileInfo> files = new ArrayList<>();
        List<Path> sourcePaths = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : List.of(
                    "fixtures/lombokgetter/LombokGetterFixture.java",
                    "fixtures/lombokgetter/wrong/WrongGetter.java",
                    "fixtures/lombokgetter/duplicate/one/DuplicateOwner.java",
                    "fixtures/lombokgetter/duplicate/two/DuplicateOwner.java",
                    "fixtures/lombokgetter/config/fluent/ConfigFluentFixture.java",
                    "fixtures/lombokgetter/config/prefix/ConfigPrefixFixture.java",
                    "fixtures/lombokgetter/config/noisprefix/ConfigNoIsPrefixFixture.java",
                    "fixtures/lombokgetter/config/importrelative/ImportRelativeFixture.java",
                    "fixtures/lombokgetter/config/importdefault/ImportDefaultFixture.java",
                    "fixtures/lombokgetter/config/importarchive/ImportArchiveFixture.java",
                    "fixtures/lombokgetter/config/importtext/ImportTextFixture.java")) {
                Path source = fixturePath(resource);
                sourcePaths.add(source);
                try (ParsedJavaFile parsed = parser.parse(source)) {
                    assertFalse(parsed.hasSyntaxErrors(), resource);
                    files.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
        }
        lombokNaming = new LombokConfigurationDiscovery().inspect(sourcePaths);
        index = new ProjectClassIndex(files);
        result = new CrossClassInterproceduralAnalysis()
                .analyze(files, RuleRegistry.javaSpringBackendDefaults(), lombokNaming);
    }

    @Test
    void classLevelGetterUsesExactFieldTypeAndModeledResolution() {
        CallSiteContext getter = call(CONTROLLER, "classLevel", "getName");
        assertEquals("java.lang.String", getter.lombokGetter().orElseThrow().qualifiedReturnType());
        assertEquals("name", getter.lombokGetter().orElseThrow().field().name());
        assertEquals(SameClassCallStatus.MODELED,
                resolution(CONTROLLER, "classLevel", "getName").status());
    }

    @Test
    void fieldLevelGetterUsesExactFieldType() {
        assertEquals("java.lang.Long",
                call(CONTROLLER, "fieldLevel", "getId")
                        .lombokGetter().orElseThrow().qualifiedReturnType());
    }

    @Test
    void primitiveBooleanUsesIsPrefixAndExistingIsPrefix() {
        assertEquals("active", call(CONTROLLER, "primitiveBoolean", "isActive")
                .lombokGetter().orElseThrow().field().name());
        assertEquals("isReady", call(CONTROLLER, "primitiveBoolean", "isReady")
                .lombokGetter().orElseThrow().field().name());
    }

    @Test
    void wrapperBooleanUsesGetPrefixOnly() {
        assertEquals("java.lang.Boolean", call(CONTROLLER, "wrapperBoolean", "getEnabled")
                .lombokGetter().orElseThrow().qualifiedReturnType());
        assertTrue(call(CONTROLLER, "wrapperBoolean", "isEnabled").lombokGetter().isEmpty());
    }

    @Test
    void noAnnotationAndWrongPackageAnnotationAreNotLombokEvidence() {
        assertTrue(call(CONTROLLER, "noAnnotation", "getName").lombokGetter().isEmpty());
        assertTrue(call(WRONG_CALLER, "call", "getName").lombokGetter().isEmpty());
    }

    @Test
    void explicitMethodBodyWinsOverSyntheticSemantics() {
        CallSiteContext getter = call(CONTROLLER, "explicit", "getName");
        assertTrue(getter.lombokGetter().isEmpty());
        assertResolved(CONTROLLER, "explicit", "getName", PACKAGE + ".ExplicitUser");
        assertEquals(TaintState.CLEAN,
                analysis(CONTROLLER, "explicit").taintResult().taintOf(getter.call()).state());
    }

    @Test
    void typeNameReceiverIsNotAnInstanceGetter() {
        CallSiteContext getter = call(CONTROLLER, "typeReceiver", "getName");
        assertFalse(getter.receiverBoundToValue());
        assertTrue(getter.lombokGetter().isEmpty());
        assertTrue(new LombokGetterMethodTaintModel().match(getter).isEmpty());
    }

    @Test
    void unresolvedSameNamePatternVariableIsNotAssumedToBeAValue() {
        CallSiteContext getter = call(CONTROLLER, "unresolvedPattern", "getName");
        assertFalse(getter.receiverBoundToValue());
        assertTrue(getter.lombokGetter().isEmpty());
    }

    @Test
    void chainedGetterReturnTypeBecomesNextReceiverType() {
        CallSiteContext getter = call(CONTROLLER, "chained", "getStatus");
        CallSiteContext name = call(CONTROLLER, "chained", "name");
        assertEquals(PACKAGE + ".OrderStatus",
                getter.lombokGetter().orElseThrow().qualifiedReturnType());
        assertEquals(PACKAGE + ".OrderStatus", name.receiverQualifiedType().orElseThrow());
    }

    @Test
    void duplicateOwnerNeverSelectsOneSyntheticGetter() {
        assertEquals(2, index.candidates(DUPLICATE).size());
        assertTrue(call(CONTROLLER, "duplicate", "getName").lombokGetter().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                resolution(CONTROLLER, "duplicate", "getName")
                        .unsupported().orElseThrow().reason());
    }

    @Test
    void unsupportedGetterOptionsDoNotCreateSyntheticMethods() {
        assertTrue(call(CONTROLLER, "disabledClass", "getValue").lombokGetter().isEmpty());
        assertTrue(call(CONTROLLER, "disabledField", "getHidden").lombokGetter().isEmpty());
    }

    @Test
    void arbitraryBeanGetterIsNormalResolutionNotLombok() {
        CallSiteContext getter = call(CONTROLLER, "ordinary", "getValue");
        assertTrue(getter.lombokGetter().isEmpty());
        assertResolved(CONTROLLER, "ordinary", "getValue", PACKAGE + ".OrdinaryBean");
    }

    @Test
    void staticFieldIsNotModeledAsAnInstanceGetter() {
        VariableInfo token = index.uniqueClass(PACKAGE + ".StaticUser").orElseThrow()
                .type().fields().getFirst();
        assertTrue(token.staticMember());
        assertTrue(call(CONTROLLER, "staticField", "getToken").lombokGetter().isEmpty());
    }

    @Test
    void exactTypeAndFieldAccessorsDisableDefaultGetterGuessing() {
        assertTrue(call(CONTROLLER, "fluentAccessors", "getName").lombokGetter().isEmpty());
        assertTrue(call(CONTROLLER, "prefixedAccessors", "get_name").lombokGetter().isEmpty());
    }

    @Test
    void wrongAccessorsPackageDoesNotDisableDefaultLombokGetter() {
        assertTrue(call(CONTROLLER, "wrongAccessorsPackage", "getValue")
                .lombokGetter().isPresent());
    }

    @Test
    void relevantProjectConfigurationDisablesDefaultGetterGuessing() {
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.fluent.ConfigFluentUser")
                        .orElseThrow().file()));
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.prefix.ConfigPrefixUser")
                        .orElseThrow().file()));
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.noisprefix.ConfigBooleanUser")
                        .orElseThrow().file()));
        assertTrue(call(CONFIG_FLUENT, "call", "getName").lombokGetter().isEmpty());
        assertTrue(call(CONFIG_PREFIX, "call", "get_name").lombokGetter().isEmpty());
        assertTrue(call(CONFIG_NO_IS, "call", "isActive").lombokGetter().isEmpty());
    }

    @Test
    void noRelevantConfigurationKeepsDefaultNamingEnabled() {
        assertTrue(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".User").orElseThrow().file()));
        assertTrue(call(CONTROLLER, "classLevel", "getName").lombokGetter().isPresent());
    }

    @Test
    void relativeImportDisablesDefaultGetterWithoutFollowingImportedContent() {
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.importrelative.ImportRelativeUser")
                        .orElseThrow().file()));
        CallSiteContext getter = call(CONFIG_IMPORT_RELATIVE, "tainted", "getName");
        assertTrue(getter.lombokGetter().isEmpty());
        assertTrue(new LombokGetterMethodTaintModel().match(getter).isEmpty());
        assertFalse(result.findings().stream()
                .anyMatch(finding -> finding.primaryLocation().file()
                        .equals(index.uniqueClass(CONFIG_IMPORT_RELATIVE).orElseThrow()
                                .file().location().file())));
    }

    @Test
    void importRemainsUnsafeEvenWhenImportedFileHasNoRelevantNamingKey() {
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.importdefault.ImportDefaultUser")
                        .orElseThrow().file()));
        assertTrue(call(CONFIG_IMPORT_DEFAULT, "call", "getName").lombokGetter().isEmpty());
    }

    @Test
    void archiveImportSyntaxDisablesDefaultGetterWithoutReadingTarget() {
        assertFalse(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.importarchive.ImportArchiveUser")
                        .orElseThrow().file()));
        assertTrue(call(CONFIG_IMPORT_ARCHIVE, "call", "getName").lombokGetter().isEmpty());
    }

    @Test
    void commentedImportAndImportTextInsideOrdinaryValueRemainDefaultSafe() {
        assertTrue(lombokNaming.defaultNamingSafe(
                index.uniqueClass(PACKAGE + ".config.importtext.ImportTextUser")
                        .orElseThrow().file()));
        assertTrue(call(CONFIG_IMPORT_TEXT, "call", "getName").lombokGetter().isPresent());
    }

    @Test
    void differentlyCasedExplicitMethodSuppressesSyntheticGetter() {
        CallSiteContext getter = call(CONTROLLER, "caseInsensitiveSuppression", "getName");
        assertTrue(getter.lombokGetter().isEmpty());
        assertTrue(new LombokGetterMethodTaintModel().match(getter).isEmpty());
    }

    @Test
    void resolvedLocalFieldAndRecordChainRemainValidValueReceivers() {
        assertTrue(call(CONTROLLER, "local", "getName").lombokGetter().isPresent());
        assertTrue(call(CONTROLLER, "field", "getName").lombokGetter().isPresent());
        assertTrue(call(CONTROLLER, "mixedChain", "user").recordAccessor().isPresent());
        assertTrue(call(CONTROLLER, "mixedChain", "getName").lombokGetter().isPresent());
    }

    @Test
    void backendLikeCategoryGetterResolvesExactLongField() {
        assertEquals("java.lang.Long",
                call(CONTROLLER, "backendCategoryShape", "getId")
                        .lombokGetter().orElseThrow().qualifiedReturnType());
    }

    @Test
    void exactFqnAnnotationAndSupportedFieldShapesPreserveDeclaredTypes() {
        assertEquals("java.lang.String", call(CONTROLLER, "fullyQualifiedAnnotation", "getValue")
                .lombokGetter().orElseThrow().qualifiedReturnType());
        assertEquals("int", call(CONTROLLER, "supportedFieldShapes", "getCount")
                .lombokGetter().orElseThrow().qualifiedReturnType());
        assertEquals("java.lang.String[]", call(CONTROLLER, "supportedFieldShapes", "getTags")
                .lombokGetter().orElseThrow().qualifiedReturnType());
        assertEquals("java.util.List", call(CONTROLLER, "supportedFieldShapes", "getAliases")
                .lombokGetter().orElseThrow().qualifiedReturnType());
    }

    @Test
    void exactGetterUsesLimitedWholeReceiverMayTaintOnly() {
        CallSiteContext getter = call(CONTROLLER, "tainted", "getName");
        assertTrue(new LombokGetterMethodTaintModel().match(getter).isPresent());
        assertEquals(TaintState.TAINTED,
                analysis(CONTROLLER, "tainted").taintResult().taintOf(getter.call()).state());
        assertTrue(result.findings().stream()
                .anyMatch(finding -> finding.cwe().equals("CWE-89")
                        && finding.sink().methodName().equals("executeQuery")));
    }

    private static RuleAwareTaintResult analysis(String ownerName, String methodName) {
        return result.methodAnalyses().entrySet().stream()
                .filter(entry -> entry.getKey().ownerQualifiedName().equals(ownerName))
                .filter(entry -> entry.getKey().method().name().equals(methodName))
                .map(java.util.Map.Entry::getValue)
                .findFirst().orElseThrow();
    }

    private static CallSiteContext call(String ownerName, String callerMethod, String calledMethod) {
        ProjectClassEntry owner = index.uniqueClass(ownerName).orElseThrow();
        MethodInfo method = owner.type().methods().stream()
                .filter(candidate -> candidate.name().equals(callerMethod))
                .findFirst().orElseThrow();
        CallSiteContextResolver calls = new CallSiteContextResolver(
                owner.file(), owner.type(), method,
                analysis(ownerName, callerMethod).taintResult().dataFlow(), index, lombokNaming);
        return calls.callSites().stream()
                .filter(context -> context.methodName().equals(calledMethod))
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
        var value = LombokGetterSemanticsTest.class.getClassLoader().getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 26A fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
