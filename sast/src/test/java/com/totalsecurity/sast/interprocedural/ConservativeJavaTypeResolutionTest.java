package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.TypeParameterInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ConservativeJavaTypeResolutionTest {
    private static final String CONTROLLER = "fixtures.types.controller.TypeController";
    private static final String SERVICE = "fixtures.types.service.TypeService";
    private static final String CHILD = "fixtures.types.model.ChildDto";
    private static final String WILDCARD_CALLER =
            "fixtures.types.wildcard.caller.WildcardCaller";
    private static final String DUPLICATE_CHILD =
            "fixtures.types.duplicatechild.ChildWithDuplicateParent";
    private static final String DUPLICATE_PARENT =
            "fixtures.types.duplicateparent.Parent";
    private static final String DUPLICATE_INTERMEDIATE_CHILD =
            "fixtures.types.intermediatechild.ChildThroughDuplicateMiddle";

    private static List<JavaFileInfo> files;
    private static ProjectClassIndex index;
    private static CrossClassInterproceduralResult result;

    @BeforeAll
    static void analyzeFixtures() throws Exception {
        List<JavaFileInfo> extracted = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : fixtureResources()) {
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
    void implicitJavaLangTypesWinBeforeUnprovenWildcardImports() {
        LightweightTypeContext types = types(CONTROLLER);
        assertEquals("java.lang.Long", types.qualifyType("Long").orElseThrow());
        assertEquals("java.lang.Integer", types.qualifyType("Integer").orElseThrow());
        assertEquals("java.lang.String", types.qualifyType("String").orElseThrow());
        assertEquals("java.lang.StringBuilder",
                types.qualifyType("StringBuilder").orElseThrow());
        assertResolved("find", "find");
        assertResolved("integer", "integer");
    }

    @Test
    void wildcardImportsRequireOneProvenProjectCandidate() {
        LightweightTypeContext types = types(WILDCARD_CALLER);
        assertTrue(types.qualifyType("MissingDto").isEmpty());
        assertTrue(types.qualifyType("AmbiguousDto").isEmpty());
    }

    @Test
    void objectParameterAcceptsKnownProjectReferenceType() {
        assertResolved("object", "object");
    }

    @Test
    void declaredGenericMethodVariableDoesNotBecomeInventedFqn() {
        assertResolved("generic", "generic");
        MethodInfo generic = method(SERVICE, "generic");
        assertEquals("T", generic.typeParameters().getFirst().name());
        assertTrue(generic.typeParameters().getFirst().upperBounds().isEmpty());
    }

    @Test
    void declaredGenericBoundIsHonoredWhenProjectTypeIsExact() {
        assertResolved("bounded", "bounded");
        assertUnsupported("boundedOther",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
        MethodInfo bounded = method(SERVICE, "bounded");
        assertEquals(List.of("BaseDto"), bounded.typeParameters().getFirst().upperBounds());
    }

    @Test
    void exactDeclaredExtendsAndImplementsEnableProjectSubtypeAssignability() {
        assertResolved("base", "base");
        assertResolved("marker", "marker");
        ClassInfo child = index.uniqueClass(CHILD).orElseThrow().type();
        assertEquals(List.of("BaseDto"), child.extendsTypes());
        assertEquals(List.of("Marker"), child.implementsTypes());
        assertTrue(index.isDeclaredSubtypeOf(CHILD, "fixtures.types.model.BaseDto"));
        assertTrue(index.isDeclaredSubtypeOf(CHILD, "fixtures.types.model.Marker"));
    }

    @Test
    void projectHierarchyTraversalStopsAtDeclaredCycles() {
        assertFalse(index.isDeclaredSubtypeOf(
                "fixtures.types.cycle.CycleOne", "fixtures.types.model.BaseDto"));
    }

    @Test
    void unrelatedProjectTypesRemainIncompatible() {
        assertUnsupported("unrelated",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
    }

    @Test
    void exactBoxingAndUnboxingPairsAreSupported() {
        assertResolved("boxing", "boxed");
        assertResolved("unboxing", "primitive");
    }

    @Test
    void safePrimitiveWideningIsSupportedButNarrowingIsRejected() {
        assertResolved("widening", "wide");
        assertUnsupported("narrowing",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
    }

    @Test
    void matchingGenericRawShapeRemainsResolvable() {
        assertResolved("sameErasure", "sameErasure");
    }

    @Test
    void multipleAssignableOverloadsRemainAmbiguous() {
        assertUnsupported("ambiguous", UnsupportedInterproceduralReason.AMBIGUOUS_OVERLOAD);
    }

    @Test
    void sameClassCompatibleCandidateDoesNotExcludeUnknownOverload() {
        assertUnsupported("sameCompatibleUnknown",
                UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE);
    }

    @Test
    void crossClassCompatibleCandidateDoesNotExcludeUnknownOverload() {
        assertUnsupported("crossCompatibleUnknown",
                UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE);
    }

    @Test
    void oneCompatibleCandidateResolvesWhenOtherCandidatesAreIncompatible() {
        assertResolved("compatibleOnly", "compatibleOnly");
    }

    @Test
    void genericArrayRejectsScalarButAcceptsMatchingArrayShape() {
        assertUnsupported("genericArrayScalar",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
        assertResolved("genericArray", "genericArray");
    }

    @Test
    void genericTypeVariableArrayRejectsPrimitiveComponents() {
        assertUnsupported("genericPrimitiveIntArray",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
        assertUnsupported("genericPrimitiveLongArray",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
    }

    @Test
    void genericTypeVariableArrayPreservesMultidimensionalShape() {
        assertUnsupported("genericPrimitiveTwoDimensionalArray",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
        assertResolved("genericReferenceTwoDimensionalArray", "genericTwoDimensionalArray");
    }

    @Test
    void genericVarargsDoesNotUseScalarTypeVariableCompatibility() {
        ConservativeTypeCompatibility compatibility = new ConservativeTypeCompatibility(index);
        MethodInfo method = genericMethodWithParameter("T...");
        assertEquals(
                ConservativeTypeCompatibility.Match.INCOMPATIBLE,
                compatibility.match("java.lang.String", method, 0, types(SERVICE)));
        assertEquals(
                ConservativeTypeCompatibility.Match.COMPATIBLE,
                compatibility.match("java.lang.String[]", method, 0, types(SERVICE)));
    }

    @Test
    void duplicateHierarchyTargetCannotProveAssignability() {
        assertEquals(2, index.candidates(DUPLICATE_PARENT).size());
        assertFalse(index.isDeclaredSubtypeOf(DUPLICATE_CHILD, DUPLICATE_PARENT));
    }

    @Test
    void duplicateHierarchyIntermediateStopsTraversal() {
        assertFalse(index.isDeclaredSubtypeOf(
                DUPLICATE_INTERMEDIATE_CHILD, "fixtures.types.model.BaseDto"));
    }

    @Test
    void sameClassMultipleCompatibleCandidatesTakePrecedenceOverUnknownCandidate() {
        assertUnsupported("sameMixedAmbiguous",
                UnsupportedInterproceduralReason.AMBIGUOUS_OVERLOAD);
    }

    @Test
    void crossClassMultipleCompatibleCandidatesTakePrecedenceOverUnknownCandidate() {
        assertUnsupported("crossMixedAmbiguous",
                UnsupportedInterproceduralReason.AMBIGUOUS_OVERLOAD);
    }

    @Test
    void exactCandidateStillTakesPrecedenceOverUnknownCandidate() {
        assertResolved("exactWithUnknown", "exactWithUnknown");
    }

    private static LightweightTypeContext types(String owner) {
        JavaFileInfo file = index.uniqueClass(owner).orElseThrow().file();
        return new LightweightTypeContext(file, index::contains);
    }

    private static void assertResolved(String callerMethod, String targetMethod) {
        ProjectCallResolution resolution = resolution(callerMethod);
        assertEquals(SERVICE, resolution.target().orElseThrow().ownerQualifiedName());
        assertEquals(targetMethod, resolution.target().orElseThrow().method().name());
    }

    private static void assertUnsupported(
            String callerMethod, UnsupportedInterproceduralReason reason) {
        ProjectCallResolution resolution = resolution(callerMethod);
        assertTrue(resolution.target().isEmpty());
        assertEquals(reason, resolution.unsupported().orElseThrow().reason());
    }

    private static ProjectCallResolution resolution(String callerMethod) {
        return result.callResolutions().stream()
                .filter(call -> call.caller().ownerQualifiedName().equals(CONTROLLER))
                .filter(call -> call.caller().method().name().equals(callerMethod))
                .findFirst()
                .orElseThrow();
    }

    private static MethodInfo method(String owner, String name) {
        return result.methodSummaries().keySet().stream()
                .filter(id -> id.ownerQualifiedName().equals(owner))
                .map(ProjectMethodId::method)
                .filter(method -> method.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static MethodInfo genericMethodWithParameter(String parameterType) {
        MethodInfo template = method(SERVICE, "generic");
        return new MethodInfo(
                MethodKind.METHOD,
                "syntheticGeneric",
                Optional.of("void"),
                List.of(new TypeParameterInfo("T", List.of(), template.location())),
                List.of(),
                List.of(new ParameterInfo("value", parameterType, List.of(), template.location())),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                Optional.empty(),
                template.location());
    }

    private static List<String> fixtureResources() {
        return List.of(
                "fixtures/types/controller/TypeController.java",
                "fixtures/types/service/TypeService.java",
                "fixtures/types/model/BaseDto.java",
                "fixtures/types/model/Marker.java",
                "fixtures/types/model/ChildDto.java",
                "fixtures/types/model/OtherDto.java",
                "fixtures/types/cycle/CycleOne.java",
                "fixtures/types/cycle/CycleTwo.java",
                "fixtures/types/duplicateparent/a/Parent.java",
                "fixtures/types/duplicateparent/b/Parent.java",
                "fixtures/types/duplicatechild/ChildWithDuplicateParent.java",
                "fixtures/types/duplicateintermediate/a/Middle.java",
                "fixtures/types/duplicateintermediate/b/Middle.java",
                "fixtures/types/intermediatechild/ChildThroughDuplicateMiddle.java",
                "fixtures/types/wildcard/one/AmbiguousDto.java",
                "fixtures/types/wildcard/two/AmbiguousDto.java",
                "fixtures/types/wildcard/caller/WildcardCaller.java");
    }

    private static Path fixturePath(String resource) throws URISyntaxException {
        var value = ConservativeJavaTypeResolutionTest.class
                .getClassLoader()
                .getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 22 fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
