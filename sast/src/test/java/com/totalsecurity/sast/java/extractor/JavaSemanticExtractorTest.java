package com.totalsecurity.sast.java.extractor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.AnnotationInfo;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodCallInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.ReturnInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.TypeKind;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.net.URISyntaxException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class JavaSemanticExtractorTest {
    @Test
    void extractsStructuredJavaIrFromSpringStyleSource() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixturePath())) {
            assertFalse(parsedFile.hasSyntaxErrors());

            JavaFileInfo file = new JavaSemanticExtractor().extract(parsedFile);
            assertEquals("fixtures.step2", file.packageName().orElseThrow());
            assertEquals(3, file.imports().size());
            assertTrue(file.imports().contains("org.springframework.web.bind.annotation.GetMapping"));
            assertOneBased(file.location());

            ClassInfo controller = type(file, "SampleController");
            assertEquals(TypeKind.CLASS, controller.kind());
            assertEquals("RestController", annotation(controller, "RestController").name());
            assertOneBased(controller.location());

            VariableInfo serviceField = variable(controller.fields(), "service");
            assertEquals("SampleService", serviceField.type());
            assertTrue(serviceField.initializer().isEmpty());
            assertOneBased(serviceField.location());

            MethodInfo constructor = method(controller, "SampleController");
            assertEquals(MethodKind.CONSTRUCTOR, constructor.kind());
            assertTrue(constructor.returnType().isEmpty());
            AssignmentInfo fieldAssignment = constructor.assignments().getFirst();
            FieldAccessExpression constructorLeft =
                    assertInstanceOf(FieldAccessExpression.class, fieldAssignment.left());
            assertEquals("service", constructorLeft.fieldName());

            MethodInfo getUser = method(controller, "getUser");
            assertEquals(MethodKind.METHOD, getUser.kind());
            assertEquals("String", getUser.returnType().orElseThrow());
            AnnotationInfo getMapping = annotation(getUser, "GetMapping");
            assertEquals(java.util.List.of("\"/users\""), getMapping.arguments());
            assertOneBased(getUser.location());

            ParameterInfo id = getUser.parameters().getFirst();
            assertEquals("id", id.name());
            assertEquals("String", id.type());
            assertEquals("RequestParam", annotation(id, "RequestParam").name());
            assertOneBased(id.location());

            VariableInfo userId = variable(getUser.localVariables(), "userId");
            VariableReference userIdInitializer =
                    assertInstanceOf(VariableReference.class, userId.initializer().orElseThrow());
            assertEquals("id", userIdInitializer.name());

            VariableInfo value = variable(getUser.localVariables(), "value");
            BinaryExpression valueInitializer =
                    assertInstanceOf(BinaryExpression.class, value.initializer().orElseThrow());
            assertEquals("+", valueInitializer.operator());
            Literal prefix = assertInstanceOf(Literal.class, valueInitializer.left());
            assertEquals("\"prefix-\"", prefix.source());
            VariableReference binaryVariable =
                    assertInstanceOf(VariableReference.class, valueInitializer.right());
            assertEquals("userId", binaryVariable.name());
            assertOneBased(valueInitializer.location());

            VariableInfo alias = variable(getUser.localVariables(), "alias");
            ParenthesizedExpression parenthesized = assertInstanceOf(
                    ParenthesizedExpression.class, alias.initializer().orElseThrow());
            assertEquals("value", assertInstanceOf(
                            VariableReference.class, parenthesized.expression())
                    .name());
            assertOneBased(parenthesized.location());

            AssignmentInfo normalization = getUser.assignments().getFirst();
            VariableReference assignmentLeft =
                    assertInstanceOf(VariableReference.class, normalization.left());
            assertEquals("userId", assignmentLeft.name());
            MethodCallExpression assignmentRight =
                    assertInstanceOf(MethodCallExpression.class, normalization.right());
            assertEquals("normalize", assignmentRight.call().methodName());
            assertTrue(assignmentRight.call().receiver().isEmpty());
            VariableReference normalizeArgument = assertInstanceOf(
                    VariableReference.class, assignmentRight.call().arguments().getFirst());
            assertEquals("userId", normalizeArgument.name());

            VariableInfo request = variable(getUser.localVariables(), "request");
            ObjectCreationExpression creation = assertInstanceOf(
                    ObjectCreationExpression.class, request.initializer().orElseThrow());
            assertEquals("SampleRequest", creation.typeName());
            assertEquals("userId", assertInstanceOf(
                            VariableReference.class, creation.arguments().getFirst())
                    .name());

            MethodCallInfo findUser = getUser.methodCalls().stream()
                    .filter(call -> call.methodName().equals("findUser"))
                    .findFirst()
                    .orElseThrow();
            VariableReference receiver =
                    assertInstanceOf(VariableReference.class, findUser.receiver().orElseThrow());
            assertEquals("service", receiver.name());
            assertEquals("userId", assertInstanceOf(
                            VariableReference.class, findUser.arguments().getFirst())
                    .name());
            assertOneBased(findUser.location());

            ReturnInfo returned = getUser.returns().getFirst();
            VariableReference returnExpression =
                    assertInstanceOf(VariableReference.class, returned.expression().orElseThrow());
            assertEquals("value", returnExpression.name());
            assertOneBased(returned.location());

            ClassInfo service = type(file, "SampleService");
            assertEquals(TypeKind.INTERFACE, service.kind());
            MethodInfo interfaceMethod = method(service, "findUser");
            assertEquals("String", interfaceMethod.returnType().orElseThrow());
            assertTrue(interfaceMethod.localVariables().isEmpty());
        }
    }

    private static ClassInfo type(JavaFileInfo file, String name) {
        return file.types().stream()
                .filter(type -> type.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static MethodInfo method(ClassInfo type, String name) {
        return type.methods().stream()
                .filter(method -> method.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static VariableInfo variable(java.util.List<VariableInfo> variables, String name) {
        return variables.stream()
                .filter(variable -> variable.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static AnnotationInfo annotation(ClassInfo type, String name) {
        return type.annotations().stream()
                .filter(annotation -> annotation.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static AnnotationInfo annotation(MethodInfo method, String name) {
        return method.annotations().stream()
                .filter(annotation -> annotation.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static AnnotationInfo annotation(ParameterInfo parameter, String name) {
        return parameter.annotations().stream()
                .filter(annotation -> annotation.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static void assertOneBased(SourceLocation location) {
        assertTrue(location.startLine() >= 1);
        assertTrue(location.startColumn() >= 1);
        assertTrue(location.endLine() >= 1);
        assertTrue(location.endColumn() >= 1);
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = JavaSemanticExtractorTest.class
                .getClassLoader()
                .getResource("fixtures/Step2SampleController.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 2 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
