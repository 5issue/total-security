package com.totalsecurity.sast.java.extractor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.expression.AssignmentExpression;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.BlockStatement;
import com.totalsecurity.sast.ir.statement.BreakStatement;
import com.totalsecurity.sast.ir.statement.ContinueStatement;
import com.totalsecurity.sast.ir.statement.DoWhileStatement;
import com.totalsecurity.sast.ir.statement.EnhancedForStatement;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.IfStatement;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class OrderedStatementExtractorTest {
    @Test
    void preservesLexicalOrderAndControlFlowHierarchy() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixturePath())) {
            assertFalse(parsedFile.hasSyntaxErrors());

            JavaFileInfo file = new JavaSemanticExtractor().extract(parsedFile);
            MethodInfo process = method(type(file, "ControlFlowFixture"), "process");
            BlockStatement body = process.body().orElseThrow();
            List<Statement> statements = body.statements();

            assertEquals(11, statements.size());
            assertInstanceOf(VariableDeclarationStatement.class, statements.get(0));
            assertInstanceOf(IfStatement.class, statements.get(1));
            assertInstanceOf(IfStatement.class, statements.get(2));
            assertInstanceOf(VariableDeclarationStatement.class, statements.get(3));
            assertInstanceOf(WhileStatement.class, statements.get(4));
            assertInstanceOf(EnhancedForStatement.class, statements.get(5));
            assertInstanceOf(ForStatement.class, statements.get(6));
            assertInstanceOf(DoWhileStatement.class, statements.get(7));
            assertInstanceOf(SwitchStatement.class, statements.get(8));
            assertInstanceOf(ExpressionStatement.class, statements.get(9));
            assertInstanceOf(ReturnStatement.class, statements.get(10));
            assertOrderedByLocation(statements);

            IfStatement nullCheck = assertInstanceOf(IfStatement.class, statements.get(1));
            BlockStatement nullBranch =
                    assertInstanceOf(BlockStatement.class, nullCheck.thenBranch());
            ThrowStatement thrown =
                    assertInstanceOf(ThrowStatement.class, nullBranch.statements().getFirst());
            ObjectCreationExpression exception =
                    assertInstanceOf(ObjectCreationExpression.class, thrown.expression());
            assertEquals("IllegalArgumentException", exception.typeName());

            IfStatement conditional = assertInstanceOf(IfStatement.class, statements.get(2));
            VariableReference condition = unwrapVariable(conditional.condition());
            assertEquals("ready", condition.name());
            BlockStatement thenBlock =
                    assertInstanceOf(BlockStatement.class, conditional.thenBranch());
            BlockStatement elseBlock = assertInstanceOf(
                    BlockStatement.class, conditional.elseBranch().orElseThrow());
            assertAssignmentTo(thenBlock.statements().getFirst(), "result");
            assertAssignmentTo(elseBlock.statements().getFirst(), "result");

            WhileStatement whileStatement =
                    assertInstanceOf(WhileStatement.class, statements.get(4));
            BlockStatement whileBody = assertInstanceOf(BlockStatement.class, whileStatement.body());
            assertEquals(3, whileBody.statements().size());
            assertInstanceOf(ExpressionStatement.class, whileBody.statements().get(0));
            IfStatement nestedIf =
                    assertInstanceOf(IfStatement.class, whileBody.statements().get(1));
            BlockStatement breakBlock =
                    assertInstanceOf(BlockStatement.class, nestedIf.thenBranch());
            assertInstanceOf(BreakStatement.class, breakBlock.statements().getFirst());
            assertInstanceOf(ContinueStatement.class, whileBody.statements().get(2));

            EnhancedForStatement enhancedFor =
                    assertInstanceOf(EnhancedForStatement.class, statements.get(5));
            assertEquals("value", enhancedFor.variable().name());
            assertEquals("values", assertInstanceOf(VariableReference.class, enhancedFor.iterable()).name());
            BlockStatement enhancedBody =
                    assertInstanceOf(BlockStatement.class, enhancedFor.body());
            BlockStatement nestedBlock =
                    assertInstanceOf(BlockStatement.class, enhancedBody.statements().getFirst());
            assertAssignmentTo(nestedBlock.statements().getFirst(), "result");

            ForStatement forStatement = assertInstanceOf(ForStatement.class, statements.get(6));
            assertInstanceOf(VariableDeclarationStatement.class, forStatement.initializers().getFirst());
            assertTrue(forStatement.condition().isPresent());
            assertInstanceOf(AssignmentExpression.class, forStatement.updates().getFirst());
            assertInstanceOf(BlockStatement.class, forStatement.body());

            DoWhileStatement doWhile =
                    assertInstanceOf(DoWhileStatement.class, statements.get(7));
            assertInstanceOf(BlockStatement.class, doWhile.body());
            assertInstanceOf(ParenthesizedExpression.class, doWhile.condition());

            SwitchStatement switchStatement =
                    assertInstanceOf(SwitchStatement.class, statements.get(8));
            assertEquals("result", unwrapVariable(switchStatement.selector()).name());
            assertEquals(3, switchStatement.cases().size());
            Literal firstLabel = assertInstanceOf(
                    Literal.class, switchStatement.cases().get(0).labels().getFirst());
            assertEquals("\"stop\"", firstLabel.source());
            ReturnStatement earlyReturn = assertInstanceOf(
                    ReturnStatement.class,
                    switchStatement.cases().get(0).statements().getFirst());
            assertEquals("\"early\"", assertInstanceOf(
                            Literal.class, earlyReturn.expression().orElseThrow())
                    .source());
            assertInstanceOf(
                    BreakStatement.class,
                    switchStatement.cases().get(1).statements().getFirst());
            assertTrue(switchStatement.cases().get(2).defaultCase());

            ExpressionStatement callStatement =
                    assertInstanceOf(ExpressionStatement.class, statements.get(9));
            MethodCallExpression call =
                    assertInstanceOf(MethodCallExpression.class, callStatement.expression());
            assertEquals("execute", call.call().methodName());

            ReturnStatement finalReturn =
                    assertInstanceOf(ReturnStatement.class, statements.get(10));
            assertEquals("result", assertInstanceOf(
                            VariableReference.class, finalReturn.expression().orElseThrow())
                    .name());
        }
    }

    private static VariableReference unwrapVariable(com.totalsecurity.sast.ir.expression.Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return assertInstanceOf(VariableReference.class, parenthesized.expression());
        }
        return assertInstanceOf(VariableReference.class, expression);
    }

    private static void assertAssignmentTo(Statement statement, String variableName) {
        ExpressionStatement expressionStatement =
                assertInstanceOf(ExpressionStatement.class, statement);
        AssignmentExpression assignment =
                assertInstanceOf(AssignmentExpression.class, expressionStatement.expression());
        assertEquals(variableName, assertInstanceOf(
                        VariableReference.class, assignment.assignment().left())
                .name());
    }

    private static void assertOrderedByLocation(List<Statement> statements) {
        for (int index = 1; index < statements.size(); index++) {
            assertTrue(
                    statements.get(index - 1).location().startLine()
                            <= statements.get(index).location().startLine());
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

    private static Path fixturePath() throws URISyntaxException {
        var resource = OrderedStatementExtractorTest.class
                .getClassLoader()
                .getResource("fixtures/ControlFlowFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 2B fixture not found");
        }
        return Path.of(resource.toURI());
    }
}

