package com.totalsecurity.sast.java.extractor;

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
import com.totalsecurity.sast.ir.TypeParameterInfo;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.VariableKind;
import com.totalsecurity.sast.ir.expression.AssignmentExpression;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.UnknownExpression;
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
import com.totalsecurity.sast.ir.statement.SwitchCase;
import com.totalsecurity.sast.ir.statement.SwitchCaseKind;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.UnknownStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.treesitter.TSNode;
import org.treesitter.TSPoint;

/** Converts Tree-sitter Java syntax nodes into the Tree-sitter-independent Java IR. */
public final class JavaSemanticExtractor {
    private ParsedJavaFile source;

    public JavaFileInfo extract(ParsedJavaFile parsedJavaFile) {
        source = Objects.requireNonNull(parsedJavaFile, "parsedJavaFile");
        TSNode root = source.rootNode();

        Optional<String> packageName = Optional.empty();
        List<String> imports = new ArrayList<>();
        List<ClassInfo> types = new ArrayList<>();

        for (TSNode child : namedChildren(root)) {
            switch (child.getType()) {
                case "package_declaration" -> packageName = extractPackageName(child);
                case "import_declaration" -> imports.add(extractImport(child));
                case "class_declaration" -> types.add(extractType(child, TypeKind.CLASS));
                case "interface_declaration" -> types.add(extractType(child, TypeKind.INTERFACE));
                default -> {
                    // STEP 2 intentionally supports only classes and interfaces as top-level types.
                }
            }
        }

        return new JavaFileInfo(packageName, imports, types, location(root));
    }

    private Optional<String> extractPackageName(TSNode declaration) {
        return firstNamedChild(declaration).map(this::text);
    }

    private String extractImport(TSNode declaration) {
        String declarationText = text(declaration).trim();
        String withoutKeyword = declarationText.substring("import".length()).trim();
        return withoutKeyword.endsWith(";")
                ? withoutKeyword.substring(0, withoutKeyword.length() - 1).trim()
                : withoutKeyword;
    }

    private ClassInfo extractType(TSNode declaration, TypeKind kind) {
        String name = field(declaration, "name").map(this::text).orElse("<unnamed>");
        List<String> extendsTypes = extractDeclaredSupertypes(
                declaration, "superclass", "extends_interfaces");
        List<String> implementsTypes = extractDeclaredSupertypes(declaration, "super_interfaces");
        List<AnnotationInfo> annotations = extractAnnotations(declaration);
        List<VariableInfo> fields = new ArrayList<>();
        List<MethodInfo> methods = new ArrayList<>();

        field(declaration, "body").ifPresent(body -> {
            for (TSNode member : namedChildren(body)) {
                switch (member.getType()) {
                    case "field_declaration" ->
                            fields.addAll(extractVariables(member, VariableKind.FIELD));
                    case "method_declaration" -> methods.add(extractMethod(member, MethodKind.METHOD));
                    case "constructor_declaration" ->
                            methods.add(extractMethod(member, MethodKind.CONSTRUCTOR));
                    default -> {
                        // Nested types and initializer blocks are outside this extraction step.
                    }
                }
            }
        });

        return new ClassInfo(
                kind,
                name,
                extendsTypes,
                implementsTypes,
                annotations,
                fields,
                methods,
                location(declaration));
    }

    private MethodInfo extractMethod(TSNode declaration, MethodKind kind) {
        String name = field(declaration, "name").map(this::text).orElse("<unnamed>");
        Optional<String> returnType = kind == MethodKind.CONSTRUCTOR
                ? Optional.empty()
                : field(declaration, "type").map(this::text);
        List<ParameterInfo> parameters = field(declaration, "parameters")
                .map(this::extractParameters)
                .orElseGet(List::of);
        MethodContents contents = new MethodContents();
        Optional<BlockStatement> body = field(declaration, "body").map(this::extractBlock);
        field(declaration, "body").ifPresent(bodyNode ->
                collectMethodContents(bodyNode, bodyNode, contents));

        return new MethodInfo(
                kind,
                name,
                returnType,
                extractTypeParameters(declaration),
                extractAnnotations(declaration),
                parameters,
                contents.localVariables,
                contents.assignments,
                contents.methodCalls,
                contents.returns,
                body,
                location(declaration));
    }

    private List<String> extractDeclaredSupertypes(TSNode declaration, String... relationTypes) {
        List<String> result = new ArrayList<>();
        for (TSNode child : namedChildren(declaration)) {
            boolean matches = false;
            for (String relationType : relationTypes) {
                if (child.getType().equals(relationType)) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                continue;
            }
            for (TSNode relationChild : namedChildren(child)) {
                if (relationChild.getType().equals("type_list")) {
                    namedChildren(relationChild).forEach(type -> result.add(text(type)));
                } else {
                    result.add(text(relationChild));
                }
            }
        }
        return List.copyOf(result);
    }

    private List<TypeParameterInfo> extractTypeParameters(TSNode declaration) {
        return field(declaration, "type_parameters")
                .map(parameters -> namedChildren(parameters).stream()
                        .filter(parameter -> parameter.getType().equals("type_parameter"))
                        .map(this::extractTypeParameter)
                        .toList())
                .orElseGet(List::of);
    }

    private TypeParameterInfo extractTypeParameter(TSNode parameter) {
        String name = namedChildren(parameter).stream()
                .filter(child -> child.getType().equals("type_identifier"))
                .findFirst()
                .map(this::text)
                .orElse("<unnamed>");
        List<String> bounds = namedChildren(parameter).stream()
                .filter(child -> child.getType().equals("type_bound"))
                .flatMap(bound -> namedChildren(bound).stream())
                .map(this::text)
                .toList();
        return new TypeParameterInfo(name, bounds, location(parameter));
    }

    private BlockStatement extractBlock(TSNode block) {
        List<Statement> statements = namedChildren(block).stream()
                .map(this::extractStatement)
                .toList();
        return new BlockStatement(statements, location(block));
    }

    private Statement extractStatement(TSNode node) {
        return switch (node.getType()) {
            case "block" -> extractBlock(node);
            case "local_variable_declaration" -> new VariableDeclarationStatement(
                    extractVariables(node, VariableKind.LOCAL), location(node));
            case "expression_statement" -> firstNamedChild(node)
                    .<Statement>map(expression -> new ExpressionStatement(
                            extractExpression(expression), location(node)))
                    .orElseGet(() -> unknownStatement(node));
            case "return_statement" -> new ReturnStatement(
                    firstNamedChild(node).map(this::extractExpression), location(node));
            case "if_statement" -> extractIf(node);
            case "while_statement" -> extractWhile(node);
            case "do_statement" -> extractDoWhile(node);
            case "for_statement" -> extractFor(node);
            case "enhanced_for_statement" -> extractEnhancedFor(node);
            case "switch_expression" -> extractSwitch(node);
            case "break_statement" -> new BreakStatement(extractJumpLabel(node), location(node));
            case "continue_statement" ->
                    new ContinueStatement(extractJumpLabel(node), location(node));
            case "throw_statement" -> firstNamedChild(node)
                    .<Statement>map(expression ->
                            new ThrowStatement(extractExpression(expression), location(node)))
                    .orElseGet(() -> unknownStatement(node));
            default -> unknownStatement(node);
        };
    }

    private IfStatement extractIf(TSNode node) {
        Expression condition = field(node, "condition")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        Statement thenBranch = field(node, "consequence")
                .map(this::extractStatement)
                .orElseGet(() -> unknownStatement(node));
        Optional<Statement> elseBranch = field(node, "alternative").map(this::extractStatement);
        return new IfStatement(condition, thenBranch, elseBranch, location(node));
    }

    private WhileStatement extractWhile(TSNode node) {
        Expression condition = field(node, "condition")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        Statement body = field(node, "body")
                .map(this::extractStatement)
                .orElseGet(() -> unknownStatement(node));
        return new WhileStatement(condition, body, location(node));
    }

    private DoWhileStatement extractDoWhile(TSNode node) {
        Statement body = field(node, "body")
                .map(this::extractStatement)
                .orElseGet(() -> unknownStatement(node));
        Expression condition = field(node, "condition")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        return new DoWhileStatement(body, condition, location(node));
    }

    private ForStatement extractFor(TSNode node) {
        List<Statement> initializers = field(node, "init")
                .map(this::extractForInitializers)
                .orElseGet(List::of);
        Optional<Expression> condition = field(node, "condition").map(this::extractExpression);
        List<Expression> updates = field(node, "update")
                .map(this::extractExpressionList)
                .orElseGet(List::of);
        Statement body = field(node, "body")
                .map(this::extractStatement)
                .orElseGet(() -> unknownStatement(node));
        return new ForStatement(initializers, condition, updates, body, location(node));
    }

    private List<Statement> extractForInitializers(TSNode node) {
        if (node.getType().equals("local_variable_declaration")) {
            return List.of(new VariableDeclarationStatement(
                    extractVariables(node, VariableKind.LOCAL), location(node)));
        }
        return extractExpressionList(node).stream()
                .<Statement>map(expression -> new ExpressionStatement(expression, expression.location()))
                .toList();
    }

    private List<Expression> extractExpressionList(TSNode node) {
        if (node.getType().equals("expression_list")) {
            return namedChildren(node).stream().map(this::extractExpression).toList();
        }
        return List.of(extractExpression(node));
    }

    private EnhancedForStatement extractEnhancedFor(TSNode node) {
        String name = field(node, "name").map(this::text).orElse("<unnamed>");
        String type = field(node, "type").map(this::text).orElse("<unknown>");
        VariableInfo variable = new VariableInfo(
                VariableKind.LOCAL,
                name,
                type,
                extractAnnotations(node),
                Optional.empty(),
                location(node));
        Expression iterable = field(node, "value")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        Statement body = field(node, "body")
                .map(this::extractStatement)
                .orElseGet(() -> unknownStatement(node));
        return new EnhancedForStatement(variable, iterable, body, location(node));
    }

    private SwitchStatement extractSwitch(TSNode node) {
        Expression selector = field(node, "condition")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        List<SwitchCase> cases = field(node, "body")
                .map(this::extractSwitchCases)
                .orElseGet(List::of);
        return new SwitchStatement(selector, cases, location(node));
    }

    private List<SwitchCase> extractSwitchCases(TSNode switchBlock) {
        List<SwitchCase> cases = new ArrayList<>();
        for (TSNode child : namedChildren(switchBlock)) {
            if (child.getType().equals("switch_block_statement_group")
                    || child.getType().equals("switch_rule")) {
                cases.add(extractSwitchCase(child));
            }
        }
        return List.copyOf(cases);
    }

    private SwitchCase extractSwitchCase(TSNode group) {
        SwitchCaseKind kind = group.getType().equals("switch_rule")
                ? SwitchCaseKind.ARROW_RULE
                : SwitchCaseKind.STATEMENT_GROUP;
        List<Expression> labels = new ArrayList<>();
        List<Statement> statements = new ArrayList<>();
        boolean defaultCase = false;

        for (TSNode child : namedChildren(group)) {
            if (child.getType().equals("switch_label")) {
                List<TSNode> labelValues = namedChildren(child);
                if (labelValues.isEmpty()) {
                    defaultCase = true;
                } else {
                    labelValues.stream().map(this::extractExpression).forEach(labels::add);
                }
            } else if (isStatementNode(child)) {
                statements.add(extractStatement(child));
            } else {
                statements.add(new ExpressionStatement(extractExpression(child), location(child)));
            }
        }
        return new SwitchCase(kind, labels, defaultCase, statements, location(group));
    }

    private boolean isStatementNode(TSNode node) {
        return switch (node.getType()) {
            case "block",
                    "local_variable_declaration",
                    "expression_statement",
                    "return_statement",
                    "if_statement",
                    "while_statement",
                    "do_statement",
                    "for_statement",
                    "enhanced_for_statement",
                    "switch_expression",
                    "break_statement",
                    "continue_statement",
                    "throw_statement" -> true;
            default -> false;
        };
    }

    private Optional<String> extractJumpLabel(TSNode node) {
        return firstNamedChild(node).map(this::text);
    }

    private UnknownStatement unknownStatement(TSNode node) {
        return new UnknownStatement(node.getType(), text(node), location(node));
    }

    private List<ParameterInfo> extractParameters(TSNode parametersNode) {
        List<ParameterInfo> parameters = new ArrayList<>();
        for (TSNode child : namedChildren(parametersNode)) {
            if (child.getType().equals("formal_parameter")) {
                String name = field(child, "name").map(this::text).orElse("<unnamed>");
                String type = field(child, "type").map(this::text).orElse("<unknown>");
                parameters.add(new ParameterInfo(
                        name, type, extractAnnotations(child), location(child)));
            }
        }
        return List.copyOf(parameters);
    }

    private List<VariableInfo> extractVariables(TSNode declaration, VariableKind kind) {
        String type = field(declaration, "type").map(this::text).orElse("<unknown>");
        List<AnnotationInfo> annotations = extractAnnotations(declaration);
        List<VariableInfo> variables = new ArrayList<>();

        for (TSNode child : namedChildren(declaration)) {
            if (!child.getType().equals("variable_declarator")) {
                continue;
            }
            String name = field(child, "name").map(this::text).orElse("<unnamed>");
            Optional<Expression> initializer = field(child, "value").map(this::extractExpression);
            variables.add(new VariableInfo(
                    kind, name, type, annotations, initializer, location(child)));
        }
        return List.copyOf(variables);
    }

    private void collectMethodContents(TSNode methodBody, TSNode node, MethodContents contents) {
        if (node != methodBody && isNestedSemanticBoundary(node)) {
            return;
        }

        switch (node.getType()) {
            case "local_variable_declaration" ->
                    contents.localVariables.addAll(extractVariables(node, VariableKind.LOCAL));
            case "assignment_expression" -> contents.assignments.add(extractAssignment(node));
            case "method_invocation" -> contents.methodCalls.add(extractMethodCall(node));
            case "return_statement" -> contents.returns.add(extractReturn(node));
            default -> {
                // Traversal continues so supported descendants inside control structures are retained.
            }
        }

        for (TSNode child : namedChildren(node)) {
            collectMethodContents(methodBody, child, contents);
        }
    }

    private boolean isNestedSemanticBoundary(TSNode node) {
        return switch (node.getType()) {
            case "class_declaration",
                    "interface_declaration",
                    "enum_declaration",
                    "record_declaration",
                    "lambda_expression" -> true;
            default -> false;
        };
    }

    private AssignmentInfo extractAssignment(TSNode assignment) {
        Expression left = field(assignment, "left")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(assignment));
        Expression right = field(assignment, "right")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(assignment));
        String operator = field(assignment, "operator")
                .map(this::text)
                .orElseGet(() -> operatorBetween(assignment, left.location(), right.location()));
        return new AssignmentInfo(left, operator, right, location(assignment));
    }

    private ReturnInfo extractReturn(TSNode returnNode) {
        return new ReturnInfo(firstNamedChild(returnNode).map(this::extractExpression), location(returnNode));
    }

    private Expression extractExpression(TSNode node) {
        String nodeType = node.getType();
        if (nodeType.endsWith("_literal")
                || nodeType.equals("true")
                || nodeType.equals("false")
                || nodeType.equals("null")) {
            return new Literal(nodeType, text(node), location(node));
        }

        return switch (nodeType) {
            case "identifier", "this", "super" -> new VariableReference(text(node), location(node));
            case "assignment_expression" -> new AssignmentExpression(extractAssignment(node));
            case "binary_expression" -> extractBinaryExpression(node);
            case "method_invocation" -> new MethodCallExpression(extractMethodCall(node));
            case "object_creation_expression" -> extractObjectCreation(node);
            case "field_access" -> extractFieldAccess(node);
            case "parenthesized_expression" -> firstNamedChild(node)
                    .<Expression>map(child ->
                            new ParenthesizedExpression(extractExpression(child), location(node)))
                    .orElseGet(() -> unknown(node));
            default -> unknown(node);
        };
    }

    private BinaryExpression extractBinaryExpression(TSNode node) {
        TSNode leftNode = field(node, "left").orElseThrow();
        TSNode rightNode = field(node, "right").orElseThrow();
        Expression left = extractExpression(leftNode);
        Expression right = extractExpression(rightNode);
        String operator = field(node, "operator")
                .map(this::text)
                .orElseGet(() -> operatorBetween(node, left.location(), right.location()));
        return new BinaryExpression(operator, left, right, location(node));
    }

    private MethodCallInfo extractMethodCall(TSNode node) {
        Optional<Expression> receiver = field(node, "object").map(this::extractExpression);
        String methodName = field(node, "name").map(this::text).orElse("<unknown>");
        List<Expression> arguments = field(node, "arguments")
                .map(this::extractArguments)
                .orElseGet(List::of);
        return new MethodCallInfo(receiver, methodName, arguments, location(node));
    }

    private ObjectCreationExpression extractObjectCreation(TSNode node) {
        String typeName = field(node, "type").map(this::text).orElse("<unknown>");
        List<Expression> arguments = field(node, "arguments")
                .map(this::extractArguments)
                .orElseGet(List::of);
        return new ObjectCreationExpression(typeName, arguments, location(node));
    }

    private FieldAccessExpression extractFieldAccess(TSNode node) {
        Expression target = field(node, "object")
                .map(this::extractExpression)
                .orElseGet(() -> unknown(node));
        String fieldName = field(node, "field").map(this::text).orElse("<unknown>");
        return new FieldAccessExpression(target, fieldName, location(node));
    }

    private List<Expression> extractArguments(TSNode argumentsNode) {
        return namedChildren(argumentsNode).stream().map(this::extractExpression).toList();
    }

    private List<AnnotationInfo> extractAnnotations(TSNode owner) {
        List<AnnotationInfo> annotations = new ArrayList<>();
        for (TSNode child : namedChildren(owner)) {
            if (child.getType().equals("modifiers")) {
                for (TSNode modifier : namedChildren(child)) {
                    if (isAnnotation(modifier)) {
                        annotations.add(extractAnnotation(modifier));
                    }
                }
            } else if (isAnnotation(child)) {
                annotations.add(extractAnnotation(child));
            }
        }
        return List.copyOf(annotations);
    }

    private boolean isAnnotation(TSNode node) {
        return node.getType().equals("annotation") || node.getType().equals("marker_annotation");
    }

    private AnnotationInfo extractAnnotation(TSNode annotation) {
        String name = field(annotation, "name")
                .map(this::text)
                .orElseGet(() -> namedChildren(annotation).stream()
                        .findFirst()
                        .map(this::text)
                        .orElse("<unknown>"));
        List<String> arguments = field(annotation, "arguments")
                .map(argumentList -> namedChildren(argumentList).stream().map(this::text).toList())
                .orElseGet(List::of);
        return new AnnotationInfo(name, arguments, location(annotation));
    }

    private UnknownExpression unknown(TSNode node) {
        return new UnknownExpression(node.getType(), text(node), location(node));
    }

    private String operatorBetween(
            TSNode parent, SourceLocation leftLocation, SourceLocation rightLocation) {
        for (int index = 0; index < parent.getChildCount(); index++) {
            TSNode child = parent.getChild(index);
            if (!child.isNamed()
                    && child.getStartPoint().getRow() + 1 >= leftLocation.endLine()
                    && child.getEndPoint().getRow() + 1 <= rightLocation.startLine()) {
                String candidate = text(child).trim();
                if (!candidate.isEmpty()) {
                    return candidate;
                }
            }
        }
        return "<unknown>";
    }

    private SourceLocation location(TSNode node) {
        TSPoint start = node.getStartPoint();
        TSPoint end = node.getEndPoint();
        return new SourceLocation(
                source.path(),
                start.getRow() + 1,
                start.getColumn() + 1,
                end.getRow() + 1,
                end.getColumn() + 1);
    }

    private String text(TSNode node) {
        return source.sourceText(node);
    }

    private Optional<TSNode> field(TSNode node, String name) {
        TSNode child = node.getChildByFieldName(name);
        return child == null || child.isNull() ? Optional.empty() : Optional.of(child);
    }

    private Optional<TSNode> firstNamedChild(TSNode node) {
        return node.getNamedChildCount() == 0
                ? Optional.empty()
                : Optional.of(node.getNamedChild(0));
    }

    private List<TSNode> namedChildren(TSNode node) {
        List<TSNode> children = new ArrayList<>(node.getNamedChildCount());
        for (int index = 0; index < node.getNamedChildCount(); index++) {
            children.add(node.getNamedChild(index));
        }
        return children;
    }

    private static final class MethodContents {
        private final List<VariableInfo> localVariables = new ArrayList<>();
        private final List<AssignmentInfo> assignments = new ArrayList<>();
        private final List<MethodCallInfo> methodCalls = new ArrayList<>();
        private final List<ReturnInfo> returns = new ArrayList<>();
    }
}
