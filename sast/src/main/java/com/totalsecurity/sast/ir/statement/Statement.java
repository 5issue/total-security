package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;

public sealed interface Statement
        permits BlockStatement,
                VariableDeclarationStatement,
                ExpressionStatement,
                ReturnStatement,
                IfStatement,
                WhileStatement,
                DoWhileStatement,
                ForStatement,
                EnhancedForStatement,
                SwitchStatement,
                BreakStatement,
                ContinueStatement,
                ThrowStatement,
                UnknownStatement {
    SourceLocation location();
}

