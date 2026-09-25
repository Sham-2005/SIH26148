"""
JOCKY Semantic Analyzer
Performs static validation, allowlist enforcement, variable scope tracking, and argument arity checks.
"""
from typing import Dict, Set, List, Optional
from compiler.ast.nodes import (
    Program,
    ScriptDeclaration,
    Statement,
    Expression,
    FunctionCall,
    VariableDeclaration,
    Assignment,
    Literal,
    Identifier,
    IfStatement,
    ForStatement,
    BinaryOp,
)
from compiler.diagnostics.errors import SemanticError, SourceLocation
from language.stdlib.stdlib_registry import is_stdlib_function, get_stdlib_spec

class SymbolTable:
    def __init__(self, parent: Optional['SymbolTable'] = None):
        self.parent = parent
        self.symbols: Dict[str, str] = {}  # var_name -> inferred type

    def define(self, name: str, var_type: str = "any") -> None:
        self.symbols[name] = var_type

    def is_defined(self, name: str) -> bool:
        if name in self.symbols:
            return True
        if self.parent:
            return self.parent.is_defined(name)
        return False

    def get_type(self, name: str) -> Optional[str]:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.get_type(name)
        return None

class SemanticAnalyzer:
    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path
        self.errors: List[SemanticError] = []
        self.script_names: Set[str] = set()

    def analyze(self, program: Program) -> None:
        self.errors.clear()
        self.script_names.clear()

        if not program.scripts:
            self._error("Program does not contain any script definitions.", program.location)

        for script in program.scripts:
            self._analyze_script(script)

        if self.errors:
            raise self.errors[0]

    def _error(self, message: str, location: Optional[SourceLocation]) -> None:
        err = SemanticError(message, location)
        self.errors.append(err)

    def _analyze_script(self, script: ScriptDeclaration) -> None:
        if script.name in self.script_names:
            self._error(f"Duplicate script declaration '{script.name}'", script.location)
        self.script_names.add(script.name)

        scope = SymbolTable()
        for stmt in script.body:
            self._analyze_statement(stmt, scope)

    def _analyze_statement(self, stmt: Statement, scope: SymbolTable) -> None:
        if isinstance(stmt, VariableDeclaration):
            expr_type = self._analyze_expression(stmt.initializer, scope)
            scope.define(stmt.name, expr_type)

        elif isinstance(stmt, Assignment):
            if not scope.is_defined(stmt.name):
                self._error(f"Cannot assign to undefined variable '{stmt.name}'", stmt.location)
            expr_type = self._analyze_expression(stmt.value, scope)
            scope.define(stmt.name, expr_type)

        elif isinstance(stmt, FunctionCall):
            self._analyze_function_call(stmt, scope)

        elif isinstance(stmt, IfStatement):
            self._analyze_expression(stmt.condition, scope)
            then_scope = SymbolTable(parent=scope)
            for s in stmt.then_body:
                self._analyze_statement(s, then_scope)
            if stmt.else_body:
                else_scope = SymbolTable(parent=scope)
                for s in stmt.else_body:
                    self._analyze_statement(s, else_scope)

        elif isinstance(stmt, ForStatement):
            self._analyze_expression(stmt.iterable, scope)
            loop_scope = SymbolTable(parent=scope)
            loop_scope.define(stmt.variable, "any")
            for s in stmt.body:
                self._analyze_statement(s, loop_scope)

    def _analyze_function_call(self, call: FunctionCall, scope: SymbolTable) -> str:
        fn_name = call.full_name
        if not is_stdlib_function(fn_name):
            self._error(
                f"Unauthorized or unknown forensic function '{fn_name}'. "
                f"Only approved standard library functions are allowed.",
                call.location
            )
            return "unknown"

        spec = get_stdlib_spec(fn_name)
        expected_params = spec.get("params", []) if spec else []

        if len(call.arguments) != len(expected_params):
            self._error(
                f"Function '{fn_name}' expects {len(expected_params)} arguments, "
                f"but received {len(call.arguments)}",
                call.location
            )

        for arg in call.arguments:
            self._analyze_expression(arg, scope)

        return spec.get("return_type", "any") if spec else "any"

    def _analyze_expression(self, expr: Expression, scope: SymbolTable) -> str:
        if isinstance(expr, Literal):
            return expr.literal_type

        elif isinstance(expr, Identifier):
            if not scope.is_defined(expr.name):
                self._error(f"Use of undeclared variable '{expr.name}'", expr.location)
                return "unknown"
            return scope.get_type(expr.name) or "any"

        elif isinstance(expr, FunctionCall):
            return self._analyze_function_call(expr, scope)

        elif isinstance(expr, BinaryOp):
            left_type = self._analyze_expression(expr.left, scope)
            right_type = self._analyze_expression(expr.right, scope)
            return "bool" if expr.operator in ("==", "!=", "<", "<=", ">", ">=") else "any"

        return "any"
