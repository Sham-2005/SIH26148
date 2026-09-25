"""
JOCKY Strongly-Typed Abstract Syntax Tree (AST) Nodes
"""
from dataclasses import dataclass, field
from typing import List, Optional, Any, Union
from compiler.diagnostics.errors import SourceLocation

@dataclass
class ASTNode:
    location: Optional[SourceLocation] = field(default=None, kw_only=True)

@dataclass
class Expression(ASTNode):
    pass

@dataclass
class Statement(ASTNode):
    pass

@dataclass
class Literal(Expression):
    value: Any
    literal_type: str  # "string", "int", "float", "bool"

@dataclass
class Identifier(Expression):
    name: str

@dataclass
class FunctionCall(Expression, Statement):
    namespace: str
    function: str
    arguments: List[Expression] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.function}"

@dataclass
class BinaryOp(Expression):
    left: Expression
    operator: str
    right: Expression

@dataclass
class VariableDeclaration(Statement):
    name: str
    initializer: Expression

@dataclass
class Assignment(Statement):
    name: str
    value: Expression

@dataclass
class IfStatement(Statement):
    condition: Expression
    then_body: List[Statement] = field(default_factory=list)
    else_body: Optional[List[Statement]] = None

@dataclass
class ForStatement(Statement):
    variable: str
    iterable: Expression
    body: List[Statement] = field(default_factory=list)

@dataclass
class ScriptDeclaration(ASTNode):
    name: str
    body: List[Statement] = field(default_factory=list)

@dataclass
class Program(ASTNode):
    scripts: List[ScriptDeclaration] = field(default_factory=list)
