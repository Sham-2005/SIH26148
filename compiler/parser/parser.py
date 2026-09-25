"""
JOCKY Recursive-Descent Parser
Parses token streams into strongly-typed AST nodes with accurate source locations.
"""
from typing import List, Optional, Union
from compiler.lexer.lexer import Token, TokenType
from compiler.diagnostics.errors import ParserError, SourceLocation
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

class Parser:
    def __init__(self, tokens: List[Token], file_path: Optional[str] = None):
        self.tokens = tokens
        self.file_path = file_path
        self.cursor = 0

    def _current(self) -> Token:
        return self.tokens[self.cursor]

    def _peek(self, offset: int = 1) -> Token:
        pos = self.cursor + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]

    def _is_at_end(self) -> bool:
        return self._current().type == TokenType.EOF

    def _match(self, *expected_types: TokenType) -> bool:
        if self._current().type in expected_types:
            self._advance()
            return True
        return False

    def _check(self, expected_type: TokenType) -> bool:
        return self._current().type == expected_type

    def _advance(self) -> Token:
        tok = self._current()
        if not self._is_at_end():
            self.cursor += 1
        return tok

    def _consume(self, expected_type: TokenType, error_message: str) -> Token:
        if self._check(expected_type):
            return self._advance()
        curr = self._current()
        raise ParserError(f"{error_message} (got {curr.type.name} '{curr.value}')", curr.location)

    def parse(self) -> Program:
        scripts: List[ScriptDeclaration] = []
        while not self._is_at_end():
            scripts.append(self._parse_script_declaration())
        return Program(scripts=scripts)

    def _parse_script_declaration(self) -> ScriptDeclaration:
        script_tok = self._consume(TokenType.SCRIPT, "Expected 'script' keyword")
        name_tok = self._consume(TokenType.IDENTIFIER, "Expected script name identifier")
        self._consume(TokenType.LBRACE, "Expected '{' after script name")

        body: List[Statement] = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            body.append(self._parse_statement())

        self._consume(TokenType.RBRACE, "Expected '}' closing script declaration")
        return ScriptDeclaration(name=name_tok.value, body=body, location=script_tok.location)

    def _parse_statement(self) -> Statement:
        curr = self._current()
        if curr.type == TokenType.IF:
            return self._parse_if_statement()
        elif curr.type == TokenType.FOR:
            return self._parse_for_statement()
        elif curr.type == TokenType.IDENTIFIER:
            # Lookahead to distinguish:
            # 1. var = expr;
            # 2. namespace.func(...);
            next_tok = self._peek(1)
            if next_tok.type == TokenType.EQUALS:
                return self._parse_assignment_or_decl()
            elif next_tok.type == TokenType.DOT:
                call = self._parse_function_call()
                self._consume(TokenType.SEMICOLON, "Expected ';' after function call statement")
                return call
            else:
                raise ParserError(f"Unexpected identifier expression statement '{curr.value}'", curr.location)
        else:
            raise ParserError(f"Unexpected token in statement: {curr.type.name} ('{curr.value}')", curr.location)

    def _parse_assignment_or_decl(self) -> Statement:
        var_tok = self._consume(TokenType.IDENTIFIER, "Expected variable name")
        eq_tok = self._consume(TokenType.EQUALS, "Expected '=' in assignment")
        expr = self._parse_expression()
        self._consume(TokenType.SEMICOLON, "Expected ';' after assignment")
        return VariableDeclaration(name=var_tok.value, initializer=expr, location=var_tok.location)

    def _parse_function_call(self) -> FunctionCall:
        ns_tok = self._consume(TokenType.IDENTIFIER, "Expected namespace identifier")
        dot_tok = self._consume(TokenType.DOT, "Expected '.' after namespace")
        fn_tok = self._consume(TokenType.IDENTIFIER, "Expected function name identifier")
        self._consume(TokenType.LPAREN, "Expected '(' after function name")

        args: List[Expression] = []
        if not self._check(TokenType.RPAREN):
            args.append(self._parse_expression())
            while self._match(TokenType.COMMA):
                args.append(self._parse_expression())

        self._consume(TokenType.RPAREN, "Expected ')' after function arguments")
        return FunctionCall(
            namespace=ns_tok.value,
            function=fn_tok.value,
            arguments=args,
            location=ns_tok.location
        )

    def _parse_if_statement(self) -> IfStatement:
        if_tok = self._consume(TokenType.IF, "Expected 'if'")
        condition = self._parse_expression()
        self._consume(TokenType.LBRACE, "Expected '{' before if-block")

        then_body: List[Statement] = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            then_body.append(self._parse_statement())
        self._consume(TokenType.RBRACE, "Expected '}' after if-block")

        else_body: Optional[List[Statement]] = None
        if self._match(TokenType.ELSE):
            self._consume(TokenType.LBRACE, "Expected '{' before else-block")
            else_body = []
            while not self._check(TokenType.RBRACE) and not self._is_at_end():
                else_body.append(self._parse_statement())
            self._consume(TokenType.RBRACE, "Expected '}' after else-block")

        return IfStatement(condition=condition, then_body=then_body, else_body=else_body, location=if_tok.location)

    def _parse_for_statement(self) -> ForStatement:
        for_tok = self._consume(TokenType.FOR, "Expected 'for'")
        var_tok = self._consume(TokenType.IDENTIFIER, "Expected loop variable name")
        self._consume(TokenType.IN, "Expected 'in' keyword")
        iterable = self._parse_expression()
        self._consume(TokenType.LBRACE, "Expected '{' before loop body")

        body: List[Statement] = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            body.append(self._parse_statement())
        self._consume(TokenType.RBRACE, "Expected '}' after loop body")

        return ForStatement(variable=var_tok.value, iterable=iterable, body=body, location=for_tok.location)

    def _parse_expression(self) -> Expression:
        return self._parse_binary()

    def _parse_binary(self) -> Expression:
        expr = self._parse_primary()
        while self._check(TokenType.OPERATOR):
            op_tok = self._advance()
            right = self._parse_primary()
            expr = BinaryOp(left=expr, operator=op_tok.value, right=right, location=op_tok.location)
        return expr

    def _parse_primary(self) -> Expression:
        curr = self._current()

        if curr.type == TokenType.STRING_LITERAL:
            tok = self._advance()
            return Literal(value=tok.value, literal_type="string", location=tok.location)
        elif curr.type == TokenType.NUMBER_LITERAL:
            tok = self._advance()
            val: Union[int, float] = float(tok.value) if "." in tok.value else int(tok.value)
            lit_type = "float" if "." in tok.value else "int"
            return Literal(value=val, literal_type=lit_type, location=tok.location)
        elif curr.type == TokenType.TRUE:
            tok = self._advance()
            return Literal(value=True, literal_type="bool", location=tok.location)
        elif curr.type == TokenType.FALSE:
            tok = self._advance()
            return Literal(value=False, literal_type="bool", location=tok.location)
        elif curr.type == TokenType.IDENTIFIER:
            if self._peek(1).type == TokenType.DOT:
                return self._parse_function_call()
            tok = self._advance()
            return Identifier(name=tok.value, location=tok.location)
        elif curr.type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._consume(TokenType.RPAREN, "Expected ')' closing parenthesized expression")
            return expr
        else:
            raise ParserError(f"Unexpected token in expression: {curr.type.name} ('{curr.value}')", curr.location)
