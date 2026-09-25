"""
JOCKY Lexical Analyzer (Lexer)
Converts JOCKY source code into a structured token stream with precise source locations.
"""
from dataclasses import dataclass
from enum import Enum, auto
import re
from typing import List, Optional
from compiler.diagnostics.errors import LexerError, SourceLocation

class TokenType(Enum):
    # Keywords
    SCRIPT = auto()
    IF = auto()
    ELSE = auto()
    FOR = auto()
    IN = auto()
    TRUE = auto()
    FALSE = auto()

    # Literals
    IDENTIFIER = auto()
    STRING_LITERAL = auto()
    NUMBER_LITERAL = auto()

    # Punctuation & Operators
    LBRACE = auto()       # {
    RBRACE = auto()       # }
    LPAREN = auto()       # (
    RPAREN = auto()       # )
    DOT = auto()          # .
    COMMA = auto()        # ,
    SEMICOLON = auto()    # ;
    EQUALS = auto()       # =
    OPERATOR = auto()     # ==, !=, <=, >=, <, >, +, -, *, /

    EOF = auto()

@dataclass
class Token:
    type: TokenType
    value: str
    location: SourceLocation

KEYWORDS = {
    "script": TokenType.SCRIPT,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "for": TokenType.FOR,
    "in": TokenType.IN,
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
}

class Lexer:
    def __init__(self, source: str, file_path: Optional[str] = None):
        self.source = source
        self.file_path = file_path
        self.length = len(source)
        self.cursor = 0
        self.line = 1
        self.column = 1

    def _peek(self, offset: int = 0) -> Optional[str]:
        pos = self.cursor + offset
        if pos < self.length:
            return self.source[pos]
        return None

    def _advance(self) -> str:
        ch = self.source[self.cursor]
        self.cursor += 1
        if ch == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def _skip_whitespace_and_comments(self):
        while self.cursor < self.length:
            ch = self._peek()
            if ch in (" ", "\t", "\r", "\n"):
                self._advance()
            elif ch == "/" and self._peek(1) == "/":
                # Line comment
                while self.cursor < self.length and self._peek() != "\n":
                    self._advance()
            else:
                break

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.cursor < self.length:
            self._skip_whitespace_and_comments()
            if self.cursor >= self.length:
                break

            start_line = self.line
            start_col = self.column
            ch = self._peek()

            # Punctuation
            if ch == "{":
                self._advance()
                tokens.append(Token(TokenType.LBRACE, "{", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == "}":
                self._advance()
                tokens.append(Token(TokenType.RBRACE, "}", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == "(":
                self._advance()
                tokens.append(Token(TokenType.LPAREN, "(", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == ")":
                self._advance()
                tokens.append(Token(TokenType.RPAREN, ")", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == ".":
                self._advance()
                tokens.append(Token(TokenType.DOT, ".", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == ",":
                self._advance()
                tokens.append(Token(TokenType.COMMA, ",", SourceLocation(start_line, start_col, self.file_path)))
            elif ch == ";":
                self._advance()
                tokens.append(Token(TokenType.SEMICOLON, ";", SourceLocation(start_line, start_col, self.file_path)))

            # Operators or equals
            elif ch in ("=", "!", "<", ">", "+", "-", "*", "/"):
                op = self._advance()
                if self._peek() == "=" and op in ("=", "!", "<", ">"):
                    op += self._advance()
                    tokens.append(Token(TokenType.OPERATOR, op, SourceLocation(start_line, start_col, self.file_path)))
                elif op == "=":
                    tokens.append(Token(TokenType.EQUALS, "=", SourceLocation(start_line, start_col, self.file_path)))
                else:
                    tokens.append(Token(TokenType.OPERATOR, op, SourceLocation(start_line, start_col, self.file_path)))

            # String literals
            elif ch == '"':
                self._advance()  # Opening quote
                s_chars = []
                while self.cursor < self.length and self._peek() != '"':
                    if self._peek() == "\n":
                        raise LexerError("Unterminated string literal across newline", SourceLocation(start_line, start_col, self.file_path))
                    s_chars.append(self._advance())
                if self.cursor >= self.length:
                    raise LexerError("Unterminated string literal", SourceLocation(start_line, start_col, self.file_path))
                self._advance()  # Closing quote
                tokens.append(Token(TokenType.STRING_LITERAL, "".join(s_chars), SourceLocation(start_line, start_col, self.file_path)))

            # Numbers
            elif ch.isdigit():
                num_chars = []
                while self.cursor < self.length and (self._peek().isdigit() or self._peek() == "."):
                    num_chars.append(self._advance())
                tokens.append(Token(TokenType.NUMBER_LITERAL, "".join(num_chars), SourceLocation(start_line, start_col, self.file_path)))

            # Identifiers & Keywords
            elif ch.isalpha() or ch == "_":
                id_chars = []
                while self.cursor < self.length and (self._peek().isalnum() or self._peek() == "_"):
                    id_chars.append(self._advance())
                ident = "".join(id_chars)
                tok_type = KEYWORDS.get(ident, TokenType.IDENTIFIER)
                tokens.append(Token(tok_type, ident, SourceLocation(start_line, start_col, self.file_path)))
            else:
                loc = SourceLocation(start_line, start_col, self.file_path)
                raise LexerError(f"Unexpected character: {ch!r}", loc)

        tokens.append(Token(TokenType.EOF, "", SourceLocation(self.line, self.column, self.file_path)))
        return tokens
