"""
Compiler Diagnostics & Error Reporting
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class SourceLocation:
    line: int
    column: int
    file_path: Optional[str] = None

class JockyError(Exception):
    def __init__(self, message: str, location: Optional[SourceLocation] = None):
        self.message = message
        self.location = location
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.location:
            loc_str = f"[{self.location.line}:{self.location.column}]"
            if self.location.file_path:
                loc_str = f"{self.location.file_path}{loc_str}"
            return f"JOCKY Error {loc_str}: {self.message}"
        return f"JOCKY Error: {self.message}"

class LexerError(JockyError):
    pass

class ParserError(JockyError):
    pass

class SemanticError(JockyError):
    pass

class SecurityViolationError(JockyError):
    pass
