"""
Automated Tests for JOCKY Compiler Pipeline
"""
import pytest
from compiler.lexer.lexer import Lexer, TokenType
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator
from compiler.diagnostics.errors import SemanticError, LexerError, ParserError

def test_lexer_tokens():
    source = 'script TestScript { system.info(); file.hash("/sample/test.exe"); }'
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    token_types = [t.type for t in tokens]
    assert token_types[0] == TokenType.SCRIPT
    assert token_types[1] == TokenType.IDENTIFIER
    assert token_types[2] == TokenType.LBRACE
    assert TokenType.STRING_LITERAL in token_types
    assert tokens[-1].type == TokenType.EOF

def test_parser_ast_generation():
    source = '''
    script ProcessInvestigation {
        limit = 100;
        process.list();
    }
    '''
    tokens = Lexer(source).tokenize()
    parser = Parser(tokens)
    program = parser.parse()

    assert len(program.scripts) == 1
    assert program.scripts[0].name == "ProcessInvestigation"
    assert len(program.scripts[0].body) == 2

def test_semantic_analyzer_allowlist_enforcement():
    # Attempting to call an unauthorized malicious or unknown function
    malicious_script = '''
    script MaliciousAttempt {
        system.exec_shell("rm -rf /");
    }
    '''
    tokens = Lexer(malicious_script).tokenize()
    program = Parser(tokens).parse()
    analyzer = SemanticAnalyzer()

    with pytest.raises(SemanticError) as exc_info:
        analyzer.analyze(program)
    assert "Unauthorized or unknown forensic function 'system.exec_shell'" in str(exc_info.value)

def test_semantic_analyzer_undeclared_variable():
    script = '''
    script BadVariable {
        file.hash(unassigned_path);
    }
    '''
    tokens = Lexer(script).tokenize()
    program = Parser(tokens).parse()
    analyzer = SemanticAnalyzer()

    with pytest.raises(SemanticError) as exc_info:
        analyzer.analyze(program)
    assert "Use of undeclared variable 'unassigned_path'" in str(exc_info.value)

def test_safe_codegen_deterministic_hash():
    script = '''
    script DeterministicTest {
        system.info();
        process.list();
        evidence.collect();
    }
    '''
    tokens = Lexer(script).tokenize()
    program = Parser(tokens).parse()
    SemanticAnalyzer().analyze(program)

    codegen = SafeCodeGenerator()
    plan_1 = codegen.generate_plan(program)
    plan_2 = codegen.generate_plan(program)

    assert plan_1["scripts"][0]["plan_hash"] == plan_2["scripts"][0]["plan_hash"]
    assert len(plan_1["scripts"][0]["steps"]) == 3
