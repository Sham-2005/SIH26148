from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.bytecode.compiler import BytecodeCompiler
from vm.vm import JockyVM


def compile_source(source: str):
    tokens = Lexer(source).tokenize()
    program = Parser(tokens).parse()
    SemanticAnalyzer().analyze(program)
    return BytecodeCompiler().compile(program)


def test_forensic_call_reaches_vm_dispatcher():
    image = compile_source('''
    script collect_host {
        process.list();
        evidence.collect();
    }
    ''')
    observed = []
    result = JockyVM(dispatcher=lambda fn, args: observed.append((fn, args)) or [{"ok": True}]).execute(image)
    assert result.status == "SUCCESS"
    assert observed == [("process.list", [])]
    assert result.evidence_sealed is True
    assert "process.list" in image.capabilities


def test_vm_rejects_undefined_variable():
    image = compile_source('''
    script bad {
        process.info(pid);
    }
    ''')
    try:
        JockyVM().execute(image)
    except Exception as exc:
        assert "Undefined VM variable" in str(exc)
    else:
        raise AssertionError("Expected VM execution failure")
