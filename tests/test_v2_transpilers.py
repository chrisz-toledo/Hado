import pytest
from hado.ast_nodes import *
from hado.v2.c_transpiler import CTranspiler
from hado.v2.rust_transpiler import RustTranspiler


# ═══════════════════════════════════════════════════════════════════════════
# C TRANSPILER TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_c_transpiler_memory_drops_if():
    """Verifica free() al final del then_body de un IfStatement."""
    stmt = IfStatement(
        condition=BooleanLiteral(value=True),
        then_body=[Assignment(name="temp_data", value=StringLiteral(value='"secret"'))]
    )
    stmt.meta["then_drops"] = ["temp_data"]
    stmt.then_body[0].meta["memory_action"] = "BindOwner"

    prog = Program(statements=[stmt])
    code = CTranspiler(prog).emit()

    assert "free(temp_data);" in code
    assert "strdup(\"secret\")" in code
    assert "if (true)" in code


def test_c_transpiler_while_loop_drops():
    """Verifica que el while real inyecte free() por CADA iteración."""
    stmt = WhileStatement(
        condition=BooleanLiteral(value=True),
        body=[Assignment(name="buf", value=StringLiteral(value='"payload"'))]
    )
    stmt.meta["drops"] = ["buf"]
    stmt.body[0].meta["memory_action"] = "BindOwner"

    prog = Program(statements=[stmt])
    code = CTranspiler(prog).emit()

    assert "while (true) {" in code
    assert "free(buf);" in code
    # No debe contener stubs
    assert "break;" not in code
    assert "Simulación" not in code
    assert "/* iterador */" not in code


def test_c_transpiler_for_loop_real():
    """Verifica que ForStatement genere un for(size_t) real en C con drops iterativos."""
    lst = ListLiteral(elements=[
        StringLiteral(value='"a"'),
        StringLiteral(value='"b"'),
    ])
    for_stmt = ForStatement(
        var="item",
        iterable=Identifier(name="mi_lista"),
        body=[
            Assignment(name="tmp", value=StringLiteral(value='"procesado"'))
        ]
    )
    for_stmt.meta["drops"] = ["tmp"]
    for_stmt.body[0].meta["memory_action"] = "BindOwner"

    prog = Program(statements=[for_stmt])
    code = CTranspiler(prog).emit()

    # Debe generar un for real con índice
    assert "for (size_t" in code
    assert "free(tmp);" in code
    # No debe contener stubs
    assert "break;" not in code
    assert "Simulación" not in code


def test_c_transpiler_global_drops():
    """Verifica que los drops globales se inyecten al final del programa."""
    assign = Assignment(name="global_data", value=StringLiteral(value='"owned"'))
    assign.meta["memory_action"] = "BindOwner"

    prog = Program(statements=[assign])
    prog.meta["drops"] = ["global_data"]
    code = CTranspiler(prog).emit()

    assert "free(global_data);" in code
    assert code.index("free(global_data);") < code.index("return 0;")


def test_c_transpiler_type_inference():
    """Verifica que la inferencia de tipos emita int para números, char* para strings."""
    prog = Program(statements=[
        Assignment(name="puerto", value=NumberLiteral(value=8080)),
        Assignment(name="host", value=StringLiteral(value='"target.com"')),
        Assignment(name="activo", value=BooleanLiteral(value=False)),
    ])
    for s in prog.statements:
        s.meta["memory_action"] = "BindOwner"

    code = CTranspiler(prog).emit()

    assert "int puerto = 8080;" in code
    assert 'char* host = strdup("target.com");' in code
    assert "bool activo = false;" in code


def test_c_transpiler_no_stubs():
    """Meta-test APE: verifica que el código generado NUNCA contenga marcadores de simulación."""
    prog = Program(statements=[
        WhileStatement(
            condition=BooleanLiteral(value=True),
            body=[Assignment(name="x", value=NumberLiteral(value=1))]
        ),
        ForStatement(
            var="i", iterable=Identifier(name="arr"),
            body=[Assignment(name="y", value=NumberLiteral(value=2))]
        ),
    ])
    for s in prog.statements:
        s.body[0].meta["memory_action"] = "BindOwner"

    code = CTranspiler(prog).emit()

    forbidden = ["TODO", "STUB", "MOCK", "Simulación", "simulación", "/* iterador */"]
    for word in forbidden:
        assert word not in code, f"Stub detectado en código C: '{word}'"


# ═══════════════════════════════════════════════════════════════════════════
# RUST TRANSPILER TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_rust_transpiler_arc_mutex():
    """Verifica Arc::new(Mutex::new()) y .lock().unwrap()."""
    val = StringLiteral(value='"10.0.0.1"')
    val.meta["lifetime"] = "ArcMutex"
    assign = Assignment(name="target", value=val)
    assign.meta["memory_action"] = "BindOwner"

    target_id = Identifier(name="target")
    target_id.meta["lifetime"] = "ArcMutex_Borrow"
    scan = CyberScan(target=target_id, ports=[NumberLiteral(value=80)])

    prog = Program(statements=[assign, scan])
    code = RustTranspiler(prog).emit()

    assert "Arc::new(Mutex::new(" in code
    assert "target.lock().unwrap()" in code


def test_rust_transpiler_task_handles():
    """Verifica colección de handles y .await masivo al final."""
    scan = CyberScan(target=StringLiteral(value='"10.0.0.1"'), ports=[NumberLiteral(value=80)])
    prog = Program(statements=[scan])
    code = RustTranspiler(prog).emit()

    assert "let mut _handles = vec![];" in code
    assert "_handles.push(tokio::spawn" in code
    assert "for h in _handles { h.await.unwrap(); }" in code
