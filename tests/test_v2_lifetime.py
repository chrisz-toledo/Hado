import pytest
from hado.ast_nodes import *
from hado.v2.lifetime import LifetimeAnalyzer, LifetimeError

def test_lifetime_basic_drops():
    """Prueba que los 'drops' (liberaciones de memoria) se registren al salir del scope."""
    ast = Program(statements=[
        IfStatement(
            condition=BooleanLiteral(value=True),
            then_body=[
                Assignment(name="temp1", value=NumberLiteral(value=1)),
                Assignment(name="temp2", value=NumberLiteral(value=2))
            ]
        )
    ])
    analyzer = LifetimeAnalyzer()
    analyzer.analyze(ast)
    
    # El nodo IfStatement deberia tener anotados los drops del then_body
    if_node = ast.statements[0]
    assert "then_drops" in if_node.meta
    assert "temp1" in if_node.meta["then_drops"]
    assert "temp2" in if_node.meta["then_drops"]

def test_lifetime_cyber_scan_arc_mutex():
    """Prueba la promoción a ArcMutex para concurrencia segura en operaciones de red."""
    ast = Program(statements=[
        Assignment(name="target_ip", value=StringLiteral(value='"10.0.0.1"')),
        CyberScan(
            target=Identifier(name="target_ip"),
            ports=[NumberLiteral(value=80)]
        )
    ])
    analyzer = LifetimeAnalyzer()
    analyzer.analyze(ast)
    
    # target_ip debe haber sido promovido a ArcMutex
    assert analyzer.current_scope.get_state("target_ip") == "ArcMutex"
    # El nodo Identifier dentro del CyberScan debe tener el meta correcto
    scan_node = ast.statements[1]
    assert scan_node.target.meta.get("lifetime") == "ArcMutex_Borrow"

def test_lifetime_use_after_move_ape():
    """Prueba APE: Forzamos un Move en CyberAttack y tratamos de usar la variable despues."""
    ast = Program(statements=[
        Assignment(name="wordlist", value=StringLiteral(value='"pass.txt"')),
        CyberAttack(
            target=StringLiteral(value='"10.0.0.1"'),
            wordlist=Identifier(name="wordlist"),
            username=StringLiteral(value='"admin"')
        ),
        # Intentamos leer la wordlist (Borrow) despues de que CyberAttack la movió y consumió
        ExpressionStatement(expr=Identifier(name="wordlist"))
    ])
    analyzer = LifetimeAnalyzer()
    
    with pytest.raises(LifetimeError, match="La variable 'wordlist' ha sido movida"):
        analyzer.analyze(ast)
