import pytest
from hado.ast_nodes import *
from hado.v2.semantic import TypeChecker, SemanticError

def test_semantic_variable_resolution():
    """Testea que una variable asignada adquiera un tipo en la tabla de simbolos."""
    ast = Program(statements=[
        Assignment(name="edad", value=NumberLiteral(value=25)),
        ExpressionStatement(expr=Identifier(name="edad"))
    ])
    
    checker = TypeChecker()
    checker.check(ast)
    
    # Verificamos que se haya registrado en el scope
    assert checker.current_scope.resolve("edad") == "Number"

def test_semantic_binary_op_types():
    """Testea la inferencia de tipos de operaciones binarias."""
    ast = BinaryOp(op="+", left=NumberLiteral(value=10), right=NumberLiteral(value=20))
    checker = TypeChecker()
    
    res_type = checker.check(ast)
    assert res_type == "Number"
    
    ast_bool = BinaryOp(op="y", left=BooleanLiteral(value=True), right=BooleanLiteral(value=False))
    res_type_bool = checker.check(ast_bool)
    assert res_type_bool == "Boolean"

def test_semantic_scope_isolation():
    """Testea que los scopes anidados (bloques if/while) no filtren variables temporales hacia arriba,
       o que si se declaran globalmente, puedan usarse."""
    ast = Program(statements=[
        IfStatement(
            condition=BooleanLiteral(value=True),
            then_body=[
                Assignment(name="temp", value=StringLiteral(value='"hola"'))
            ]
        )
    ])
    checker = TypeChecker()
    checker.check(ast)
    
    # "temp" fue declarada dentro del If, no debería existir en el scope global actual
    assert checker.current_scope.resolve("temp") is None

def test_semantic_unsupported_node():
    """Test APE: Probamos que si pasamos un nodo basura, lanza un SemanticError claro."""
    class BasuraNode(Node):
        pass
        
    checker = TypeChecker()
    with pytest.raises(SemanticError, match="Semantic checker no implementado para: BasuraNode"):
        checker.check(BasuraNode())
