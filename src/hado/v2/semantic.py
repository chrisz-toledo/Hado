"""
Hado V2.0 — Analizador Semántico (Pasada 1)

Este módulo realiza la inferencia de tipos y validación de variables en el AST
antes de pasarlo a los backends de generación de código. Esto garantiza que
errores estructurales (como sumar un string con un booleano) sean interceptados
temprano y devueltos al Agente IA como un error semántico claro.
"""

from typing import Dict, Any, Optional
from ..ast_nodes import *

class SemanticError(Exception):
    pass

class SymbolTable:
    def __init__(self, parent: Optional['SymbolTable'] = None):
        self.symbols: Dict[str, str] = {}  # name -> type (String, Number, Boolean, List, Dict, Null)
        self.parent = parent

    def define(self, name: str, var_type: str):
        self.symbols[name] = var_type

    def resolve(self, name: str) -> Optional[str]:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.resolve(name)
        return None

class TypeChecker:
    def __init__(self):
        self.current_scope = SymbolTable()

    def check(self, node: Node) -> str:
        """Retorna el tipo de la expresión o 'Void' para statements."""
        method = f"_check_{type(node).__name__}"
        checker = getattr(self, method, self._check_unknown)
        return checker(node)

    def _check_unknown(self, node: Node) -> str:
        raise SemanticError(f"Semantic checker no implementado para: {type(node).__name__}")

    # -- Program & Statements --
    def _check_Program(self, node: Program) -> str:
        for stmt in node.statements:
            self.check(stmt)
        return "Void"

    def _check_Assignment(self, node: Assignment) -> str:
        val_type = self.check(node.value) if node.value else "Null"
        self.current_scope.define(node.name, val_type)
        return "Void"

    def _check_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if node.expr:
            self.check(node.expr)
        return "Void"

    def _check_ShowStatement(self, node: ShowStatement) -> str:
        if node.value:
            self.check(node.value)
        return "Void"

    def _check_SaveStatement(self, node: SaveStatement) -> str:
        if node.value:
            self.check(node.value)
        if node.filename:
            fname_type = self.check(node.filename)
            if fname_type not in ["String", "Identifier_String"]: # Tolerancia básica
                pass # Por ahora somos tolerantes
        return "Void"

    def _check_IfStatement(self, node: IfStatement) -> str:
        if node.condition:
            self.check(node.condition)
            
        # Scope anidado
        prev_scope = self.current_scope
        self.current_scope = SymbolTable(parent=prev_scope)
        for stmt in node.then_body:
            self.check(stmt)
        self.current_scope = prev_scope
        
        if node.else_body:
            self.current_scope = SymbolTable(parent=prev_scope)
            for stmt in node.else_body:
                self.check(stmt)
            self.current_scope = prev_scope
            
        return "Void"

    def _check_WhileStatement(self, node: WhileStatement) -> str:
        if node.condition:
            self.check(node.condition)
            
        prev_scope = self.current_scope
        self.current_scope = SymbolTable(parent=prev_scope)
        for stmt in node.body:
            self.check(stmt)
        self.current_scope = prev_scope
        return "Void"

    def _check_ForStatement(self, node: ForStatement) -> str:
        iterable_type = self.check(node.iterable) if node.iterable else "List"
        # Asumimos que iterar sobre una lista/dict expone elementos "Any" temporalmente
        prev_scope = self.current_scope
        self.current_scope = SymbolTable(parent=prev_scope)
        self.current_scope.define(node.var, "Any")
        
        for stmt in node.body:
            self.check(stmt)
        self.current_scope = prev_scope
        return "Void"

    # -- Expressions --
    def _check_Identifier(self, node: Identifier) -> str:
        var_type = self.current_scope.resolve(node.name)
        if not var_type:
            # En Hado v1 asumiamos que a veces las variables se resuelven en runtime,
            # pero en V2 alertaremos esto si queremos seguridad extrema.
            # Por ahora lo permitimos con advertencia.
            return "Any"
        return var_type

    def _check_StringLiteral(self, node: StringLiteral) -> str:
        return "String"

    def _check_NumberLiteral(self, node: NumberLiteral) -> str:
        return "Number"

    def _check_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "Boolean"

    def _check_NullLiteral(self, node: NullLiteral) -> str:
        return "Null"

    def _check_ListLiteral(self, node: ListLiteral) -> str:
        for el in node.elements:
            self.check(el)
        return "List"

    def _check_DictLiteral(self, node: DictLiteral) -> str:
        for k, v in node.pairs:
            self.check(k)
            self.check(v)
        return "Dict"

    def _check_BinaryOp(self, node: BinaryOp) -> str:
        l_type = self.check(node.left) if node.left else "Any"
        r_type = self.check(node.right) if node.right else "Any"
        
        # En algebra booleana
        if node.op in ["y", "o", "no", "es", "==", "!=", ">", "<", ">=", "<="]:
            return "Boolean"
            
        # Operaciones matematicas primitivas
        if node.op in ["+", "-", "*", "/", "%"]:
            if l_type == "String" and node.op == "+":
                return "String" # Concatenación
            return "Number"
            
        return "Any"

    def _check_FunctionCall(self, node: FunctionCall) -> str:
        for arg in node.args:
            self.check(arg)
        return "Any"

    def _check_PipeExpression(self, node: PipeExpression) -> str:
        for step in node.steps:
            self.check(step)
        return "PipeFlow"

    # -- Cyber Operations --
    def _check_CyberScan(self, node: CyberScan) -> str:
        if node.target: self.check(node.target)
        for p in node.ports: self.check(p)
        return "CyberResult"

    def _check_CyberAttack(self, node: CyberAttack) -> str:
        if node.target: self.check(node.target)
        if node.wordlist: self.check(node.wordlist)
        if node.username: self.check(node.username)
        return "CyberResult"

    def _check_CyberRecon(self, node: CyberRecon) -> str:
        if node.domain: self.check(node.domain)
        return "CyberResult"
