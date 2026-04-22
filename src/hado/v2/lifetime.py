"""
Hado V2.0 — Analizador de Ciclo de Vida y Memoria (Pasada 2)

Este módulo implementa "Lifetime Analysis" al estilo Rust. 
Inyecta metadatos en el AST (`meta`) para domar al Borrow Checker en Rust
y dictar exactamente dónde insertar `free()` en C.
"""

from typing import Dict, List, Optional, Set
from ..ast_nodes import *

class LifetimeError(Exception):
    """Error cuando se viola el ciclo de vida de la memoria (ej. uso después de Move)."""
    pass

class LifetimeScope:
    def __init__(self, parent: Optional['LifetimeScope'] = None):
        # variable -> estado (Owner, Borrow, ArcMutex, Moved)
        self.variables: Dict[str, str] = {}
        self.parent = parent

    def define(self, name: str):
        self.variables[name] = "Owner"

    def update_state(self, name: str, state: str):
        if name in self.variables:
            self.variables[name] = state
        elif self.parent:
            self.parent.update_state(name, state)
        else:
            raise LifetimeError(f"Variable '{name}' no existe en este contexto de memoria.")

    def get_state(self, name: str) -> str:
        if name in self.variables:
            return self.variables[name]
        if self.parent:
            return self.parent.get_state(name)
        raise LifetimeError(f"Variable '{name}' no rastreada en memoria.")

    def get_locals(self) -> List[str]:
        return list(self.variables.keys())

class LifetimeAnalyzer:
    def __init__(self):
        self.current_scope = LifetimeScope()

    def analyze(self, node: Node):
        method = f"_analyze_{type(node).__name__}"
        analyzer = getattr(self, method, self._analyze_children)
        analyzer(node)

    def _analyze_children(self, node: Node):
        """Si el nodo no tiene lógica especial de memoria, analizamos sus hijos si los tiene."""
        for field_name, value in node.__dict__.items():
            if field_name == "meta":
                continue
            if isinstance(value, Node):
                self.analyze(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, Node):
                        self.analyze(item)

    # -- Program & Statements --
    def _analyze_Program(self, node: Program):
        for stmt in node.statements:
            self.analyze(stmt)
        # Drops al final del programa
        node.meta["drops"] = self.current_scope.get_locals()

    def _analyze_Assignment(self, node: Assignment):
        if node.value:
            self.analyze(node.value)
        # Si la variable ya existe, es una reasignación (mutación). Si no, es un nuevo Owner.
        try:
            state = self.current_scope.get_state(node.name)
            node.meta["memory_action"] = "Mutate"
        except LifetimeError:
            self.current_scope.define(node.name)
            node.meta["memory_action"] = "BindOwner"

    def _analyze_IfStatement(self, node: IfStatement):
        if node.condition:
            self.analyze(node.condition)

        # Analizar then_body
        prev_scope = self.current_scope
        self.current_scope = LifetimeScope(parent=prev_scope)
        for stmt in node.then_body:
            self.analyze(stmt)
        node.meta["then_drops"] = self.current_scope.get_locals()
        self.current_scope = prev_scope

        # Analizar else_body
        if node.else_body:
            self.current_scope = LifetimeScope(parent=prev_scope)
            for stmt in node.else_body:
                self.analyze(stmt)
            node.meta["else_drops"] = self.current_scope.get_locals()
            self.current_scope = prev_scope

    def _analyze_WhileStatement(self, node: WhileStatement):
        if node.condition:
            self.analyze(node.condition)
        
        prev_scope = self.current_scope
        self.current_scope = LifetimeScope(parent=prev_scope)
        for stmt in node.body:
            self.analyze(stmt)
        node.meta["drops"] = self.current_scope.get_locals()
        self.current_scope = prev_scope

    def _analyze_ForStatement(self, node: ForStatement):
        if node.iterable:
            self.analyze(node.iterable)
            
        prev_scope = self.current_scope
        self.current_scope = LifetimeScope(parent=prev_scope)
        self.current_scope.define(node.var)
        for stmt in node.body:
            self.analyze(stmt)
        node.meta["drops"] = self.current_scope.get_locals()
        self.current_scope = prev_scope

    # -- Expressions --
    def _analyze_Identifier(self, node: Identifier):
        state = self.current_scope.get_state(node.name)
        if state == "Moved":
            raise LifetimeError(f"La variable '{node.name}' ha sido movida (Moved) y no puede ser utilizada de nuevo sin ser clonada.")
        # Uso normal es un Borrow (préstamo)
        node.meta["lifetime"] = "Borrow"

    # -- Cyber Operations (Concurrency Boundaries) --
    def _analyze_CyberScan(self, node: CyberScan):
        """CyberScan genera tareas asincronas. Las variables inyectadas deben ser promovidas a ArcMutex."""
        self._analyze_children(node)
        
        if node.target and isinstance(node.target, Identifier):
            self._promote_to_arc_mutex(node.target.name)
            node.target.meta["lifetime"] = "ArcMutex_Borrow"
            
        for port in node.ports:
            if isinstance(port, Identifier):
                self._promote_to_arc_mutex(port.name)
                port.meta["lifetime"] = "ArcMutex_Borrow"

    def _analyze_CyberAttack(self, node: CyberAttack):
        """CyberAttack es destructivo y transfiere el hilo de ejecución principal en algunos backends.
        Modelamos esto como un 'Move' destructivo (Rust move semantics) para la wordlist."""
        self._analyze_children(node)
        
        if node.wordlist and isinstance(node.wordlist, Identifier):
            self.current_scope.update_state(node.wordlist.name, "Moved")
            node.wordlist.meta["lifetime"] = "Moved"

    def _promote_to_arc_mutex(self, name: str):
        state = self.current_scope.get_state(name)
        if state == "Moved":
            raise LifetimeError(f"No se puede promover '{name}' a concurrencia; ya ha sido movida.")
        self.current_scope.update_state(name, "ArcMutex")
