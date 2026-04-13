"""
Habla DSL — Parser de descenso recursivo.
Convierte una secuencia de tokens en un AST.
"""

from __future__ import annotations
from typing import List, Optional

from .lexer import Token, TokenType
from .ast_nodes import *
from .errors import ParseError, IncompleteError, fmt


class Parser:
    def __init__(self, tokens: List[Token], filename: str = "<input>"):
        self.tokens = tokens
        self.pos = 0
        self.filename = filename

    # ─── Primitivas de navegacion ─────────────────────────────────────────────

    def current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TokenType.EOF, "", 0, 0)

    def peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return Token(TokenType.EOF, "", 0, 0)

    def consume(self) -> Token:
        tok = self.current()
        self.pos += 1
        return tok

    def expect(self, ttype: TokenType, value: str = None) -> Token:
        tok = self.current()
        if tok.type != ttype:
            if ttype == TokenType.INDENT and tok.type == TokenType.EOF:
                raise IncompleteError("Bloque incompleto", tok.line, tok.col, self.filename)
            raise ParseError(
                fmt("expected_token", expected=ttype.name, found=tok.value or tok.type.name, line=tok.line),
                tok.line, tok.col, self.filename,
            )
        if value is not None and tok.value != value:
            raise ParseError(
                fmt("expected_token", expected=value, found=tok.value, line=tok.line),
                tok.line, tok.col, self.filename,
            )
        return self.consume()

    def match(self, *types_or_values) -> bool:
        tok = self.current()
        for tv in types_or_values:
            if isinstance(tv, TokenType):
                if tok.type == tv:
                    return True
            elif isinstance(tv, str):
                if tok.value == tv:
                    return True
        return False

    def skip_newlines(self):
        while self.match(TokenType.NEWLINE):
            self.consume()

    def current_value(self) -> str:
        """Retorna el valor del token actual (independiente de si es KEYWORD o IDENTIFIER)."""
        return self.current().value

    def match_value(self, *values: str) -> bool:
        """True si el token actual tiene alguno de los valores especificados."""
        return self.current().value in values

    # ─── Punto de entrada ─────────────────────────────────────────────────────

    def parse(self) -> Program:
        self.skip_newlines()
        statements = []
        while not self.match(TokenType.EOF):
            self.skip_newlines()
            if self.match(TokenType.EOF):
                break
            stmt = self.parse_statement()
            if stmt is not None:
                statements.append(stmt)
        return Program(statements=statements)

    # ─── Statements ──────────────────────────────────────────────────────────

    def parse_statement(self) -> Optional[Node]:
        tok = self.current()

        if tok.type == TokenType.NEWLINE:
            self.consume()
            return None

        line = tok.line

        # fn definicion
        if tok.type == TokenType.KEYWORD and tok.value == "fn":
            return self.parse_fn_def()

        # si / sino
        if tok.type == TokenType.KEYWORD and tok.value == "si":
            return self.parse_if()

        # mientras
        if tok.type == TokenType.KEYWORD and tok.value == "mientras":
            return self.parse_while()

        # para / cada
        if tok.type == TokenType.KEYWORD and tok.value in ("para", "cada"):
            return self.parse_for()

        # devuelve
        if tok.type == TokenType.KEYWORD and tok.value == "devuelve":
            self.consume()
            val = self.parse_expr()
            self._consume_newline()
            return ReturnStatement(value=val, line=line)

        # muestra
        if tok.type == TokenType.KEYWORD and tok.value == "muestra":
            self.consume()
            val = self.parse_expr()
            self._consume_newline()
            return ShowStatement(value=val, line=line)

        # guarda
        if tok.type == TokenType.KEYWORD and tok.value == "guarda":
            return self.parse_save()

        # lee
        if tok.type == TokenType.KEYWORD and tok.value == "lee":
            self.consume()
            fname = self.parse_expr()
            self._consume_newline()
            return ReadStatement(filename=fname, line=line)

        # escanea
        if tok.type == TokenType.KEYWORD and tok.value == "escanea":
            return self._maybe_pipe_chain(self.parse_cyber_scan())

        # busca
        if tok.type == TokenType.KEYWORD and tok.value == "busca":
            return self._maybe_pipe_chain(self.parse_busca())

        # captura
        if tok.type == TokenType.KEYWORD and tok.value == "captura":
            return self._maybe_pipe_chain(self.parse_capture())

        # ataca
        if tok.type == TokenType.KEYWORD and tok.value == "ataca":
            return self._maybe_pipe_chain(self.parse_attack())

        # genera
        if tok.type == TokenType.KEYWORD and tok.value == "genera":
            return self._maybe_pipe_chain(self.parse_genera())

        # analiza
        if tok.type == TokenType.KEYWORD and tok.value == "analiza":
            return self._maybe_pipe_chain(self.parse_analiza())

        # Asignacion: IDENT = expr o keyword-como-variable = expr (lookahead)
        # Solo triggerea si el siguiente token es '=' (operador de asignacion, no '==')
        if (tok.type in (TokenType.IDENTIFIER, TokenType.KEYWORD)
                and self.peek().type == TokenType.OPERATOR
                and self.peek().value == "="):
            return self.parse_assignment()

        # Expression statement (puede ser pipe chain)
        expr = self.parse_expr()
        self._consume_newline()
        return ExpressionStatement(expr=expr, line=line)

    def _consume_newline(self):
        if self.match(TokenType.NEWLINE):
            self.consume()

    def _maybe_pipe_chain(self, stmt: Node) -> Node:
        """
        Si el token actual es PIPE (-> o |), envuelve la expresion del stmt
        en un PipeExpression con los pasos siguientes.
        Permite usar | o -> despues de cualquier verbo cyber a nivel de statement.
        """
        if not self.match(TokenType.PIPE):
            return stmt
        # Extraer la expresion del ExpressionStatement
        expr = stmt.expr if isinstance(stmt, ExpressionStatement) else stmt
        line = expr.line
        steps = [expr]
        while self.match(TokenType.PIPE):
            self.consume()
            step = self.parse_pipe_step()
            steps.append(step)
        pipe_expr = PipeExpression(steps=steps, line=line)
        self._consume_newline()
        return ExpressionStatement(expr=pipe_expr, line=line)

    # ─── Bloques ─────────────────────────────────────────────────────────────

    def parse_block(self) -> List[Node]:
        """Parsea un bloque indentado. Espera INDENT ... DEDENT."""
        self.expect(TokenType.INDENT)
        stmts = []
        while not self.match(TokenType.DEDENT, TokenType.EOF):
            self.skip_newlines()
            if self.match(TokenType.DEDENT, TokenType.EOF):
                break
            stmt = self.parse_statement()
            if stmt is not None:
                stmts.append(stmt)
        if self.match(TokenType.DEDENT):
            self.consume()
        return stmts

    # ─── Control de flujo ────────────────────────────────────────────────────

    def parse_fn_def(self) -> FunctionDef:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "fn")
        name_tok = self.expect(TokenType.IDENTIFIER)
        name = name_tok.value

        # Params opcionales: fn nombre param1 param2
        params = []
        if self.match(TokenType.LPAREN):
            self.consume()
            while not self.match(TokenType.RPAREN, TokenType.EOF):
                if self.match(TokenType.IDENTIFIER):
                    params.append(self.consume().value)
                elif self.match(TokenType.COMMA):
                    self.consume()
                else:
                    break
            if self.match(TokenType.RPAREN):
                self.consume()
        else:
            # Params sin parentesis: fn nombre a b c
            while self.match(TokenType.IDENTIFIER) and not self.match(TokenType.NEWLINE):
                params.append(self.consume().value)

        self.skip_newlines()
        body = self.parse_block()
        return FunctionDef(name=name, params=params, body=body, line=line)

    def parse_if(self) -> IfStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "si")
        cond = self.parse_expr()
        self.skip_newlines()
        then_body = self.parse_block()

        self.skip_newlines()
        else_body = []
        if self.match(TokenType.KEYWORD) and self.current().value == "sino":
            self.consume()
            self.skip_newlines()
            else_body = self.parse_block()

        return IfStatement(condition=cond, then_body=then_body, else_body=else_body, line=line)

    def parse_while(self) -> WhileStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "mientras")
        cond = self.parse_expr()
        self.skip_newlines()
        body = self.parse_block()
        return WhileStatement(condition=cond, body=body, line=line)

    def parse_for(self) -> ForStatement:
        line = self.current().line
        self.consume()  # para / cada
        # Soporte para 'para cada x en ...' (consume el segundo keyword)
        if self.match_value("cada"):
            self.consume()
        # La variable del loop puede ser IDENTIFIER o KEYWORD usado como nombre
        tok = self.current()
        if tok.type not in (TokenType.IDENTIFIER, TokenType.KEYWORD):
            raise ParseError(
                fmt("expected_token", expected="IDENTIFIER", found=tok.value or tok.type.name, line=tok.line),
                tok.line, tok.col, self.filename,
            )
        var = self.consume().value
        # Consumir 'en' o 'in'
        if self.match_value("en", "in"):
            self.consume()
        iterable = self.parse_expr()
        self.skip_newlines()
        body = self.parse_block()
        return ForStatement(var=var, iterable=iterable, body=body, line=line)

    # ─── Asignacion ──────────────────────────────────────────────────────────

    def parse_assignment(self) -> Assignment:
        line = self.current().line
        name = self.consume().value  # IDENTIFIER o KEYWORD usado como variable
        self.expect(TokenType.OPERATOR, "=")
        value = self.parse_expr()
        self._consume_newline()
        return Assignment(name=name, value=value, line=line)

    # ─── Cyber statements ────────────────────────────────────────────────────

    def parse_save(self) -> SaveStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "guarda")

        # Formas soportadas:
        #   guarda "archivo"                  -> value=None, filename="archivo"
        #   guarda variable en "archivo"      -> value=variable, filename="archivo"
        #   guarda variable a "archivo"       -> idem
        #
        # IMPORTANTE: usamos parse_postfix() (no parse_expr()) para el valor,
        # evitando que 'en' sea consumido como operador binario 'in'.
        val = self.parse_postfix()
        filename = None
        if self.match_value("en", "a"):
            self.consume()
            filename = self.parse_primary()
        self._consume_newline()
        return SaveStatement(value=val, filename=filename, line=line)

    def parse_cyber_scan(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "escanea")

        # Caso 1: escanea ports de target  →  scan con ports por defecto
        if self.current().value == "ports" and self.peek().value == "de":
            self.consume()  # ports
            self.consume()  # de
            target = self.parse_primary()
            default_ports = [
                NumberLiteral(value=p, line=line)
                for p in [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
            ]
            self._consume_newline()
            node = CyberScan(target=target, ports=default_ports, line=line)
            return ExpressionStatement(expr=node, line=line)

        # Caso 2: escanea target "ip" en ports [22, 80]
        # escanea target "192.168.1.1" -> consume 'target', luego parsea string
        # escanea mi_var en ports [...]  -> 'mi_var' es la variable directamente
        tok_now = self.current()
        if tok_now.value == "target" and self.peek().type == TokenType.STRING:
            self.consume()  # consume el literal 'target'

        target = self.parse_primary()

        # Consumir 'en ports' o 'en'
        ports = []
        if self.current().value == "en":
            self.consume()
            if self.current().value == "ports":
                self.consume()
            if self.match(TokenType.LBRACKET):
                ports_list = self.parse_list_literal()
                ports = ports_list.elements
            else:
                ports.append(self.parse_primary())

        self._consume_newline()
        node = CyberScan(target=target, ports=ports, line=line)
        return ExpressionStatement(expr=node, line=line)

    def parse_busca(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "busca")
        tok = self.current()

        # busca subdomains de "dominio"
        if tok.value == "subdomains":
            self.consume()
            if self.match_value("de"):
                self.consume()
            domain = self.parse_primary()
            self._consume_newline()
            return ExpressionStatement(expr=CyberRecon(domain=domain, line=line), line=line)

        # busca vulns en target donde severity >= HIGH
        if tok.value == "vulns":
            self.consume()
            if self.match_value("en"):
                self.consume()
            target = self.parse_primary()
            severity = None
            if self.match_value("donde"):
                self.consume()
                severity = self.parse_expr()
            self._consume_newline()
            return ExpressionStatement(expr=CyberFindVulns(target=target, severity=severity, line=line), line=line)

        # busca hash h en "api.hashes.org"
        # Fallback: expresion generica
        expr = self.parse_expr()
        self._consume_newline()
        return ExpressionStatement(expr=expr, line=line)

    def parse_capture(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "captura")

        # captura packets en interface "eth0" donde port == 443
        if self.match_value("packets"):
            self.consume()

        interface = None
        filter_expr = None

        if self.match_value("en"):
            self.consume()
            if self.match_value("interface"):
                self.consume()
            interface = self.parse_primary()

        if self.match_value("donde"):
            self.consume()
            filter_expr = self.parse_expr()

        self._consume_newline()
        node = CyberCapture(interface=interface, filter_expr=filter_expr, line=line)
        return ExpressionStatement(expr=node, line=line)

    def parse_attack(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "ataca")

        # ataca ssh en target con wordlist "rockyou.txt"
        # ataca ssh en target con usuario y wordlist "rockyou.txt"
        service = self.parse_primary()
        target = None
        username = None
        wordlist = None

        if self.match_value("en"):
            self.consume()
            target = self.parse_primary()

        if self.match_value("con"):
            self.consume()
            # con usuario X y wordlist Y / con wordlist Y
            if self.match_value("usuario"):
                self.consume()
                username = self.parse_primary()
                if self.match_value("y"):
                    self.consume()
            if self.match_value("wordlist"):
                self.consume()
            wordlist = self.parse_primary()

        self._consume_newline()
        node = CyberAttack(service=service, target=target, username=username, wordlist=wordlist, line=line)
        return ExpressionStatement(expr=node, line=line)

    def parse_genera(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "genera")

        # genera reporte / genera report  (ambos alias aceptados)
        if self.match_value("reporte") or self.match_value("report"):
            self.consume()
        data = None
        if self.match_value("con"):
            self.consume()
            # Recoger argumentos separados por coma: genera reporte con a, b, c
            args = [self.parse_primary()]
            while self.match(TokenType.COMMA):
                self.consume()
                args.append(self.parse_primary())
            data = ListLiteral(elements=args, line=line) if len(args) > 1 else args[0]
        self._consume_newline()
        return ExpressionStatement(expr=GenerateReport(data=data, line=line), line=line)

    def parse_analiza(self) -> ExpressionStatement:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "analiza")

        # analiza headers de target
        mode = "auto"
        if self.match_value("headers"):
            self.consume()
            mode = "headers"
        if self.match_value("de"):
            self.consume()
        source = self.parse_primary()
        self._consume_newline()
        return ExpressionStatement(expr=CyberAnalyze(source=source, mode=mode, line=line), line=line)

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def parse_expr(self) -> Node:
        return self.parse_pipe_or_binary()

    def parse_pipe_or_binary(self) -> Node:
        left = self.parse_binary()

        if self.match(TokenType.PIPE):
            steps = [left]
            while self.match(TokenType.PIPE):
                self.consume()
                step = self.parse_pipe_step()
                steps.append(step)
            return PipeExpression(steps=steps, line=left.line)

        return left

    def parse_pipe_step(self) -> Node:
        tok = self.current()

        # filtra donde cond
        if tok.type == TokenType.KEYWORD and tok.value == "filtra":
            return self.parse_filter_step()

        # ordena por campo
        if tok.type == TokenType.KEYWORD and tok.value == "ordena":
            return self.parse_sort_step()

        # cuenta
        if tok.type == TokenType.KEYWORD and tok.value == "cuenta":
            self.consume()
            return CountExpression(line=tok.line)

        # muestra (terminal)
        if tok.type == TokenType.KEYWORD and tok.value == "muestra":
            self.consume()
            return ShowStatement(value=None, line=tok.line)

        # guarda "archivo" (terminal)
        if tok.type == TokenType.KEYWORD and tok.value == "guarda":
            self.consume()
            fname = self.parse_primary()
            return SaveStatement(value=None, filename=fname, line=tok.line)

        # genera reporte
        if tok.type == TokenType.KEYWORD and tok.value == "genera":
            self.consume()
            if self.match_value("reporte"):
                self.consume()
            return GenerateReport(line=tok.line)

        # escanea ports
        if tok.type == TokenType.KEYWORD and tok.value == "escanea":
            return self.parse_cyber_scan_inline()

        # busca vulns
        if tok.type == TokenType.KEYWORD and tok.value == "busca":
            return self.parse_busca_inline()

        return self.parse_binary()

    def parse_filter_step(self) -> FilterExpression:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "filtra")

        # filtra alive (especial)
        if self.match_value("alive"):
            self.consume()
            return FilterExpression(
                iterable=None,
                condition=Identifier(name="_x", line=line),
                var="_x",
                line=line,
            )

        if self.match_value("donde"):
            self.consume()

        cond = self.parse_binary()
        return FilterExpression(iterable=None, condition=cond, var="_x", line=line)

    def parse_sort_step(self) -> SortExpression:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "ordena")
        if self.match_value("por"):
            self.consume()
        key = self.parse_primary()
        return SortExpression(source=None, key=key, line=line)

    def parse_cyber_scan_inline(self) -> CyberScan:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "escanea")
        if self.match_value("target") and self.peek().type == TokenType.STRING:
            self.consume()
        target = self.parse_primary()
        ports = []
        if self.match_value("en"):
            self.consume()
            if self.match_value("ports"):
                self.consume()
            if self.match(TokenType.LBRACKET):
                ports_list = self.parse_list_literal()
                ports = ports_list.elements
        return CyberScan(target=target, ports=ports, line=line)

    def parse_busca_inline(self) -> Node:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "busca")
        if self.match_value("vulns"):
            self.consume()
            target = None
            if self.match_value("en"):
                self.consume()
                target = self.parse_primary()
            return CyberFindVulns(target=target, line=line)
        return self.parse_binary()

    def parse_binary(self) -> Node:
        left = self.parse_unary()

        while True:
            tok = self.current()
            if tok.type == TokenType.OPERATOR and tok.value in ("==", "!=", ">=", "<=", ">", "<", "+", "-", "*", "/", "%"):
                op = self.consume().value
                right = self.parse_unary()
                left = BinaryOp(op=op, left=left, right=right, line=tok.line)
            elif tok.type == TokenType.KEYWORD and tok.value in ("y", "o", "es"):
                op = self.consume().value
                right = self.parse_unary()
                left = BinaryOp(op=op, left=left, right=right, line=tok.line)
            elif tok.type == TokenType.KEYWORD and tok.value == "en":
                # x en lista
                op = self.consume().value
                right = self.parse_unary()
                left = BinaryOp(op="in", left=left, right=right, line=tok.line)
            else:
                break

        return left

    def parse_unary(self) -> Node:
        tok = self.current()
        if tok.type == TokenType.KEYWORD and tok.value == "no":
            self.consume()
            operand = self.parse_unary()
            return UnaryOp(op="no", operand=operand, line=tok.line)
        if tok.type == TokenType.OPERATOR and tok.value == "-":
            self.consume()
            operand = self.parse_unary()
            return UnaryOp(op="-", operand=operand, line=tok.line)
        return self.parse_postfix()

    def parse_postfix(self) -> Node:
        node = self.parse_primary()

        while True:
            tok = self.current()
            if tok.type == TokenType.DOT:
                self.consume()
                prop = self.expect(TokenType.IDENTIFIER).value
                node = PropertyAccess(obj=node, prop=prop, line=tok.line)
            elif tok.type == TokenType.LBRACKET:
                self.consume()
                idx = self.parse_expr()
                self.expect(TokenType.RBRACKET)
                node = IndexAccess(obj=node, index=idx, line=tok.line)
            elif tok.type == TokenType.LPAREN:
                # Llamada a funcion
                self.consume()
                args = []
                while not self.match(TokenType.RPAREN, TokenType.EOF):
                    args.append(self.parse_expr())
                    if self.match(TokenType.COMMA):
                        self.consume()
                self.expect(TokenType.RPAREN)
                if isinstance(node, Identifier):
                    node = FunctionCall(func=node.name, args=args, line=tok.line)
                else:
                    node = FunctionCall(func=str(node), args=args, line=tok.line)
            else:
                break

        return node

    def parse_primary(self) -> Node:
        tok = self.current()

        # Literales
        if tok.type == TokenType.NUMBER:
            self.consume()
            val = float(tok.value) if "." in tok.value else int(tok.value)
            return NumberLiteral(value=val, line=tok.line)

        if tok.type == TokenType.STRING:
            self.consume()
            return StringLiteral(value=tok.value, line=tok.line)

        if tok.type == TokenType.KEYWORD and tok.value == "cierto":
            self.consume()
            return BooleanLiteral(value=True, line=tok.line)

        if tok.type == TokenType.KEYWORD and tok.value == "falso":
            self.consume()
            return BooleanLiteral(value=False, line=tok.line)

        if tok.type == TokenType.KEYWORD and tok.value in ("nulo", "vacio"):
            self.consume()
            return NullLiteral(line=tok.line)

        # Lista
        if tok.type == TokenType.LBRACKET:
            return self.parse_list_literal()

        # Dict
        if tok.type == TokenType.LBRACE:
            return self.parse_dict_literal()

        # Parentesis
        if tok.type == TokenType.LPAREN:
            self.consume()
            expr = self.parse_expr()
            self.expect(TokenType.RPAREN)
            return expr

        # desde "url" [con headers {...}]
        if tok.type == TokenType.KEYWORD and tok.value == "desde":
            return self.parse_desde()

        # ─── Verbos cyber en contexto de expresion ──────────────────────────
        # Permiten: subs = busca subdomains de dom
        #           n = cuenta lista
        #           resultado = escanea "ip" en ports [22, 80]

        if tok.type == TokenType.KEYWORD and tok.value == "busca":
            return self._parse_busca_expr()

        if tok.type == TokenType.KEYWORD and tok.value == "cuenta":
            self.consume()
            # cuenta X — el argumento es la siguiente expresion primaria
            src = self.parse_primary() if not self.match(TokenType.NEWLINE, TokenType.EOF) else None
            return CountExpression(source=src, line=tok.line)

        if tok.type == TokenType.KEYWORD and tok.value == "escanea":
            return self.parse_cyber_scan_inline()

        if tok.type == TokenType.KEYWORD and tok.value == "analiza":
            return self._parse_analiza_expr()

        if tok.type == TokenType.KEYWORD and tok.value == "genera":
            self.consume()
            if self.match_value("reporte"):
                self.consume()
            data = None
            if self.match_value("con"):
                self.consume()
                data = self.parse_primary()
            return GenerateReport(data=data, line=tok.line)

        # Identifier o keyword usado como identifier
        if tok.type in (TokenType.IDENTIFIER, TokenType.KEYWORD):
            self.consume()
            return Identifier(name=tok.value, line=tok.line)

        raise ParseError(
            fmt("unexpected_token", token=tok.value or tok.type.name, line=tok.line, suggestion="una expresion"),
            tok.line, tok.col, self.filename,
        )

    def _parse_busca_expr(self) -> Node:
        """busca subdomains de X  /  busca vulns en X  — en contexto de expresion."""
        line = self.current().line
        self.consume()  # consume 'busca'
        tok = self.current()
        if tok.value == "subdomains":
            self.consume()
            if self.match_value("de"):
                self.consume()
            domain = self.parse_primary()
            return CyberRecon(domain=domain, line=line)
        if tok.value == "vulns":
            self.consume()
            target = None
            severity = None
            if self.match_value("en"):
                self.consume()
                target = self.parse_primary()
            if self.match_value("donde"):
                self.consume()
                severity = self.parse_binary()
            return CyberFindVulns(target=target, severity=severity, line=line)
        # Fallback: 'busca' como identificador
        return Identifier(name="busca", line=line)

    def _parse_analiza_expr(self) -> Node:
        """analiza headers de X  — en contexto de expresion."""
        line = self.current().line
        self.consume()  # consume 'analiza'
        mode = "auto"
        if self.match_value("headers"):
            self.consume()
            mode = "headers"
        if self.match_value("de"):
            self.consume()
        source = self.parse_primary()
        return CyberAnalyze(source=source, mode=mode, line=line)

    def parse_desde(self) -> HttpGet:
        line = self.current().line
        self.expect(TokenType.KEYWORD, "desde")
        url = self.parse_primary()
        headers = None
        if self.match_value("con"):
            self.consume()
            if self.match_value("headers"):
                self.consume()
            headers = self.parse_primary()
        return HttpGet(url=url, headers=headers, line=line)

    def parse_list_literal(self) -> ListLiteral:
        line = self.current().line
        self.expect(TokenType.LBRACKET)
        elements = []
        while not self.match(TokenType.RBRACKET, TokenType.EOF):
            self.skip_newlines()
            if self.match(TokenType.RBRACKET):
                break
            elements.append(self.parse_expr())
            if self.match(TokenType.COMMA):
                self.consume()
        self.expect(TokenType.RBRACKET)
        return ListLiteral(elements=elements, line=line)

    def parse_dict_literal(self) -> DictLiteral:
        line = self.current().line
        self.expect(TokenType.LBRACE)
        pairs = []
        while not self.match(TokenType.RBRACE, TokenType.EOF):
            self.skip_newlines()
            if self.match(TokenType.RBRACE):
                break
            key = self.parse_primary()
            self.expect(TokenType.COLON)
            val = self.parse_expr()
            pairs.append((key, val))
            if self.match(TokenType.COMMA):
                self.consume()
        self.expect(TokenType.RBRACE)
        return DictLiteral(pairs=pairs, line=line)
