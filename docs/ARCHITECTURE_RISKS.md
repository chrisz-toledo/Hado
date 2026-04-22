# Análisis de Riesgos Estructurales y Limitaciones Arquitectónicas (Hado V1.0)

Este documento detalla las fallas estructurales y los cuellos de botella inherentes a la arquitectura de Hado, identificados tras la finalización de la V1.0. Sirve como advertencia para futuros desarrollos y como justificación para el pivote hacia la Fase V2.0 (Agentes Autónomos).

## 1. Naturaleza de Transpilación (El Problema del "Wrapper")
**Riesgo:** Hado no es un compilador nativo (no genera bytecode ni assembly directamente), sino un transpilador (fuente a fuente) altamente especializado. Opera inyectando plantillas de código y librerías preexistentes (`libcurl`, `reqwest`, `tokio`).
**Impacto:** Su capacidad de generar ataques de ultra-bajo nivel (Zero-Days, ROP chains, inyección de shellcode directo en memoria) está fuertemente limitada por la abstracción de los lenguajes de destino y el boilerplate estático del compilador.
**Mitigación:** Aceptar que Hado es una **Capa de Orquestación (Intermediate Representation - IR)** para operaciones ofensivas de alto/medio nivel, no un lenguaje de desarrollo de exploits binarios.

## 2. Complejidad de Mantenimiento y Deuda Técnica Multilenguaje
**Riesgo:** Mantener paridad del AST en 9 lenguajes distintos (Python, Go, Rust, C, Bash, PowerShell, JS, Solidity, Arduino) es matemáticamente insostenible para equipos pequeños.
**Impacto (El problema de Rust):** El AST de Hado, pensado desde una óptica dinámica y "vibe-coding", colisiona severamente con modelos de memoria estrictos como el *borrow checker* de Rust o el manejo manual de C. Generar Rust idiomático y seguro desde un AST no tipado requiere inyectar miles de sentencias `.clone()`, `Arc<Mutex<T>>` y envolturas `anyhow` que destruyen el rendimiento y ensucian el código emitido.
**Mitigación:** Congelar los features del AST en la V1.0. No agregar más nodos sintácticos, sino enfocarse exclusivamente en estabilizar la semántica existente.

## 3. Fragilidad del Parser y Tolerancia a Fallos
**Riesgo:** El *Lexer* y *Parser* escritos en Python puro son frágiles ante desviaciones gramaticales, caracteres invisibles y sintaxis no estricta.
**Impacto:** La experiencia de desarrollo humano (DX) es frustrante. Un error de indentación, un símbolo `.` mal colocado o unas comillas tipográficas causan colapsos fatales en tiempo de compilación.
**Mitigación:** Hado **no debe ser programado por humanos**. La gramática estricta está diseñada para ser producida mecánicamente por Agentes LLM que pueden ajustarse perfectamente a una gramática determinista.

## 4. El Callejón de la Adopción (Target de Usuario Incorrecto)
**Riesgo:** Un pentester humano no tiene incentivos para abandonar Bash/Python a favor de un DSL experimental.
**Impacto:** Riesgo de adopción cero si se mercadea como una herramienta manual.
**Mitigación Estratégica (Pivote a V2.0):** El "cliente" de Hado no es el humano; es el **Agente IA**. Hado soluciona el problema del *token limit* y de la "alucinación de librerías" para los LLMs. Es mucho más barato y seguro que un LLM escupa 15 tokens de Hado (`escanea "10.0.0.1" en ports [80]`), que luego son traducidos localmente a 200 líneas perfectas de C/Rust, que pedirle al LLM que genere esas 200 líneas (lo cual consume tiempo de inferencia, costo en $$, y riesgo de errores de sintaxis en lenguajes complejos).

## 5. Peligro de "Feature Creep"
**Riesgo:** Intentar que Hado sirva para OSINT, auditoría Web3, hacking de hardware y desarrollo de malware simultáneamente.
**Impacto:** Dilución del producto y pérdida del principio de *cero fricción*.
**Mitigación:** Limitar el alcance a *Networking, Enumeración y Transporte de Datos*. No intentar agregar soporte sintáctico para manipulación de memoria bruta o criptografía a bajo nivel. Dejar que los comandos fileless (Bash/PS) o las integraciones externas manejen el trabajo sucio.
