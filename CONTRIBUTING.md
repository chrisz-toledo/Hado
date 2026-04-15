# Contribuir a Hado

Gracias por tu interés en contribuir a Hado.

## Setup

```bash
git clone https://github.com/chrisz-toledo/hado
cd hado
pip install -e ".[dev]"
```

## Correr tests

```bash
pytest tests/
```

Criterio mínimo antes de cada commit: **0 failures**.

---

## ⚠️ Regla de doc-sync — obligatoria

**La documentación desactualizada es un bug.** Esta es la regla más importante del proyecto.

Todo commit que modifique el compilador, el AST o cualquier backend **debe** actualizar la documentación en el mismo commit. No en un commit posterior. No "lo hago después". En el mismo commit.

### Qué actualizar según el tipo de cambio

| Cambio | README.md | docs/spec.md | docs/tutorial.md | docs/roadmap.md |
|--------|-----------|-------------|-----------------|-----------------|
| Nuevo keyword | ✅ sección "Resumen del lenguaje" | ✅ sección keywords | ✅ si afecta ejemplos | — |
| Backend funcional (stub→real) | ✅ tabla de backends | ✅ sección 8 (multi-target) | ✅ step compilación | ✅ tabla de fases |
| Nuevo módulo cybersec | ✅ sección ejemplos | ✅ sección 5 (cybersec) | ✅ si hay nuevo ejemplo | — |
| Fase completada | ✅ tabla roadmap | ✅ versión en título | — | ✅ fase marcada ✅ |
| Fix de bug | — | — | — | — |
| Nuevo test | — | — | — | — |

### Checklist de PR

Antes de abrir un PR, verificar:

- [ ] `python -m pytest tests/ -q` → 0 failures
- [ ] Si agregué un keyword: está en `docs/spec.md` sección 1.4
- [ ] Si cambié un backend: la tabla de backends en README.md refleja el estado real
- [ ] Si completé una fase: `docs/roadmap.md` tabla de resumen actualizada
- [ ] Los ejemplos en la documentación compilan: `hado run example.ho`

---

## Agregar un nuevo keyword

1. Agregar el keyword a `KEYWORDS` en `src/hado/lexer.py`
2. Agregar un nodo AST en `src/hado/ast_nodes.py` si es necesario
3. Agregar lógica de parsing en `src/hado/parser.py`
4. Agregar transpilación en los cuatro backends:
   - `src/hado/backends/python_transpiler.py`
   - `src/hado/backends/go_transpiler.py` ← (funcional desde Fase 4)
   - `src/hado/backends/c_transpiler.py`
   - `src/hado/backends/rust_transpiler.py`
5. Agregar tests en `tests/`
6. **Actualizar `docs/spec.md` sección 1.4 (keywords)**
7. **Actualizar README.md si afecta los ejemplos principales**

## Agregar un módulo cybersec

1. Crear el módulo en `src/hado/cybersec/`
2. Exportar desde `src/hado/cybersec/__init__.py`
3. Agregar el mapping `_hado_X` en `src/hado/backends/python_transpiler.py`
4. Agregar codegen en los demás backends (código real si el backend es funcional, stub comentado si no)
5. Agregar ejemplo en `examples/`
6. **Actualizar `docs/cybersec-cookbook.md` con la receta correspondiente**
7. **Actualizar `docs/spec.md` sección 5 (cybersec constructs)**

## Completar una fase del roadmap

Cuando una fase del roadmap pase a "completa":

1. **`README.md`**: actualizar tabla de backends y tabla de roadmap
2. **`docs/spec.md`**: actualizar versión en el título (`v0.X.0`) y tabla multi-target
3. **`docs/roadmap.md`**: marcar la fase como `✅ Completa`, actualizar la tabla de stocks y el estado actual
4. **`docs/tutorial.md`**: actualizar si hay cambios en los pasos de uso
5. Commit con mensaje: `docs: sync documentation — fase N completa`

---

## Estilo de código

- Python sigue el formato Black (`black src/ tests/`)
- Todos los mensajes de error visibles al usuario deben estar en español
- Los comentarios en el código fuente del compilador pueden ser en español o inglés

## Principios de diseño

- Cada token debe llevar el máximo significado semántico (sin boilerplate)
- Verbos en español + sustantivos en inglés (nunca traducir términos técnicos)
- Keywords solo ASCII (sin tildes en la especificación del lenguaje)
- Cero imports para el usuario (el transpiler los maneja todos)
- Mensajes de error siempre en español

## Reportar issues

Abrir un issue en https://github.com/chrisz-toledo/hado/issues
