# Arquitectura y decisiones de TrustPass

## Problema y límites

Un operador necesita emitir una credencial digital, entregar su token a un titular y comprobar posteriormente si sigue siendo válida. El sistema debe impedir alteraciones, controlar expiración y revocación y conservar el historial de emisiones y revocaciones pese a indisponibilidad temporal de auditoría.

Los identificadores son pseudónimos. El diseño no almacena nombres, documentos de identidad ni información sanitaria. El JWT está firmado, no cifrado: su contenido es legible y no debe contener datos confidenciales.

## Contextos delimitados

| Contexto | Responsabilidad | Persistencia |
| --- | --- | --- |
| Emisión | Crear y revocar credenciales, resolver idempotencia, guardar eventos pendientes | SQLite propia, WAL |
| Verificación | Validar criptografía y consultar el estado actual | Sin estado de negocio; volumen local preparado para readiness |
| Auditoría | Recibir eventos idempotentemente y consultarlos | SQLite propia, WAL |
| Gateway | Servir el panel, enrutar APIs y aplicar controles de borde | Sin estado |

Una base compartida por varios contextos introduciría acoplamiento entre sus modelos. La auditoría conserva sólo identificadores, tipos de evento, tiempo e ID de correlación.

## ADR 001 — Monorepo y trunk based development

El monorepo mantiene servicios, contratos e infraestructura en una revisión coherente y permite probar cambios de integración antes de publicar. Ramas cortas y PR hacia `main`; las imágenes se identifican por commit. La misma imagen Python sirve tres roles, con arranque y rutas específicas de cada uno. Esto reduce duplicación operativa y conserva aislamiento de procesos y almacenamiento, a costa de coordinar sus versiones.

## ADR 002 — Contratos REST y FastAPI

Se utilizan REST, Pydantic y OpenAPI 3 para contratos tipados, validación estricta de entrada y errores HTTP explícitos. Los contratos se exportan y versionan; CI detecta diferencias no actualizadas. La implementación es code first, con artefactos OpenAPI revisables. La referencia API first puede implementarse después mediante generación desde una especificación única; no se atribuye esa capacidad al estado actual.

## ADR 003 — Firma asimétrica y separación de claves

RSA de 3072 bits y RS256 permiten que el verificador valide una credencial sin poseer la clave de emisión. Se fija algoritmo, emisor, audiencia y `kid`; el verificador usa exclusivamente la clave pública configurada. La publicación de JWKS facilita la consulta de esa clave, pero no cambia dinámicamente el conjunto de confianza del verificador. No se siguen URLs de claves recibidas en tokens.

`exp`, `iat`, `nbf`, `sub`, `iss`, `aud` y `jti` son obligatorios. La verificación criptográfica precede a cualquier consulta de revocación, para evitar que contenido no confiable controle solicitudes internas.

## ADR 004 — Outbox e inbox idempotente

```mermaid
sequenceDiagram
    participant O as Operador
    participant I as Emisión
    participant D as Base emisor
    participant W as Despachador
    participant A as Auditoría
    O->>I: POST credencial + Idempotency-Key
    I->>D: BEGIN IMMEDIATE
    I->>D: Credencial + respuesta + evento outbox
    I->>D: COMMIT
    I-->>O: 201 + credencial firmada
    W->>D: Leer eventos pendientes
    W->>A: POST evento con ID estable
    A->>A: Persistir si no existe; rechazar colisión
    A-->>W: Aceptado
    W->>D: Marcar entregado
```

Si el proceso termina después de recibir la confirmación y antes de marcar el evento, éste vuelve a enviarse. Auditoría lo deduplica por ID, preservando entrega al menos una vez y un único registro lógico. Los reintentos son cada dos segundos, en lotes de 50 y con timeout HTTP de tres segundos; no hay broker, orden global garantizado, backoff exponencial ni dead letter queue. Un lote con fallos se vuelve a intentar y se contabilizan intentos para operación.

No se necesita una saga: la operación crítica sólo modifica una base local; auditoría es una proyección eventual y su indisponibilidad no revierte la credencial. Una futura compra de credenciales con cobro independiente requeriría compensaciones y una decisión adicional sobre saga.

## ADR 005 — Consistencia y disponibilidad

La verificación consulta el registro de revocación en cada solicitud. Si está caído o responde de forma inválida, devuelve 503 y no afirma validez. Esa elección prioriza revocación actualizada y evita autorizar una credencial con estado desconocido. La auditoría tolera indisponibilidad eventual, mientras que emisión y revocación confirman exclusivamente después del commit local.

SQLite simplifica reproducción y operaciones en una sola máquina. Los archivos son por servicio y persisten en volúmenes. Cada servicio tiene una réplica; escalar réplicas requeriría migración a almacenamiento compartido de propósito específico como PostgreSQL, coordinación del despachador y autenticación por identidad de servicio.

## ADR 006 — Seguridad y entrega

Las APIs de operador usan un token opaco de instalación y los endpoints internos una credencial diferente. El JWT emitido representa una credencial de negocio, no una sesión de operador. No se implementa un servidor OAuth2/OIDC.

El gateway es el único puerto publicado, ligado a loopback. Las aplicaciones carecen de puertos del host y se comunican por una red interna de Docker. Todas las imágenes operan sin root y sin capacidades adicionales, con filesystem de sólo lectura excepto sus volúmenes y `/tmp`.

CI prueba la integración y escanea las mismas imágenes que publica; no recompila entre verificación y entrega. No hay despliegue remoto automático: Compose proporciona el destino local reproducible. Blue green y canary exigen un entorno con balanceador, capacidad duplicada y estrategia de compatibilidad de datos; no se incluyen mecanismos inactivos para simularlos.
