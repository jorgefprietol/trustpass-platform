# Operación

## Arranque, salud y métricas

Inicializar con `python scripts/init-env.py` y arrancar con `docker compose up -d --build --wait --wait-timeout 180`. `docker compose ps` muestra los cuatro contenedores; `docker compose logs --tail=100 issuer` permite revisar eventos correlacionados. Los servicios exponen `/health/live` y `/health/ready` dentro de la red interna. Readiness confirma acceso SQLite; no realiza una comprobación transitiva de dependencias.

Las métricas Prometheus están en `/metrics`, protegidas con la credencial interna. No se publican a través del gateway. Un sistema de monitorización conectado a `backend` puede consultarlas. Las etiquetas usan plantillas de rutas y no IDs de credenciales para limitar cardinalidad. Este proyecto expone métricas y logs; no incluye un stack de dashboards ni trazas distribuidas de OpenTelemetry.

## Auditoría no disponible

Emisión y revocación siguen funcionando y acumulan eventos en el outbox. Al recuperar auditoría, el despachador reintenta. Consultar `/internal/outbox` dentro de la red, con autenticación interna, para comprobar `pending`. Los eventos permanecen hasta su entrega; no se purgan automáticamente.

Si aumenta la cola, comprobar disponibilidad y credenciales de auditoría. Un evento que retorna 409 indica una colisión de ID con otro contenido y requiere investigación. No borrar filas pendientes para silenciar una alerta. El despachador guarda `attempts` por evento; el almacenamiento del outbox debe monitorizarse para evitar agotamiento de disco.

## Registro de revocación no disponible

Verificación devuelve 503 hasta recuperar el emisor. No sustituir ese resultado por una aceptación local de firma: una firma correcta no acredita el estado actual de revocación.

## Reinicios y copias de seguridad

`docker compose down` detiene y retira contenedores conservando volúmenes. `docker compose up -d --wait` vuelve a iniciarlos. `docker compose down --volumes` elimina los datos de esa instalación; usarlo sólo en entornos efímeros descartables.

Para una copia consistente, detener escrituras y usar la API de backup SQLite o detener el servicio antes de copiar su volumen. Respaldar tanto el volumen `issuer_data` como `audit_data`, `.env` y `.secrets` en un destino con acceso restringido. Restaurar la base y el par de claves correspondiente como una unidad: cambiar la clave rompe la validación de credenciales anteriores.

## Claves y acceso

El script no rota claves existentes. La versión actual mantiene una sola clave de confianza. La rotación sin interrupción requiere varios `kid`, publicación de claves anteriores durante su vigencia y actualización coordinada de verificadores; debe implementarse antes de introducir rotación periódica.

Los secretos se montan desde archivos locales. En Linux, el directorio de origen es modo 700 y los archivos legibles por el UID del contenedor; mantener restringido el acceso al host y al daemon Docker. En Windows, aplicar ACL apropiadas al directorio. Una instalación accesible fuera del host necesita TLS, gestión central de secretos e identidad de operadores.

## Actualizar imágenes publicadas

Confirmar que el commit de destino tiene CI verde. Usar los digests emitidos en el resumen de publicación, verificar las atestaciones con `gh attestation verify oci://ghcr.io/jorgefprietol/trustpass-platform@sha256:<digest> -R jorgefprietol/trustpass-platform` y el equivalente para gateway.

Respaldar datos y configuración; actualizar ambos digests en `.env` y ejecutar `docker compose up -d --no-build --wait`. Comprobar emisión, verificación, revocación y drenaje de eventos. La vuelta a la imagen anterior sólo es segura si conserva compatibilidad con el esquema de datos.
