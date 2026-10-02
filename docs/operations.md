# Operación

## Arranque, salud y métricas

Inicializar con `python scripts/init-env.py` y arrancar con `docker compose up -d --build --wait --wait-timeout 180`. `docker compose ps` muestra los cuatro contenedores; `docker compose logs --tail=100 issuer` permite revisar eventos correlacionados. Los servicios exponen `/health/live` y `/health/ready` dentro de la red interna. Readiness confirma acceso SQLite; no realiza una comprobación transitiva de dependencias.

Compose reserva `10.250.120.0/24` y `10.250.121.0/24` para backend y borde. Cambiar `TRUSTPASS_BACKEND_SUBNET` y `TRUSTPASS_EDGE_SUBNET` en `.env` si se solapan con otra red del destino. En un host con Docker muy cargado, `TRUSTPASS_HEALTHCHECK_TIMEOUT=60s` amplía el timeout de la comprobación; el predeterminado es 10 segundos. Ampliar también `--wait-timeout` a 300 cuando el inicio de contenedores sea lento.

Las métricas Prometheus están en `/metrics`, protegidas con la credencial interna. No se publican a través del gateway. Un sistema de monitorización conectado a `backend` puede consultarlas. Las etiquetas usan plantillas de rutas y no IDs de credenciales para limitar cardinalidad. Este proyecto expone métricas y logs; no incluye un stack de dashboards ni trazas distribuidas de OpenTelemetry.

## Auditoría no disponible

Emisión y revocación siguen funcionando y acumulan eventos en el outbox. Al recuperar auditoría, el despachador reintenta. Consultar `/internal/outbox` dentro de la red, con autenticación interna, para comprobar `pending`. Los eventos permanecen hasta su entrega; no se purgan automáticamente.

Si aumenta la cola, comprobar disponibilidad y credenciales de auditoría. Un evento que retorna 409 indica una colisión de ID con otro contenido y requiere investigación. No borrar filas pendientes para silenciar una alerta. El despachador guarda `attempts`, `next_attempt_at` y `last_error` por evento; la espera duplica hasta un máximo de 300 segundos, con hasta un segundo adicional de jitter. Tras ocho fallos (configurable mediante `MAX_DELIVERY_ATTEMPTS`, entre 1 y 50), el evento pasa a `dead_letter`. El endpoint `/internal/outbox` devuelve ambos contadores; monitorizarlos junto al espacio disponible.

Una vez corregida la causa, consultar el ID del evento con acceso administrativo al almacenamiento y ejecutar `POST /internal/outbox/{event_id}/retry` con el token interno, desde la red backend. Esta operación sólo recupera eventos de la cola de errores; reinicia su contador y los vuelve a programar. Auditoría deduplica los IDs ya recibidos. El esquema antiguo se migra automáticamente al iniciar sin perder eventos pendientes.

## Registro de revocación no disponible

Verificación devuelve 503 hasta recuperar el emisor. No sustituir ese resultado por una aceptación local de firma: una firma correcta no acredita el estado actual de revocación.

## Reinicios y copias de seguridad

`docker compose down` detiene y retira contenedores conservando volúmenes. `docker compose up -d --wait` vuelve a iniciarlos. `docker compose down --volumes` elimina los datos de esa instalación; usarlo sólo en entornos efímeros descartables.

Para una copia consistente, detener escrituras y usar la API de backup SQLite o detener el servicio antes de copiar su volumen. Respaldar tanto el volumen `issuer_data` como `audit_data`, `.env` y `.secrets` en un destino con acceso restringido. Restaurar la base y el par de claves correspondiente como una unidad: cambiar la clave rompe la validación de credenciales anteriores.

## Claves y acceso

`init-env.py` conserva las claves existentes. Para rotar, respaldar `.env`, `.secrets` y los volúmenes, detener temporalmente emisor y verificador y ejecutar:

```powershell
docker compose stop issuer verifier
.\.venv\Scripts\python scripts/rotate-keys.py trustpass-2026-02
docker compose up -d --no-build --force-recreate issuer verifier --wait
docker compose restart gateway
```

El identificador debe ser nuevo. El script conserva la clave pública anterior en `.secrets/keyring/{kid}.pem`, genera un nuevo par RSA de 3072 bits y actualiza `SIGNING_KEY_ID`. Ambos servicios se recrean juntos para aplicar los archivos y la configuración; reiniciar el gateway actualiza sus resoluciones DNS si Docker cambia las direcciones. JWKS publica todas las claves de confianza; el verificador selecciona exclusivamente una clave local por `kid` y rechaza identificadores desconocidos. Esta operación incluye una ventana de mantenimiento; no promete rotación sin interrupción.

Conservar cada clave pública anterior hasta que haya expirado la última credencial firmada con ella. Después, retirar sólo su archivo de `keyring` y recrear ambos servicios. Comprobar una credencial nueva y una anterior, consultar JWKS y verificar revocación. No eliminar la clave pública activa ni reutilizar un identificador. Las claves privadas anteriores se retienen únicamente en el respaldo restringido.

Los secretos se montan desde archivos locales. En Linux, el directorio de origen es modo 700 y los archivos legibles por el UID del contenedor; mantener restringido el acceso al host y al daemon Docker. En Windows, aplicar ACL apropiadas al directorio. Una instalación accesible fuera del host necesita TLS, gestión central de secretos e identidad de operadores.

## Actualizar imágenes publicadas

Confirmar que el commit de destino tiene CI verde. Usar los digests emitidos en el resumen de publicación, verificar las atestaciones con `gh attestation verify oci://ghcr.io/jorgefprietol/trustpass-platform@sha256:<digest> -R jorgefprietol/trustpass-platform` y el equivalente para gateway.

Respaldar datos y configuración; actualizar ambos digests en `.env` y ejecutar `docker compose up -d --no-build --wait`. Comprobar emisión, verificación, revocación y drenaje de eventos. La vuelta a la imagen anterior sólo es segura si conserva compatibilidad con el esquema de datos.
