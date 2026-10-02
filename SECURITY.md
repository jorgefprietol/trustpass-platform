# Seguridad

No publicar vulnerabilidades ni credenciales en issues abiertos. Reportar hallazgos mediante el canal privado de seguridad de GitHub, cuando esté habilitado en el repositorio.

## Controles implementados

- Tokens aleatorios de instalación separados para APIs de operador y comunicación interna.
- RS256 con clave privada aislada al emisor; claims, algoritmo, emisor, audiencia y `kid` validados.
- JWT sin datos personales directos; auditoría sin token ni subject.
- SQL parametrizado y validación estricta; límites de tamaño y tráfico en gateway.
- Panel sin interpolación HTML de datos de API, CSP sin scripts inline, secretos sólo en memoria.
- Endpoints internos no enrutados desde el borde; puerto publicado únicamente en loopback.
- Contenedores sin root, read only, sin capacidades y con secretos fuera de las imágenes.
- Dependencias y acciones fijadas, escaneo de secretos e imágenes y comprobación de dependencias en CI.

## Límites

El token opaco de operador es una credencial compartida de instalación y no provee identidad individual, roles ni OAuth2. Los eventos registran correlación, no una atribución autenticada a una persona. HTTP está previsto para loopback y la red interna de una máquina controlada; fuera de ese escenario se requiere TLS y un proveedor de identidad.

Un JWT firmado es legible. Usar identificadores pseudónimos y no incluir información confidencial. La clave actual no rota automáticamente. El control de tasa funciona por dirección IP; un reverse proxy adicional necesita configuración explícita de IP real.

Los volúmenes y claves deben respaldarse y protegerse. El administrador del host y quien controla Docker pueden leer secretos montados. No se presentan estos controles como cumplimiento de un estándar regulatorio o certificación de producción.
