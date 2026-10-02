# Experiencia técnica — TrustPass

**Proyecto independiente · Ingeniería de backend y plataforma · Jorge Prieto**

Diseño e implementación de una plataforma de credenciales digitales con emisión, verificación criptográfica, revocación y auditoría. El repositorio conserva código, decisiones de arquitectura, contratos y pipeline de entrega para demostrar la ejecución técnica del proyecto.

## Responsabilidades implementadas

- Definición de contextos delimitados y responsabilidades de tres microservicios, con persistencia independiente y gateway de acceso.
- Implementación de APIs REST tipadas, contratos OpenAPI versionados y validación de entradas.
- Separación de firma y verificación RSA, controles de claims JWT y denegación de validación cuando el registro de revocación no responde.
- Construcción de idempotencia durable y transactional outbox con deduplicación de eventos y recuperación tras indisponibilidad.
- Desarrollo de panel web para emisión, verificación, revocación y consulta de auditoría.
- Contenerización con Docker Compose, imágenes sin root, secretos montados y segmentación de red.
- Automatización de calidad, pruebas, auditoría de dependencias, pruebas de contenedores, escaneo de imágenes, SBOM y publicación de imágenes verificadas con GitHub Actions.
- Documentación de decisiones, límites operativos y procedimientos de recuperación.

## Texto breve para portafolio o CV

> Desarrollé TrustPass, una plataforma de credenciales digitales basada en microservicios, APIs REST y firma RSA. Implementé emisión idempotente, revocación, verificación independiente y auditoría eventual mediante transactional outbox. Automaticé la validación y entrega de contenedores con Docker y GitHub Actions, incluyendo pruebas de recuperación, análisis de seguridad y publicación de imágenes verificadas en GHCR.

## Evidencias

Los workflows, las pruebas del repositorio y los artifacts de Actions permiten verificar cada capacidad. No se atribuyen clientes, empleo, tráfico real ni mejoras cuantitativas sin evidencia. El despliegue remoto, la identidad OAuth2/OIDC y el escalado con múltiples réplicas quedan fuera del alcance implementado.
