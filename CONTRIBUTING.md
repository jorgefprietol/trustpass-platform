# Contribuir

Crear una rama corta desde `main`, implementar una capacidad o corrección coherente y abrir un pull request. Mantener los cambios de contrato, pruebas e infraestructura en la misma revisión cuando estén relacionados.

Antes del PR:

1. Ejecutar Ruff y las pruebas del proyecto.
2. Exportar OpenAPI con `python scripts/export-contracts.py` y revisar las diferencias.
3. Si cambia comunicación, persistencia o Docker, ejecutar `python scripts/e2e.py` en un stack dedicado.
4. Actualizar arquitectura u operación cuando cambien sus supuestos.

Para actualizar dependencias desde un entorno Python 3.12:

```text
python -m piptools compile --upgrade --generate-hashes --allow-unsafe --strip-extras -o requirements.lock requirements.in
python -m piptools compile --upgrade --generate-hashes --allow-unsafe --strip-extras -o requirements-dev.lock requirements-dev.in
python -m pip install --require-hashes -r requirements-dev.lock
```

Mantener las versiones de runtime iguales en ambos archivos lock. Actualizar digests de las imágenes de base y hashes de Actions mediante PR con CI verde. No introducir credenciales o datos personales en fixtures, documentación, capturas o logs.
