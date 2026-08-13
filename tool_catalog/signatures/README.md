# signatures/

`catalog.manifest.json` es un manifiesto de integridad real (SHA-256 de cada definición en `../definitions/`), generado con `write_integrity_manifest` y verificable con `verify_integrity_manifest` — ambos probados en `tests/contract/`.

Esto detecta que un archivo cambió desde que se generó el manifiesto; **no** prueba quién lo generó ni lo autorizó (eso requiere firma criptográfica real, pendiente de ARG-002, mismo mecanismo Cosign que las imágenes de contenedor — ADR-013). Regenerar el manifiesto tras cualquier cambio en `../definitions/`:

```bash
python -c "from pathlib import Path; from tool_catalog.signatures import write_integrity_manifest; write_integrity_manifest(Path('tool_catalog/definitions'), Path('tool_catalog/signatures/catalog.manifest.json'))"
```
