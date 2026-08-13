# rollback/

| Módulo | Contenido |
| --- | --- |
| [`strategies.py`](strategies.py) | `rollback_isolation`, `rollback_scale_to_zero`: revierten el estado real (`FakeClusterState`/`FakeReplicaState`) que modificó el executor correspondiente; `mark_rolled_back` produce la copia del `ActionResult` original con `status="rolled_back"` y `rollback_ref` |
| [`verification.py`](verification.py) | Verificación independiente del estado tras el rollback — no confía en el campo `verification` que ya puso el propio rollback |

Probado de extremo a extremo en `tests/rollback/`: aislar → verificar aislado → revertir → verificar restaurado, sobre el mismo estado en memoria que modificó el executor (no un mock separado que finge).
