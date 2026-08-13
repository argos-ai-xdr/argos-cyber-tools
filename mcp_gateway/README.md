# mcp_gateway

Punto de entrada único entre `argos-core/services/recommendation` y `executors`/`mcp_servers`. `Gateway.authorize` valida, en orden: modo soportado por la herramienta → scope concedido → target allowlist → (si `execute`) `Approval` válida vía `policies/approval`. Nunca reenvía `request.caller_token`: emite una credencial efímera propia (`_mint_ephemeral_credential`, hoy un id opaco — SPIFFE/SPIRE real pendiente de ARG-020) y `TokenPassthroughError` existe como salvaguarda estructural comprobable en test.

Sin servidor HTTP/gRPC real todavía — `Gateway` es la lógica de autorización en sí, lista para envolverse en un transporte cuando exista (ARG-020).
