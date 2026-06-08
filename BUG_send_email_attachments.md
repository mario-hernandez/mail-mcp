# BUG: `send_email` ignora silenciosamente los adjuntos

> Prompt / encargo para corregir un bug confirmado en `mail_mcp`.
> Repo: `/Users/mario/Desarrollo/mail-mcp-xo8dv` (paquete Python `mail_mcp`, servidor MCP de correo IMAP/SMTP).

---

## Resumen en una línea

`send_email` acepta `attachments` en el schema pero **nunca los adjunta**: construye el mensaje sin pasarlos al builder MIME, y aun así devuelve `message_id` como si todo fuera bien. El correo llega como `text/plain` de una sola parte, sin el fichero.

---

## 1) Síntoma (observado y reproducido en producción)

- Llamada a `send_email` con `attachments=[{"path": "/ruta/a/factura.pdf"}]`.
- La tool devuelve éxito normal: `{"message_id": "...", "recipients": {...}}`. **No hay error, ni warning, ni campo que indique problema.**
- PERO el correo que llega es de una sola parte `Content-Type: text/plain`, **sin adjunto**. Verificado de dos formas independientes:
  1. `list_attachments` sobre la copia en "Enviados" devuelve `[]`.
  2. `get_email_raw` muestra el RFC822 con `Content-Type: text/plain; charset="utf-8"` y una sola parte — no es multipart, no hay PDF.
- Probado con 3 rutas distintas de adjunto (`Desktop`, `~/Downloads/mail-mcp/`, `~/Downloads/mail-mcp/<alias>/`): resultado idéntico → **NO es un problema de "allowed directory"** (si lo fuera debería ERRAR, no devolver éxito).

**Contraste que prueba que el resto del stack está bien:** `save_draft` con EXACTAMENTE el mismo `attachments` SÍ produce un MIME multipart correcto (`list_attachments` del borrador muestra `application/pdf` con su tamaño real), y `send_draft` de ese borrador SÍ entrega el adjunto. Es decir, el builder MIME y la ruta SMTP funcionan; **el defecto está aislado en `send_email`**.

---

## 2) Causa raíz (ya localizada — no hace falta tocar el builder)

- **`src/mail_mcp/tools/send.py`**, función `send_email` (aprox. líneas 106-118): llama a `smtp_client.build_message_with_bcc(...)` pasando from/to/cc/bcc/subject/body/in_reply_to/references **pero no pasa `attachments`** y **nunca resuelve `params.attachments`** (no llama a `resolve_many`). El parámetro `SendEmailInput.attachments` se acepta en el schema pero se descarta.

- En cambio, **`src/mail_mcp/tools/drafts.py`**, `save_draft` (líneas 64-74) hace lo correcto:

  ```python
  attachments = resolve_many(params.attachments) if params.attachments else []
  msg = smtp_client.build_message(..., attachments=attachments)
  ```

- El builder **YA soporta adjuntos**: `src/mail_mcp/smtp_client.py` `build_message_with_bcc` (líneas 175-205) declara `attachments: list | None` y lo reenvía a `build_message`, que invoca `_attach_files`. Así que el fix **NO requiere modificar `smtp_client.py`**: solo hay que ALIMENTAR el parámetro desde `send_email`.

---

## 3) Fix requerido (mínimo, paridad con `save_draft`)

En `src/mail_mcp/tools/send.py`:

- Importar el resolvedor: `from ..safety.attachments import resolve_many`
- Dentro de `send_email`, antes de construir el mensaje:

  ```python
  attachments = resolve_many(params.attachments) if params.attachments else []
  ```

- Pasarlo al builder:

  ```python
  msg, bcc = smtp_client.build_message_with_bcc(
      from_addr=acct.email,
      to=params.to, cc=params.cc, bcc=params.bcc,
      subject=params.subject, body_text=params.body,
      in_reply_to=params.in_reply_to, references=params.references,
      attachments=attachments,          # <-- línea que faltaba
  )
  ```

Mantén el orden actual: la resolución de adjuntos debe ocurrir DESPUÉS de los gates (`is_enabled` / `confirm` / rate limit) para no resolver disco si la llamada va a ser rechazada — o, si prefieres fallar barato, resuélvelos antes del rate-limit pero después de los gates de habilitación. Justifica la elección en un comentario.

---

## 4) Mejora secundaria OBLIGATORIA: que NO vuelva a fallar en silencio

El daño real de este bug fue que devolvió éxito sin adjuntar nada, y un agente dio por enviadas 17 facturas que llegaron vacías. Para que un fallo futuro sea visible:

- Incluye en el dict de respuesta de `send_email` (y por coherencia en `save_draft`) un resumen de los adjuntos **realmente incorporados**, p. ej.:

  ```python
  "attachments": [
      {"filename": "...", "size": 12345, "content_type": "application/pdf"},
      ...
  ]
  ```

  derivado del mensaje construido, **no** del input crudo.

- Confirma (y cubre con test) que `resolve_many` **LANZA** un error claro cuando una ruta no existe o cae fuera de los directorios permitidos, de modo que `send_email` aborte con error en vez de enviar un correo sin adjunto. Si hoy no lanza, haz que lance.

---

## 5) Tests de regresión (añádelos; sin red real)

- **Unit:** monkeypatch de `smtp_client.send` para capturar el `EmailMessage` que `send_email` construye. Aserta:
  - `msg.get_content_maintype() == "multipart"`
  - existe una parte con `Content-Type: application/pdf` y el nombre de fichero esperado
  - el cuerpo de texto sigue presente

  (Mira `tests/test_smtp_message.py` y `tests/test_update_draft_attachments.py` como referencia de estilo; reutiliza fixtures de adjuntos si existen.)

- **Unit:** `send_email` con una ruta de adjunto inexistente / fuera de allowed dirs → debe LANZAR y NO llamar a `smtp_client.send`.
- **Unit:** `send_email` **sin** adjuntos sigue produciendo un `text/plain` de una sola parte (no regresar a multipart vacío).
- Revisa que `reply_draft` / `forward_draft` / `send_draft` NO estén afectados (usan `build_message` con attachments, `carry_over_attachments` o reenvían el raw del borrador) y deja un test que lo confirme si no existe.

---

## 6) Criterios de aceptación

- [ ] `send_email` con `attachments` entrega un correo multipart con el/los ficheros; `list_attachments` sobre la copia en Enviados los muestra.
- [ ] Ruta de adjunto inválida → error explícito, sin envío.
- [ ] La respuesta de `send_email` refleja los adjuntos incluidos.
- [ ] Toda la suite (`pytest`) en verde, incluidos los tests nuevos.
- [ ] Sin cambios en las firmas públicas del builder ni en el modelo de gating (env gates + confirm + rate limit intactos).
- [ ] Actualiza el CHANGELOG/README si documentan adjuntos en `send_email`.

> No cambies la lógica de seguridad de adjuntos (`safety/attachments.py`, validación de rutas) salvo para hacerla fallar ruidosamente como se pide en (4). Entrega un diff pequeño y enfocado.

---

## Apéndice: referencias de código

| Qué | Archivo | Líneas (aprox.) |
|---|---|---|
| `send_email` (bug: no pasa attachments) | `src/mail_mcp/tools/send.py` | 94-128 (llamada al builder 109-118) |
| `save_draft` (correcto, usar de modelo) | `src/mail_mcp/tools/drafts.py` | 61-87 |
| `build_message` (ya soporta attachments) | `src/mail_mcp/smtp_client.py` | 123-172 |
| `build_message_with_bcc` (ya reenvía attachments) | `src/mail_mcp/smtp_client.py` | 175-205 |
| `_attach_files` | `src/mail_mcp/smtp_client.py` | 42-85 |
| `resolve_many` | `src/mail_mcp/safety/attachments.py` | — |
