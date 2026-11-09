# nip46-signer — firmante remoto Nostr (NIP-46) para iniciar sesión en Stacker News

Aplicación mínima en **Python** (CLI) que:

1. **Crea o importa** una clave secreta de Nostr y la guarda **cifrada con contraseña** (NIP-49).
2. Actúa como **firmante remoto NIP-46** ("bunker"): escucha peticiones en relays Nostr y firma con esa clave.
3. Permite **iniciar sesión en Stacker News** pegando el token `bunker://…` que genera el firmante.

La clave privada nunca sale del proceso del firmante: Stacker News solo recibe el evento ya firmado.

```
 Navegador (stacker.news, NDK)          Relays Nostr                 Este firmante (CLI)
 ───────────────────────────            ────────────                 ───────────────────
 pegas bunker://<pk>?relay=…&secret=…
 connect [ "", secret ]      ── kind 24133 (cifrado) ──▶            valida secret, pide aprobación → "ack"
 get_public_key              ─────────────────────────▶            → pubkey del usuario
 sign_event kind 27235       ─────────────────────────▶            muestra el evento, pide aprobación,
   tags [challenge,k1] …                                             firma (BIP-340) → evento firmado
 POST /api/auth (evento)  ◀── respuesta cifrada ──────
 SN verifica id + firma + challenge → sesión iniciada
```

## Instalación

Requisitos: Python ≥ 3.10.

```bash
git clone <este-repo> && cd nip46-signer-sn
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Uso: login en Stacker News de principio a fin

```bash
# 1. Crear una clave nueva (o importar una existente con --import) y protegerla con contraseña
python -m nip46_signer init
python -m nip46_signer info          # muestra la npub (no pide contraseña)

# 2. Levantar el firmante
python -m nip46_signer bunker
#   Usuario: npub1…
#   Pega este token en Stacker News …:
#     bunker://<pubkey>?relay=wss%3A%2F%2Frelay.nsec.app&relay=wss%3A%2F%2Fnos.lol&secret=…
```

3. Abre <https://stacker.news/signup?callbackUrl=https%3A%2F%2Fstacker.news%2F&type=nostr>
   (o *Login → Nostr*), pega el token `bunker://…` en el campo de texto y confirma.
4. En la terminal aparecen dos aprobaciones: **conexión** de la app y **firma** del evento
   kind 27235 *"Stacker News Authentication"*. Responde `s` a ambas.
5. Stacker News inicia sesión con tu npub (si la cuenta no existía, la crea).

Para un nuevo login (otra pestaña u otro navegador), el firmante imprime un **token nuevo**:
el `secret` es de un solo uso.

Otros comandos: `export` (muestra la nsec, pide contraseña), `connect "nostrconnect://…"`
(flujo iniciado por la aplicación, ver más abajo), `--relay wss://…` (repetible) y
`--auto-approve` (aprueba todo sin preguntar; solo para demos).

## Pruebas

```bash
pip install pytest && python -m pytest -q      # 94 tests
```

- Criptografía validada contra los **vectores oficiales** de NIP-44 (`tests/vectors/`), NIP-49 y NIP-19.
- `tests/test_signer_e2e.py` levanta un **relay Nostr local** y un cliente que reproduce exactamente lo que hace
  Stacker News: el cliente NIP-46 de NDK 2.12.2 (`connect` → `get_public_key` → `sign_event` kind 27235) y luego la
  **misma verificación que hace el servidor de SN** (`nostrEventAuth`: id SHA-256, firma Schnorr y tag `challenge`).
  También cubre el secreto de un solo uso, el rechazo por parte del usuario, peticiones sin `connect` y `nostrconnect://`.

## Cómo acoté el problema

Antes de escribir código revisé el código fuente de Stacker News (`components/nostr-auth.js`, `lib/nostr.js`,
`pages/api/auth/[...nextauth].js`) y del cliente que usa (NDK 2.12.2). Eso cambió varias decisiones:

| Hallazgo en SN/NDK | Consecuencia en el diseño |
|---|---|
| NDK 2.12 cifra las peticiones NIP-46 con **NIP-04** por defecto (la spec actual exige NIP-44). | El firmante soporta **ambos** y responde con el mismo esquema que recibió (detecta `?iv=`). Sin esto, el login con SN no funciona. |
| NDK solo acepta `result == "ack"` en `connect` (no el secret). | `connect` responde exactamente `"ack"`. |
| SN solo acepta tokens `bunker://` (o NIP-05), no muestra `nostrconnect://`. | `bunker://` es el flujo principal; `nostrconnect://` es un extra mínimo. |
| SN verifica `id`, firma y que el **primer tag** sea `challenge`. | El evento se firma tal como llega (sin reordenar tags) y la serialización del id replica `JSON.stringify`. |

## Supuestos

- **Un usuario, una clave, una máquina.** Es un firmante personal de demostración, no un servicio multiusuario.
- **CLI en vez de interfaz web.** La prueba pide "una forma" de ingresar la clave; una CLI cumple, es más simple de
  auditar y evita servir una página que maneje secretos. Las aprobaciones se hacen en la terminal.
- **Relays por defecto:** `wss://relay.nsec.app` (dedicado a NIP-46) y `wss://nos.lol`. Se pueden cambiar con `--relay`.
- **La clave del firmante es la misma clave del usuario** (`remote-signer-pubkey == user-pubkey`), algo que la spec permite.
- **Sesiones en memoria:** al cerrar el firmante, las apps conectadas deben volver a conectarse.

## Tradeoffs

- **Seguridad vs. simplicidad de la clave:** se guarda cifrada con NIP-49 (scrypt log_n=16 + XChaCha20-Poly1305) en un
  archivo con permisos `0600` en `~/.nip46-signer/key.json`. No se usa el llavero del sistema operativo ni hardware
  seguro: queda fuera de alcance. `NIP46_PASSWORD` existe solo para tests y demos automatizadas.
- **Aprobación manual por cada petición sensible** (`connect`, `sign_event`, `nip04/44_encrypt/decrypt`) en lugar de un
  sistema de permisos persistente (`perms`). Es más seguro y suficiente para un login; sería molesto en uso intensivo.
- **Misma clave para firmante y usuario:** es la opción más compatible, pero publica en los relays que esa npub usa
  un bunker. Usar una clave separada sería más privado; NDK 2.12 lo soporta (llama a `get_public_key`).
- **Se soporta NIP-04 aunque esté deprecado**, porque es lo que envía el cliente real de Stacker News. NIP-44 se usa
  cuando el cliente lo usa y en el flujo `nostrconnect://`.
- **Librerías auditadas para las primitivas** (`coincurve`/libsecp256k1, `cryptography`, `pynacl`); se implementa
  a mano solo el "pegamento" de cada NIP (bech32, padding NIP-44, formato `ncryptsec`), verificado con vectores oficiales.
- **No implementado (fuera de alcance):** auth challenges (`auth_url`), `switch_relays` (responde `null`), NIP-05/NIP-89
  para descubrir el firmante, AUTH de relays (NIP-42), persistencia de sesiones y permisos, interfaz gráfica.

## Estructura

```
nip46_signer/
  crypto.py    claves, firma de eventos (BIP-340), NIP-04, NIP-44 v2
  keystore.py  clave cifrada con contraseña (NIP-49)
  bech32.py    npub / nsec / ncryptsec
  relays.py    pool de websockets con reconexión
  signer.py    lógica NIP-46 (connect, sign_event, get_public_key, ping, nip04/44, logout)
  cli.py       comandos init / info / export / bunker / connect
tests/         vectores oficiales, relay local y cliente que imita a Stacker News
docs/ai-logs/  registros de conversación con el agente de IA
```

## Uso de IA

Desarrollado con un agente de programación con IA (Claude). Los registros de conversación están en
[`docs/ai-logs/`](docs/ai-logs/).
