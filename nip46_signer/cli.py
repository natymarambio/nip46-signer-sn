"""Command line interface.

    python -m nip46_signer init              # create or import a key, stored encrypted
    python -m nip46_signer info              # show npub (no password needed)
    python -m nip46_signer bunker            # run the signer, print a bunker:// URI for Stacker News
    python -m nip46_signer connect <uri>     # answer a nostrconnect:// URI shown by an app
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

from . import crypto, keystore
from .signer import DEFAULT_RELAYS, Nip46Signer, allow_all

LABELS = {
    "connect": "Una aplicación quiere conectarse",
    "sign_event": "Solicitud de firma",
}


def _password(confirm=False) -> str:
    env = os.environ.get("NIP46_PASSWORD")  # for scripted demos/tests only
    if env:
        return env
    pw = getpass.getpass("Contraseña de la clave: ")
    if confirm:
        if len(pw) < 8:
            sys.exit("La contraseña debe tener al menos 8 caracteres.")
        if getpass.getpass("Repite la contraseña: ") != pw:
            sys.exit("Las contraseñas no coinciden.")
    return pw


async def terminal_approver(kind: str, client: str, details: str) -> bool:
    print(f"\n=== {LABELS.get(kind, kind)} ===\ncliente: {crypto.npub(client)}\n{details}")
    answer = await asyncio.to_thread(input, "¿Aprobar? [s/N]: ")
    return answer.strip().lower() in ("s", "si", "sí", "y", "yes")


def cmd_init(args):
    path = Path(args.keyfile)
    if path.exists() and not args.force:
        sys.exit(f"Ya existe una clave en {path}. Usa --force para reemplazarla.")
    if args.import_key:
        raw = getpass.getpass("Pega tu clave secreta (nsec1… o hex): ")
        try:
            secret = crypto.parse_secret(raw)
        except Exception as e:
            sys.exit(f"Clave inválida: {e}")
    else:
        secret = crypto.generate_secret()
    keystore.save(secret, _password(confirm=True), path)
    pub = crypto.pubkey_hex(secret)
    print(f"Clave guardada cifrada (NIP-49) en {path}\nnpub: {crypto.npub(pub)}")
    if not args.import_key:
        print("Respaldo: ejecuta `python -m nip46_signer export` si necesitas ver la nsec.")


def cmd_info(args):
    meta = keystore.load_meta(args.keyfile)
    print(f"npub:      {crypto.npub(meta['pubkey'])}\npubkey:    {meta['pubkey']}\n"
          f"ncryptsec: {meta['ncryptsec']}")


def cmd_export(args):
    secret = _unlock(args)
    print(f"nsec: {crypto.nsec(secret)}\n(no la compartas: quien la tenga controla tu identidad)")


def _unlock(args) -> bytes:
    try:
        return keystore.unlock(_password(), args.keyfile)
    except FileNotFoundError:
        sys.exit(f"No hay clave en {args.keyfile}. Ejecuta primero: python -m nip46_signer init")
    except ValueError as e:
        sys.exit(f"No se pudo desbloquear la clave: {e}")


async def _serve(args, nostrconnect_uri: str | None = None):
    secret = _unlock(args)
    approve = allow_all if args.auto_approve else terminal_approver
    signer = Nip46Signer(secret, args.relay or DEFAULT_RELAYS, approve)
    print(f"Usuario: {crypto.npub(signer.pubkey)}\nConectando a relays: {', '.join(signer.relays)} …")
    await signer.start()
    if nostrconnect_uri:
        await signer.accept_nostrconnect(nostrconnect_uri)
    else:
        print("\nPega este token en Stacker News (Login → Nostr → campo 'bunker://…'):\n")
        print(f"  {signer.bunker_uri()}\n")
    print("Firmante activo. Ctrl+C para salir.")
    try:
        await asyncio.Future()
    finally:
        await signer.stop()


def main(argv=None):
    p = argparse.ArgumentParser(prog="nip46_signer", description="Firmante remoto Nostr (NIP-46)")
    p.add_argument("--keyfile", default=str(keystore.DEFAULT_PATH), help="ruta del archivo de clave")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="crear o importar una clave secreta")
    s.add_argument("--import", dest="import_key", action="store_true", help="importar nsec/hex existente")
    s.add_argument("--force", action="store_true", help="reemplazar una clave existente")
    s.set_defaults(func=cmd_init)

    sub.add_parser("info", help="mostrar la clave pública").set_defaults(func=cmd_info)
    sub.add_parser("export", help="mostrar la nsec (requiere contraseña)").set_defaults(func=cmd_export)

    for name, help_ in (("bunker", "ejecutar el firmante y mostrar un token bunker://"),
                        ("connect", "aceptar un URI nostrconnect:// de una aplicación")):
        s = sub.add_parser(name, help=help_)
        if name == "connect":
            s.add_argument("uri")
        s.add_argument("--relay", action="append", help=f"relay a usar (repetible). Default: {DEFAULT_RELAYS}")
        s.add_argument("--auto-approve", action="store_true", help="aprobar todo sin preguntar (solo demo)")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        if args.cmd == "bunker":
            asyncio.run(_serve(args))
        elif args.cmd == "connect":
            asyncio.run(_serve(args, args.uri))
        else:
            args.func(args)
    except KeyboardInterrupt:
        print("\nFirmante detenido.")
    except ConnectionError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
