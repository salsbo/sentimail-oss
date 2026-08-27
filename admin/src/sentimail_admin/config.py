"""Configuration de la console.

L'adresse d'écoute est la seule frontière de ce service : il n'a pas de mot de
passe. Elle vaut par défaut l'adresse Tailscale de la machine, et le service
refuse de démarrer s'il ne la trouve pas. Écouter sur toutes les interfaces
reste possible, mais seulement si on l'a écrit noir sur blanc.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

# Plage partagée de Tailscale (CGNAT, RFC 6598) : 100.64.0.0/10.
TAILSCALE_NETWORK = ipaddress.ip_network("100.64.0.0/10")
# Adresse de service de Tailscale : joignable seulement depuis le tailnet.
_TAILSCALE_PROBE = "100.100.100.100"
_WILDCARD = {"0.0.0.0", "::", "*"}


class ConfigurationInvalide(RuntimeError):
    """Le service ne peut pas démarrer dans cet état."""


@dataclass(frozen=True)
class Settings:
    database_url: str
    bind_host: str
    bind_port: int
    trusted_origins: tuple[str, ...]
    trusted_proxies: frozenset[str]
    messages_limit: int
    events_limit: int
    # Ou la console pose la cle du moteur. Elle y ecrit, elle n'y lit
    # jamais : voir sentimail_admin.secrets.
    provider_secrets_dir: str


def is_tailscale_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value) in TAILSCALE_NETWORK
    except ValueError:
        return False


def discover_tailscale_address(probe: str = _TAILSCALE_PROBE) -> str | None:
    """Adresse locale que le noyau utiliserait pour joindre le tailnet.

    Une socket UDP connectée n'émet aucun paquet : elle ne fait que demander à
    la table de routage quelle source serait choisie. Sur une machine du
    tailnet, c'est l'adresse Tailscale ; ailleurs, ce n'en est pas une et elle
    est écartée.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((probe, 53))
        address = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    return address if is_tailscale_address(address) else None


def resolve_bind_host(environ: Mapping[str, str]) -> str:
    """Adresse d'écoute : configurée, sinon celle du tailnet, jamais 0.0.0.0."""
    configured = environ.get("ADMIN_BIND_HOST", "").strip()
    unrestricted = environ.get("ADMIN_BIND_UNRESTRICTED", "").casefold() == "true"

    if not configured:
        discovered = discover_tailscale_address()
        if discovered:
            return discovered
        raise ConfigurationInvalide(
            "Aucune adresse Tailscale trouvée sur cette machine. "
            "Renseignez ADMIN_BIND_HOST avec l'adresse d'écoute voulue."
        )

    if configured in _WILDCARD and not unrestricted:
        raise ConfigurationInvalide(
            "Écouter sur toutes les interfaces exposerait la console sans "
            "authentification. Indiquez une adresse précise, ou assumez le "
            "choix avec ADMIN_BIND_UNRESTRICTED=true."
        )
    return configured


def _database_url(environ: Mapping[str, str]) -> str:
    """Même contrat que les autres services : le mot de passe est un fichier."""
    password_file = environ.get("DATABASE_PASSWORD_FILE")
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
        if not password:
            raise ConfigurationInvalide("DATABASE_PASSWORD_FILE est vide.")
        user = environ.get("DATABASE_USER", "sentimail_v3")
        host = environ.get("DATABASE_HOST", "db")
        port = environ.get("DATABASE_PORT", "5432")
        database = environ.get("DATABASE_NAME", "sentimail_v3")
        return (
            f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}/{quote(database, safe='')}"
        )
    url = environ.get("DATABASE_URL")
    if not url:
        raise ConfigurationInvalide(
            "Ni DATABASE_PASSWORD_FILE ni DATABASE_URL ne sont renseignés."
        )
    return url


def _tuple(environ: Mapping[str, str], name: str) -> tuple[str, ...]:
    return tuple(
        item.strip() for item in environ.get(name, "").split(",") if item.strip()
    )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    return Settings(
        database_url=_database_url(env),
        bind_host=resolve_bind_host(env),
        bind_port=int(env.get("ADMIN_PORT", "8093")),
        trusted_origins=_tuple(env, "ADMIN_TRUSTED_ORIGINS"),
        trusted_proxies=frozenset(_tuple(env, "ADMIN_TRUSTED_PROXIES")),
        messages_limit=int(env.get("ADMIN_MESSAGES_LIMIT", "100")),
        events_limit=int(env.get("ADMIN_EVENTS_LIMIT", "50")),
        provider_secrets_dir=env.get(
            "PROVIDER_SECRETS_DIR", "/run/sentinel-provider-secrets"
        ),
    )


def identity_environment_defaults(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Les valeurs d'identité que le processus d'admin voit dans son environnement.

    Mêmes noms de variable et mêmes valeurs par défaut que
    ``sentimail_v3.config.load_settings`` côté collector : c'est ce qui
    s'applique tant qu'aucune ligne n'existe dans ``instance_identity``. Cette
    fonction ne charge rien dans ``Settings`` - elle ne pilote aucun réglage
    du service web, elle sert seulement à les montrer sur ``/reglages``.
    """
    env = os.environ if environ is None else environ
    aliases = [
        value.strip()
        for value in env.get(
            "ACTION_ALIASES", "kitt@sentinel.sentimail.example"
        ).split(",")
        if value.strip()
    ]
    return {
        "action_address": env.get(
            "ACTION_ADDRESS", "maia@sentinel.sentimail.example"
        ),
        "action_aliases": aliases,
        "assistant_sender": env.get(
            "ASSISTANT_SENDER", "MAIA - SentiMail <maia@sentimail.example>"
        ),
        "probe_recipient": env.get(
            "PROBE_RECIPIENT", "sentinel-probe@sentimail.example"
        ),
    }
