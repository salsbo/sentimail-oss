"""Les préréglages du moteur de langage.

Un fournisseur nommé n'existe plus dans la configuration : c'est l'URL qui dit
où part le courrier, exactement comme ``llm_role_providers`` la retient. Ces
préréglages ne sont qu'un raccourci de formulaire - remplir en un geste les
quatre colonnes techniques (adaptateur, URL, modèle, paramètre de longueur)
pour un fournisseur connu. ``custom`` reste ouvert : aucune valeur imposée, et
son fichier de clé se déduit du rôle plutôt que d'être fixe, parce qu'un
fournisseur maison peut différer entre le verdict et la conversation.
"""

from __future__ import annotations

from typing import NamedTuple


class Preset(NamedTuple):
    provider: str
    base_url: str
    model: str
    token_limit_param: str
    secret_filename: str | None
    # Champ(s) propriétaire(s) que ce fournisseur exige dans le corps de la
    # requête (ex. couper le raisonnement DeepSeek).
    body_extras: dict[str, object] = {}


PRESETS: dict[str, Preset] = {
    "deepseek": Preset(
        "openai_compatible", "https://api.deepseek.com", "deepseek-v4-pro",
        "max_tokens", "deepseek_api_key",
        {"thinking": {"type": "disabled"}},
    ),
    "openai": Preset(
        "openai_compatible", "https://api.openai.com/v1", "gpt-5",
        "max_completion_tokens", "openai_api_key",
    ),
    "mistral": Preset(
        "openai_compatible", "https://api.mistral.ai/v1", "mistral-large-latest",
        "max_tokens", "mistral_api_key",
    ),
    "ollama": Preset(
        "openai_compatible", "http://host.docker.internal:11434/v1", "qwen3:8b",
        "max_tokens", "ollama_api_key",
    ),
    "anthropic": Preset(
        "anthropic", "https://api.anthropic.com", "claude-sonnet-4-5",
        "max_tokens", "anthropic_api_key",
    ),
    "custom": Preset("openai_compatible", "", "", "max_tokens", None),
}


def secret_filename_for(preset: str, role: str) -> str:
    """Le fichier où la clé de ce préréglage se pose, pour ce rôle.

    Seul ``custom`` n'a pas de fichier fixe : il en tire un par rôle, pour
    qu'un fournisseur maison configuré côté verdict n'écrase pas celui de la
    conversation.
    """
    valeur = PRESETS[preset]
    if valeur.secret_filename is not None:
        return valeur.secret_filename
    return f"custom_{role}_api_key"
