#!/usr/bin/env bash
# Amorce le répertoire secrets/ de SentiMail : crée le dossier et les cinq
# fichiers attendus par docker-compose.yml, sans jamais écraser un secret
# déjà en place.
#
# usage: scripts/bootstrap-secrets.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$REPO_ROOT/secrets"

mkdir -p "$SECRETS_DIR"
chmod 0700 "$SECRETS_DIR"

CREES=()
CONSERVES=()

# Écrit $2 dans le fichier $1 en mode 0600, sans écraser un fichier non vide
# existant.
ecrire_secret() {
    local nom="$1"
    local valeur="$2"
    local chemin="$SECRETS_DIR/$nom"

    if [ -s "$chemin" ]; then
        echo "-- $nom : déjà présent, conservé"
        CONSERVES+=("$nom")
        return 0
    fi

    printf '%s' "$valeur" > "$chemin"
    chmod 0600 "$chemin"
    echo "-- $nom : créé"
    CREES+=("$nom")
}

ecrire_secret "db_password" "$(openssl rand -hex 24)"
ecrire_secret "assistant_token_secret" "$(openssl rand -hex 32)"
ecrire_secret "backup_password" "$(openssl rand -hex 24)"
# 32 octets hex-encodés (64 caractères) : format accepté par
# collector/src/sentimail_v3/crypto.py load_key.
ecrire_secret "raw_eml_key" "$(openssl rand -hex 32)"

# Clé API DeepSeek : prompt interactif, silencieux, laissée vide si non-TTY
# ou si l'utilisateur n'entre rien.
DEEPSEEK_PATH="$SECRETS_DIR/deepseek_api_key"
if [ -s "$DEEPSEEK_PATH" ]; then
    echo "-- deepseek_api_key : déjà présent, conservé"
    CONSERVES+=("deepseek_api_key")
else
    DEEPSEEK_VALEUR=""
    if [ -t 0 ]; then
        read -rs -p "Clé API DeepSeek (Entrée pour laisser vide et configurer plus tard via la console /reglages) : " DEEPSEEK_VALEUR
        echo
    fi
    printf '%s' "$DEEPSEEK_VALEUR" > "$DEEPSEEK_PATH"
    chmod 0600 "$DEEPSEEK_PATH"
    if [ -z "$DEEPSEEK_VALEUR" ]; then
        echo "-- deepseek_api_key : créé vide (le moteur LLM devra être configuré depuis la console /reglages avant que les verdicts tombent)"
    else
        echo "-- deepseek_api_key : créé"
    fi
    CREES+=("deepseek_api_key")
fi

echo
echo "Récapitulatif :"
if [ "${#CREES[@]}" -gt 0 ]; then
    echo "  créés     : ${CREES[*]}"
fi
if [ "${#CONSERVES[@]}" -gt 0 ]; then
    echo "  conservés : ${CONSERVES[*]}"
fi
echo
echo "Prochaine étape : copier .env.example vers .env et renseigner SENTINEL_ADMIN_ADDR."
