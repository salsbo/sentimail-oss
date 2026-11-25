#!/usr/bin/env bash
# Amorce le répertoire secrets/ de SentiMail : crée le dossier et les six
# fichiers attendus par docker-compose.yml, sans jamais écraser un secret
# déjà en place.
#
# usage: scripts/bootstrap-secrets.sh
set -euo pipefail
umask 077

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

demander_secret() {
    local nom="$1"
    local invite="$2"
    local message_vide="$3"
    local chemin="$SECRETS_DIR/$nom"

    if [ -s "$chemin" ]; then
        echo "-- $nom : déjà présent, conservé"
        CONSERVES+=("$nom")
        return 0
    fi

    local valeur=""
    if [ -t 0 ]; then
        read -rs -p "$invite" valeur || true
        echo
    fi
    printf '%s' "$valeur" > "$chemin"
    chmod 0600 "$chemin"
    if [ -z "$valeur" ]; then
        echo "-- $nom : créé vide ($message_vide)"
    else
        echo "-- $nom : créé"
    fi
    CREES+=("$nom")
}

demander_secret \
    "deepseek_api_key" \
    "Clé API DeepSeek (Entrée pour laisser vide et configurer plus tard via la console /reglages) : " \
    "le moteur LLM devra être configuré depuis la console /reglages avant que les verdicts tombent"

demander_secret \
    "search_api_key" \
    "Clé API de recherche Tavily (Entrée pour laisser vide, facultatif) : " \
    "la recherche externe des domaines officiels reste désactivée"

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
