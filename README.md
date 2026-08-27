# SentiMail

*Self-hosted email protection gateway with a configurable LLM judge : an
autonomous MX receives mail, a multi-stage pipeline decides to deliver,
hold or classify each message. Full English guide: [README.en.md](README.en.md).
License: personal/noncommercial use is free, commercial use requires the
author's prior written permission (see `LICENSE`).*

Passerelle de protection de messagerie auto-hébergée : un MX autonome reçoit
le courrier, un examen en plusieurs étapes (signaux déterministes + juge LLM)
décide de livrer, retenir ou classer chaque message, une assistante, MAIA (Mail Authentication Intelligence Agent),
dialogue avec l'utilisateur par email, et une console d'admin configure
l'instance.

## Avertissements

- **Le contenu des messages est envoyé au fournisseur LLM configuré**
  (DeepSeek, OpenAI, Mistral, Anthropic, ou un endpoint local via
  Ollama/vLLM). L'encart de confidentialité de la console (`/reglages`,
  `/etat`) affiche en permanence, rôle par rôle, où part ce contenu : vers
  l'URL du fournisseur distant configuré, ou vers le modèle local si aucune
  donnée ne sort.
- **Poser un MX en coupure du flux de courrier exige de savoir opérer un
  serveur mail** : enregistrement MX, PTR de l'adresse publique, certificat
  TLS. Une mauvaise configuration DNS/TLS fait refuser le courrier par les
  expéditeurs.

## Architecture

Services Docker Compose (`docker-compose.yml`) :

| Service | Rôle |
|---|---|
| `db` | PostgreSQL, base de données de l'instance |
| `migrate` | Applique les migrations SQL au démarrage (append-only, vérifiées par somme de contrôle) |
| `backup` | Sauvegardes périodiques chiffrées de la base |
| `collector` | Réception SMTP interne (`observation.smtp_server`) et orchestration du pipeline d'analyse |
| `assistant` | MAIA : dialogue par email avec l'utilisateur (`conversation.assistant`) |
| `verdict` | Étage de jugement LLM (`judgment.verdict_engine`) : confronte éléments favorables et défavorables, rend le verdict |
| `enricher` | Analyse profonde asynchrone (`observation.enricher`) : sandboxes, âge de domaine, DNS, RDAP, ASN, pays |
| `retention` | Dégonflage puis suppression du contenu selon la fenêtre de rétention (`execution.retention`) |
| `watchdog` | Superviseur anti-soft-fail (`supervision.watchdog`) : vérifie qu'un message accepté est soit livré, soit accompagné d'un avis MAIA |
| `caretaker` | Diagnostic et garde-fous de supervision (`supervision.caretaker`) |
| `admin` | Console de configuration (identité, moteur LLM, domaines, listes) |
| `relay` | Postfix côté interne : relaie le courrier accepté vers `collector` |
| `url-sandbox` | Bac à sable d'analyse des URL (redirections, formulaires) |
| `file-sandbox` | Bac à sable d'analyse des pièces jointes (YARA, macros, PDF, archives, OCR) |
| `render-sandbox` | Bac à sable de rendu (captures, contenu caché) |
| `valkey` | Stockage de travail de rspamd (Bayes, caches), jetable |
| `rspamd` | Milter qui produit la preuve d'authentification (SPF/DKIM/DMARC) |
| `mx` | Postfix public autonome : réception SMTP depuis Internet (port 25) |

Chaîne de réception publique : `Internet -> mx -> rspamd (milter) -> mx ->
collector -> pipeline`. Détail complet dans `docs/mx-autonome.md`.

Organisation du code (`collector/src/sentimail_v3/`) : `observation/` capte
et décrit le courrier, `code/` porte la règle applicable, `judgment/`
tranche, `execution/` agit sur un verdict déjà rendu, `conversation/` parle
à l'utilisateur par SMTP, `supervision/` surveille l'ensemble. Voir
`docs/code-sentinel.md` pour le détail fonctionnel complet.

## Démarrage

1. Cloner le dépôt.
2. Copier `.env.example` vers `.env` et ajuster les valeurs (domaine,
   identité de service, adresse Tailscale de l'admin, etc.).
3. Créer les fichiers secrets attendus sous `secrets/` (mode 0700 pour le
   dossier, 0600 par fichier) avec :

   ```
   scripts/bootstrap-secrets.sh
   ```

   Le script est idempotent (il ne touche jamais à un fichier déjà présent
   et non vide) et génère `db_password`, `assistant_token_secret` et
   `backup_password` en hex 32 octets, `raw_eml_key` en hex 32 octets
   (format exigé par `crypto.load_key`, 64 caractères hex). Il demande
   interactivement `deepseek_api_key` ; laissé vide (Entrée), le fichier
   est créé vide et le moteur LLM devra être configuré depuis la console
   `/reglages` avant que les verdicts tombent.
4. Démarrer la pile :

   ```
   docker compose up -d --build
   ```

5. Ouvrir la console d'admin à l'adresse `SENTINEL_ADMIN_ADDR` (variable
   d'`.env` : la console n'a pas de mot de passe, l'appartenance au réseau
   qui porte cette adresse est l'autorisation. N'importe quelle adresse
   privée dont vous contrôlez seul l'accès convient (VPN quelconque, LAN
   filtré) ; Tailscale est le choix documenté par défaut. `0.0.0.0` est
   refusé sauf opt-in explicite via `ADMIN_BIND_UNRESTRICTED=true`).
6. Enrôler un domaine (procédure détaillée dans `docs/mx-autonome.md`).
7. Configurer le moteur LLM depuis `/reglages` (préréglages `deepseek`,
   `openai`, `mistral`, `ollama`, `anthropic`, ou `custom`). Préréglage
   `ollama` : sous Linux, `host.docker.internal` ne se résout pas par
   défaut depuis un conteneur ; utiliser l'IP de l'hôte ou ajouter
   `extra_hosts: host.docker.internal:host-gateway` au service concerné
   dans `docker-compose.yml`.

## Configuration

Toutes les variables commentées sont dans `.env.example`. Le détail des
tables de configuration vivante (`llm_role_providers`, `instance_identity`,
éditables depuis `/reglages` sans redémarrage) et de l'ordre de préséance du
routage (routage local par rôle > table `llm_role_providers` du rôle >
variables d'environnement) est dans la section « Configuration du moteur et
de l'identité » de `docs/code-sentinel.md`.

## Tests

```
cd collector && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
cd admin && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
```

## Documentation

- `docs/code-sentinel.md` : procédure fonctionnelle complète (contrat des
  hooks, mode décisionnel, conversation SMTP, listes d'expéditeurs,
  configuration du moteur, rétention, verrous anti-empoisonnement).
- `docs/mx-autonome.md` : fonctionnement du MX autonome.
- `AGENTS.md` : repères pour les agents IA qui reprennent ce code.

## Licence

Usage personnel et non commercial libre, sous licence PolyForm Noncommercial
1.0.0 (voir `LICENSE`). Tout usage commercial requiert une autorisation
écrite préalable de l'auteur. Contact : https://github.com/salsbo
