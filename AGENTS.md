# SentiMail V3

Repères pour les agents IA qui développent ou font évoluer SentiMail.
Lire d'abord `docs/code-sentinel.md` (procédure fonctionnelle complète) et
`docs/mx-autonome.md` (MX autonome) avant de coder.

## Carte du dépôt

- `collector/src/sentimail_v3/` : cœur du pipeline, rangé par ce que fait
  chaque module, pas par ancienneté.
  - `observation/` capte le courrier et le décrit : réception SMTP, analyse,
    enrichissement, constitution du dossier. Rien n'y décide, tout y
    constate.
  - `code/` porte la règle applicable : articles, listes de l'utilisateur,
    autorisation des domaines, vocabulaire en clair, normes de la
    messagerie.
  - `judgment/` tranche : éléments favorables et défavorables confrontés,
    verdict final et décision de livraison.
  - `execution/` agit sur le courrier : livrer, retenir, chiffrer, purger.
    Elle applique un verdict, elle ne le réévalue jamais.
  - `conversation/` parle à l'utilisateur, et seulement par SMTP (MAIA).
  - `supervision/` surveille l'ensemble : santé, cohérence, rejeu, mesure.
  - `config`, `crypto`, `llm` restent à la racine du package : transverses
    par nature, ils n'appartiennent à aucun des six.
- `collector/tests/`, `admin/tests/` : suites pytest.
- `admin/src/` : console de configuration (identité, moteur LLM, domaines,
  listes).
- `database/init/` : migrations SQL, appliquées par le service `migrate`.
- `infra/url-sandbox/`, `infra/file-sandbox/`, `infra/render-sandbox/` :
  bacs à sable d'analyse, images autonomes.
- `infra/postfix/`, `infra/rspamd/` : configuration du MX public autonome.
- `docs/` : documentation fonctionnelle (`code-sentinel.md`,
  `mx-autonome.md`).
- `knowledge/` : corpus normatif et doctrine adverse (RAG).
- `ops/` : scripts d'exploitation (sauvegarde, etc.).
- `tools/` : scripts ponctuels hors service.

## Invariants non négociables

1. **Jamais de fix spécifique à un cas.** Pas de liste blanche d'expéditeur
   codée en dur, pas de `if domain == "x"`. Tout signal doit être générique
   et reproductible.
2. **Aucun chemin de code par correspondant ou par client.** Les politiques
   passent par les tables et le corpus normatif, jamais par le code.
3. **Lisibilité sans framework maison.** Modules courts, pas d'event bus,
   pas de DSL interne.
4. **Fail-soft / fail-open.** Un sous-module en erreur rend un signal
   absent ; il ne fait pas tomber la chaîne. Une défaillance critique livre
   le mail et lève une alerte au superviseur plutôt que de retenir en
   silence.
5. **Un verdict accepté n'est jamais retouché après coup.** Le validateur
   rejette un verdict incohérent avant qu'il ne devienne contraignant ;
   aucun moteur de politique ne repasse derrière un verdict déjà accepté.
6. **Tout critère de détection passe par un `clue_code` du corpus
   normatif.** Un critère qui n'est pas un `clue_code` n'entre ni au
   jugement ni à l'apprentissage : il n'existe pas pour le système.

## Migrations

- `database/init/` est **append-only** : un fichier déjà appliqué en
  production ne se modifie jamais. Toute évolution s'ajoute dans un nouveau
  fichier numéroté.
- `migrate.sh` vérifie une somme de contrôle sur les fichiers déjà
  appliqués : modifier un fichier existant fait échouer le démarrage.

## Tests

```
cd collector && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
cd admin && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
```

Les tests unitaires du caretaker fournissent eux-mêmes leur configuration et
ne dépendent plus de la présence de `DATABASE_URL` dans le terminal appelant.

## Langue et style

- Code et docstrings : français.
- Modules courts ; les commentaires expliquent le pourquoi d'une décision,
  pas ce que fait déjà la ligne suivante.
- Aucun tiret cadratin : utiliser « - » ou « : ».
