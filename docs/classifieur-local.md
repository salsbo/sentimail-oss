# Classifieur local

Le classifieur décharge le **verdict final** des dossiers simples. Les observations,
les bacs à sable et les éventuels appels sémantiques des enquêteurs ont déjà eu
lieu : leurs coûts ne sont pas supprimés par cette première version.

Il apprend une régression logistique binaire avec scikit-learn (BSD-3-Clause),
sur CPU. La classe positive est « légitime ». Tout autre résultat est une
abstention et rend le dossier au circuit LLM existant. Il ne classe aucun mail
en indésirable, ne le supprime pas et ne modifie aucune liste d'expéditeurs.

## Variables et apprentissage

Les seules variables sont la présence, la force et la confiance de chaque
`clue_code`, rattaché à son article et à sa direction. Ni adresse, domaine,
texte libre, sujet, corps, label ou réponse du modèle ne deviennent une variable.
Les règles de livraison servent de barrières avant la décision, pas de variables
apprises. Aucun seuil SMTP ou matériel n'est abaissé par le classifieur.

L'entraînement lit un export JSONL sans connexion à la base. Le cycle automatique
produit cet export avec `supervision.classifier_corpus` ; l'export général
`supervision.dataset` reste disponible pour les autres évaluations.
Le contrat `llm-holdout-ab-1`, demandé le 24 septembre 2026, apprend les verdicts
LLM et les corrections SMTP A/B actives. Les corrections ont un poids de 1,
contre 0,25 pour le LLM ; leur groupe est exclu des exemples enseignants.
Une expertise de sécurité disponible prime sur une préférence de boîte, sans
changer la provenance de celle-ci. Aucun retour utilisateur n'est renommé expert.
Un groupe aux corrections contradictoires est écarté. Les anciennes préférences
sans dossier restent conservées, mais ne permettent pas d'inventer des variables.
Les listes d'expéditeurs continuent à appliquer immédiatement A/B au client
concerné. L'apprentissage généralise seulement les indices structurés ; une
préférence personnelle n'est pas présentée comme une vérité de sécurité.
Les décisions du classifieur lui-même n'alimentent pas les exemples enseignants.

Un groupe est l'ensemble trié des codes d'indices, sans répétition. Tous ses
exemples, y compris enseignants, vont dans une seule partition stable : 70 %
entraînement, 15 % validation, 15 % test. Ce découpage est recalculé depuis les
indices : les anciens groupes persistés ont pu précéder une évolution des
familles. Les partitions de cet entraînement peuvent donc différer de celles
des fichiers exportés. Chaque groupe compte au plus une fois dans une mesure.

Le modèle conserve coefficients, intercept, seuil, versions des règles,
empreintes du dataset et du corpus normatif, date d'entraînement et rapport.
L'inférence utilise ces nombres dans du Python standard. Aucun pickle, serveur
de modèle, GPU, téléchargement ou dépendance scikit-learn dans le worker.
Les coefficients JSON sont vérifiés contre les probabilités scikit-learn sur
tous les exemples d'entraînement avant l'export.

## Décider ou s'abstenir

Le score est une probabilité logistique estimée, pas une garantie de sécurité.
Son étalonnage est mesuré par le score de Brier ; aucun étalonnage empirique
fiable n'est revendiqué tant que les annotations expertes manquent.

Une livraison candidate exige :

- un dossier non tronqué, contenant de 1 à 60 indices connus du modèle ;
- une version des règles déjà vue et le même corpus normatif ;
- des analyses statique et profonde complètes ;
- des indices favorables, aucun indice défavorable, aucune preuve matérielle
  et aucune instruction authentifiée de retenue ;
- un score au moins égal au seuil du modèle (0,995 par défaut) et au seuil du dossier ;
- l'acceptation du candidat par le validateur de verdict utilisé par le LLM.

Tout échec revient au LLM. Un modèle absent ou désactivé conserve le circuit
historique. Un modèle illisible, modifié, incompatible, âgé de plus de 90 jours,
ou un changement du corpus normatif déclenche aussi un repli journalisé.

## Modes et qualification

`off` est la valeur de la migration 089. Installer un modèle le place toujours
en `shadow` : le LLM décide, la prédiction locale reste une comparaison.
Les dossiers éligibles sont alors envoyés au palier premium si la cascade est
activée. Cette observation peut donc coûter davantage que Flash seul.

Le contrat `llm-holdout-ab-1` n'exige aucune revue humaine ni quota de
comparaisons en observation avant activation. Il exige dans chacun des jeux
LLM indépendants de validation et de test : au moins 200 groupes, 50 groupes
non légitimes, au moins une proposition locale et aucune livraison divergente.
Un dossier invalide dans ces jeux, une livraison contredite par une correction
A/B ou une expertise disponible, un corpus incohérent ou un modèle périmé
empêchent aussi l'activation. Le seuil de proposition reste 0,995 minimum.

Ces mesures portent sur l'accord avec le LLM, pas sur une vérité indépendante.
Une faible quantité de propositions locales ne permet pas de revendiquer un
taux d'erreur faible ; le rapport conserve leur nombre et la borne statistique.
Les erreurs du LLM peuvent être apprises. Le choix accepté est une activation
sélective avec contrôle continu et corrections SMTP, sans campagne humaine.
Le quota historique de 300 groupes réels ne bloque plus ce contrat.

Les anciens artefacts sans ce contrat gardent leurs critères d'expertise
(30 candidats en validation, 300 candidats et 50 adverses au test) et leurs
300 groupes observés. Ils ne sont pas réétiquetés : le cycle entraîne une nouvelle
version, avec ses propres corrections et évaluations.

En mode contraignant, un dossier éligible sur vingt, sélectionné par UUID, reste
jugé à distance. Une divergence de livraison remet le modèle en observation et
écrit `classifier.disabled_after_divergence`. Elle n'annule aucun verdict passé.
Installer une autre version impose une nouvelle évaluation hors entraînement. Les corrections
n'altèrent jamais les poids en direct.

## Cycle automatique et corrections A/B

Le caretaker existant passe toutes les six heures. Quand
`classifier_automation.enabled` est actif, il intègre les revues soumises dans
l'admin et exporte un snapshot PostgreSQL cohérent. Il entraîne au plus une fois
par jour, sauf changement du Code, nouvelle correction A/B, retrait de correction
ou revue facultative.
Les empreintes des labels actifs et du corpus normatif sont vérifiées à chaque
passage : une correction ou un changement du Code n'attend pas l'échéance
quotidienne. Le corpus est comparé au dernier candidat évalué, même refusé,
pour ne pas répéter son entraînement à chaque passage. Un dataset inchangé
réutilise le même candidat. Le calcul utilise un processus CPU limité à cinq minutes et un thread
BLAS, avec scikit-learn et ses dépendances épinglés dans l'image du caretaker.
Le worker de verdict conserve son inférence Python sans scikit-learn.

Les candidats et leurs rapports vivent dans PostgreSQL et sa sauvegarde. Le
répertoire d'export temporaire est effacé à la fin du cycle. Un verrou empêche
deux cycles concurrents. Une panne garde la version active et devient visible
dans l'admin et au Watchdog ; un cycle absent depuis 36 heures est aussi signalé.

`auto_activate` autorise un candidat LLM corrigé à remplacer le modèle actif
uniquement après réussite de ses tests indépendants. L'installation commence
en shadow ; la même passe vérifie ensuite les contrôles de production dans
la transaction d'activation. La comparaison de configuration attendue respecte
un arrêt opérateur ou une modification concurrente. Un candidat insuffisant
ne remplace pas le modèle. Une divergence connue du modèle exact empêche sa
réactivation ; ses observations ne sont pas effacées.

Les corrections de la partition d'entraînement changent les poids. Celles de
validation et de test servent au contrôle, jamais à ajuster ces poids : cela
maintient la séparation des jeux. Toutes conservent leur effet SMTP local.

L'admin `/classifieur/revues` propose facultativement les groupes à expertiser. Elle affiche le
texte du message, le texte extrait des fichiers et les indices conservés, sans
afficher la réponse du modèle. Aucune réponse n'est présélectionnée. La
confirmation d'examen est obligatoire et l'origine HTTP est contrôlée. Le
caretaker applique chaque revue une seule fois par `supervision.adjudication`,
avec une trace d'audit. Cela ne modifie ni livraison ni préférence de boîte.
Une absence de pièces ne devient jamais automatiquement une expertise.

Les exemples enseignants ne sont jamais renommés « expert ». Les jeux de
validation et de test restent disjoints de l'entraînement, les paramètres et
le seuil restent fixes. Le nombre de dossiers disponibles peut être inférieur
aux planchers : la qualification attend alors de nouvelles preuves.

Pour déclencher un cycle ponctuel, sans changer ces gardes :

```sh
docker compose exec -T caretaker python -m sentimail_v3.supervision.classifier_cycle --force
```

## Commandes

Exporter dans le conteneur, puis copier **le répertoire complet** sur le poste
d'entraînement. Le manifeste doit porter `corpus_sha256` ; un ancien export sans
cette empreinte peut produire un candidat, mais ne peut autoriser son activation.

```sh
docker compose exec -T verdict python -m sentimail_v3.supervision.dataset /tmp/corpus-classifier
```

Depuis `collector/`, sur le poste disposant de `uv` :

```sh
PYTHONPATH=src uv run --with-requirements requirements.txt \
  --with-requirements requirements-classifier.txt \
  python -m sentimail_v3.supervision.classifier_training \
  /chemin/corpus-classifier /chemin/model-20260924.json --qualification llm-holdout-ab-1
```

Le nom de sortie doit être nouveau. Le rapport sépare les mesures contre
l'enseignant et les mesures contre l'expertise humaine. Réutiliser le test pour
ajuster plusieurs fois le seuil invaliderait son indépendance : réserver alors
un nouveau jeu de test avant toute qualification.

Copier le JSON dans le conteneur (`docker cp`), puis :

```sh
docker compose exec -T verdict python -m sentimail_v3.supervision.classifier --install /tmp/model-20260923.json
docker compose exec -T verdict python -m sentimail_v3.supervision.classifier --status
docker compose exec -T verdict python -m sentimail_v3.supervision.classifier --enforce
docker compose exec -T verdict python -m sentimail_v3.supervision.classifier --off
```

`--enforce` vérifie les mesures dans la même transaction que l'activation, sous
verrou de configuration. La commande échoue sans modifier le mode si la
qualification manque. `--off` rend immédiatement les nouveaux dossiers au LLM.
Une ancienne version peut être réinstallée en observation pour un retour arrière.

## Exploitation

La page d'administration `/classifieur` est accessible depuis l'onglet
« Classifieur local ». Elle montre le mode, le modèle, les comparaisons sur
30 jours, les verdicts locaux, les abstentions et les conditions d'activation.
Les critères viennent du rapport publié par le Watchdog, sans seconde
implémentation dans la console. Un rapport âgé de plus de dix minutes ou lié
à un autre modèle est explicitement marqué non confirmé. Le suivi est en
lecture seule et ne charge ni corps de mail ni coefficients du modèle. La revue
humaine est une page distincte, avec un formulaire POST explicitement confirmé.

`classifier_models` conserve les versions, `classifier_config` le modèle choisi,
`classifier_observations` les comparaisons sans contenu personnel. Ces tables
font partie de la sauvegarde PostgreSQL existante. Les comparaisons sont purgées
avec leur `verdict_run`, les modèles restent disponibles.

Les erreurs portent `classifier.error` au journal d'audit. Le Watchdog dégrade
après trois erreurs sur une heure, ou une désactivation sur divergence dans les
24 dernières heures. Les compteurs sont `classifier_errors_last_hour` et
`classifier_unsafe_divergences`. Le contrat natif reste le heartbeat du worker
`verdict` et la sonde centrale SentiMail existante. Le cycle porte en plus
`classifier_cycle_unhealthy` et le heartbeat du caretaker ; aucun nouveau runtime,
tunnel ni port n'est créé.

## Premier essai, 23 septembre 2026

Export : 3 148 exemples enseignants, 205 dossiers humains dont 200 exportables,
une annotation experte, cinq conflits et six labels non matérialisés.
Entraînement : 1 224 groupes (1 expert, 1 223 enseignants), 836 positifs et 388
autres. Validation enseignante : 19 candidats sur 283, zéro divergence de
livraison ; test enseignant : 18 sur 266 (6,8 %), zéro divergence. Aucun exemple
expert dans la validation ou le test : activation contraignante refusée.
Cette couverture porte sur des groupes historiques et ne prédit pas directement
la part du trafic futur ni l'économie totale du pipeline.
