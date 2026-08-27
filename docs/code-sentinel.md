# Code Sentinel

Le Code Sentinel sépare quatre responsabilités :

1. les faits immuables issus du SMTP et du message ;
2. les hooks qui observent ces faits sans décider ;
3. les articles versionnés qui donnent un sens et des limites aux indices ;
4. le verdict, produit plus tard et toujours rattaché aux preuves utilisées.

## Contrat des hooks

Chaque hook possède un nom stable, une version et un délai maximal. Il retourne :

- ses faits de travail ;
- zéro ou plusieurs indices ;
- pour chaque indice, un article, une direction, une force, une confiance,
  une explication et une provenance.

Une erreur de hook est enregistrée et n'arrête ni les autres hooks ni le SMTP.
La liste ordonnée des hooks est définie une seule fois dans `dossier/pipeline.py`.

## Mode décisionnel

Le moteur est activé par `SENTINEL_V3_DECISION_MODE` et applique le comportement
suivant :

- `legitimate` : original délivré intact, action SMTP distincte pour signaler
  une erreur ;
- `suspect`, `dangerous`, `undetermined` : notification SentiMail délivrée,
  original conservé en attente ;
- réponse authentifiée sur l'adresse MAIA : demande de libération ou correction du
  verdict ;
- un message déjà livré ne peut pas être retiré de la boîte.

Quatre faits du dossier interdisent la livraison quelle que soit la conviction
du verdict final : analyse profonde incomplète, enquête statique incomplète, preuve
matérielle de danger, retenue authentifiée demandée par l'utilisateur. Ils lui
sont énoncés explicitement. Un verdict qui les ignore est rejeté avant de
devenir contraignant, et sa seule issue restante est appliquée : demander l'avis
de l'utilisateur. Rejouer le modèle sur un fait immuable dépenserait des appels
pour aboutir au même ordre, et une couverture URL limitée n'appartient pas à
cette liste.

Le moteur reçoit avant de statuer le seuil de confiance, l'état réel des analyses,
la couverture URL, les preuves matérielles et les règles SMTP authentifiées de
l'utilisateur. Il rend à la fois la classification et l'ordre final `deliver` ou
`ask_user`. Une réponse incohérente est rejetée et rejouée ; elle
n'est jamais corrigée ou contredite après coup par une politique de livraison.
Des confirmations humaines cohérentes peuvent abaisser progressivement le seuil
de confiance de 0,90 jusqu'à 0,82. Elles ne créent jamais d'immunité absolue.

Le SMTP accuse réception uniquement après la transaction de capture. Une panne
de base renvoie un code temporaire. Une retenue et son avis MAIA sont créés dans
la même transaction : l'état `held` ne peut donc pas précéder la mise en file de
l'avis. La capture PNG est facultative et ne bloque jamais la synthèse texte.
Si la construction de l'avis échoue, si les cinq envois SMTP échouent, ou si la
file reste bloquée dix minutes, l'original est automatiquement livré en mode de
secours. Cette livraison est journalisée et réessayée en cas de panne SMTP.

Un réconciliateur examine aussi les anciens dossiers toutes les quelques
secondes. Il recrée l'avis d'une retenue orpheline après une minute ; s'il ne
peut pas garantir cet avis, il déclenche la livraison de secours. Le watchdog
compte séparément les retenues non protégées et silencieuses et alerte même si
SentiMail était déjà dans un autre état dégradé.

Les jetons ne sont conservés qu'après hachage. Ils authentifient le rattachement
au dossier ; le texte saisi par l'utilisateur est ensuite interprété par MAIA.

## Conversation SMTP

Le canal conversationnel utilise `maia@sentinel.mondomaine.example`. Pour chaque dossier
retenu, l'assistant envoie une synthèse, une capture neutralisée et demande une
directive libre. La réponse revient au collecteur uniquement par SMTP.
L'utilisateur autorisé peut aussi écrire spontanément à cette adresse ; MAIA
répond comme un ami de confiance et conserve le fil par un jeton dédié.

Le `Message-ID` de la question contient un jeton HMAC déterministe et à durée
limitée. Seul son SHA-256 est conservé. `In-Reply-To` rattache la réponse au bon
dossier ; l'adresse de l'expéditeur doit aussi correspondre au destinataire du
message original. Une conversation libre ne peut être ouverte que par
`operateur@mondomaine.example`.

Le texte cité et la signature sont retirés avant l'analyse par DeepSeek. Le
modèle produit une interprétation structurée, bornée par des valeurs autorisées.
Cette interprétation est persistée et MAIA répond par SMTP avec ce qu'elle a
compris. Seule une action également reconnue explicitement par la politique
déterministe peut libérer l'original. Une qualification explicite non
contradictoire devient un label humain d'apprentissage. Une panne du LLM génère
une demande de reformulation et ne modifie jamais une livraison.

Deux rôles logiques sont isolés et chacun a son fournisseur configurable
séparément : le moteur applique le Code Sentinel et rend un verdict final ;
MAIA comprend les réponses et répond exclusivement par email SMTP.
L'amorçage par email active les deux rôles avec le même choix, mais rien
n'empêche ensuite de donner à la conversation un fournisseur différent de
celui du verdict - voir « Configuration du moteur et de l'identité ».
DeepSeek V4 Pro reste le choix initial, mais Claude et ChatGPT sont supportés.
Le validateur local contrôle le schéma, les références probatoires et la
cohérence avec le Code avant d'accepter le verdict ; une fois accepté,
l'exécuteur l'applique littéralement.

Le moteur organise, dans un seul appel LLM, un examen contradictoire en trois
temps. L'étape défavorable ne peut citer que les indices défavorables présents
dans le dossier. L'étape favorable ne peut citer que les indices favorables
présents. Le verdict final confronte ensuite ces preuves dans le contexte réel du message : une urgence liée
à un code à usage unique n'a par exemple pas la même portée qu'une urgence liée à
un virement. Il décide en dernier ressort de livrer ou de demander l'avis de
l'utilisateur. Les codes cités par le modèle sont validés contre les indices
réellement observés ; une preuve inventée ou un verdict contradictoire invalide
la réponse du modèle et provoque un nouveau verdict, jamais un veto postérieur.

Le message envoyé au destinataire ne reprend pas ce vocabulaire. Il dit, en
français courant : ce qui gêne, ce qui rassure, ce qu'il en conclut, ce qu'il n'a
pas pu vérifier, puis ce qu'il faut répondre. Chaque phrase traduit un indice
réellement observé, sans code interne, sans score et sans terme judiciaire. Une
limite d'analyse est présentée comme telle, jamais comme un danger.

La preuve technique reste entière en base et à disposition de l'administrateur :

    docker compose exec collector python -m sentimail_v3.conversation.explain <message>

A, B et C sans texte sont des décisions déterministes : leur sens est écrit dans
le collecteur et aucun appel au fournisseur n'est effectué. Une panne, une clé
expirée ou un quota atteint ne peuvent donc pas perdre une réponse dont la
signification est déjà connue localement, et ces réponses ne consomment aucun
quota. Seuls C suivi d'une explication et le texte libre sont interprétés par le
fournisseur LLM sélectionné, dans le dossier SMTP authentifié et avec une
confiance suffisante ; toute ambiguïté laisse le message en attente et provoque
une question ciblée. Une précision écrite à côté d'un A ou d'un B est conservée
comme motif, sans jamais modifier l'action déterministe choisie.

## Ce qu'une qualification humaine apprend

Une réponse A ou B ne juge pas seulement un message : elle inscrit l'expéditeur
exact dans une liste, et elle conserve les indices qui accompagnaient ce message.
Ces indices deviennent un contexte probatoire pour les suivants : l'examen final apprend
combien de fois l'utilisateur a déjà qualifié lui-même des messages portant le
même indice, tous expéditeurs confondus, à partir de deux confirmations.

Ce profil renforce une charge déjà présente ; il n'en crée jamais et ne remplace
aucune preuve. Il reste isolé par destinataire, et disparaît dès qu'une règle est
désactivée. Les messages adressés à l'utilisateur restent donc jugés sur leurs
propres preuves, avec la mémoire de ce qu'il a déjà tranché.

## Listes d'expéditeurs par SMTP

Le registre d'apprentissage est autoportant : chaque label enregistre lui-même le
correspondant, le destinataire et l'objet témoin. Il reste donc lisible et
opposable au prochain message même après le dégonflage puis la suppression du
message d'origine par la rétention.

Les listes sont isolées par utilisateur et portent par défaut sur l'adresse exacte,
jamais implicitement sur tout un domaine. Une réponse A enregistre l'expéditeur en
liste blanche et désactive son éventuelle entrée noire ; B effectue l'opération
inverse. Chaque bascule reste auditée, visible dans le registre et réversible.

La liste blanche est une preuve à décharge et peut abaisser le seuil de confiance
jusqu'au plancher de 0,82 uniquement quand DMARC authentifie aussi l'identité
affichée. Elle ne force jamais un verdict légitime et ne contourne
ni une analyse incomplète, ni une preuve matérielle de danger, ni une politique de
retenue active. La liste noire impose la retenue des prochains messages de
l'expéditeur exact. Ce comportement limite l'impact d'une réponse erronée ou d'un
compte expéditeur ultérieurement compromis.

MAIA comprend par LLM les demandes d'export et d'import, mais la mutation reste
validée localement. « Envoie-moi la liste complète de tes règles » produit le
registre complet en CSV joint. Une adresse peut aussi être ajoutée directement par
une consigne comme « ajoute ami@example.org à la liste blanche » : l'adresse et la
liste comprises par le LLM doivent correspondre exactement au texte utilisateur.
Un import accepte un seul fichier UTF-8 de 256 Kio
maximum et 1 000 adresses : CSV `email,liste` avec `liste_blanche` ou
`liste_noire`, ou TXT avec une adresse par ligne si la directive nomme une seule
liste. Le contenu joint n'est jamais envoyé au LLM ; adresses, format, doublons et
contradictions sont contrôlés avant une transaction atomique. À la moindre erreur,
aucune ligne n'est importée.

Avant tout appel conversationnel, une barrière locale classe la demande. Les
demandes manifestement étrangères à la messagerie sont refusées sans LLM ; une
demande ambiguë autorise au maximum un appel borné qui doit confirmer le périmètre.
Les limites par défaut sont de 10 appels par conversation et par heure, 20 par
utilisateur et par heure, et 100 par utilisateur sur 24 heures. Le texte utilisateur
est limité à 8 000 caractères. Les refus et quotas sont audités avec
`llm_called=false` et n'exécutent aucune action SMTP.

Le dossier transmis au moteur de verdict exclut l'EML brut, le HTML et le contenu
binaire des pièces jointes. Il contient le texte borné, les métadonnées, les
entités, leurs enrichissements DNS/RDAP/ASN/pays, les résultats URL/fichier, les
corrélations historiques, les indices et les articles applicables. La clé API
est montée en lecture seule uniquement dans les services `verdict` et
`assistant`.

## Amorçage du fournisseur LLM par SMTP

Si aucun fournisseur actif n'est présent, MAIA prend l'initiative et envoie à
`operateur@mondomaine.example` un email lié par un jeton HMAC à durée bornée. Le message
joint un fichier `cle-api.txt` vide et demande de choisir explicitement DeepSeek,
Claude/Anthropic ou ChatGPT/OpenAI. L'utilisateur place uniquement la clé dans ce
fichier, le met seul dans un ZIP chiffré AES, puis répond au fil avec le fournisseur
choisi et le ZIP. MAIA demande ensuite le mot de passe dans un second email.

Ces deux réponses sensibles sont interceptées avant la capture générale : ni le
ZIP ni le mot de passe ne sont stockés comme emails, transmis à un LLM ou écrits
dans les logs. Le ZIP est limité à 128 Kio, doit contenir exactement
`cle-api.txt`, est protégé contre les ratios de décompression anormaux et expire
après quinze minutes. Le mot de passe est limité à trois essais. La clé est testée
par un appel minimal au modèle choisi, écrite atomiquement en mode `0600` dans le
volume de secrets, puis le ZIP chiffré temporaire est purgé. PostgreSQL ne conserve
que le fournisseur, le modèle, la date de validation et le nom du fichier secret.

La séparation ZIP/mot de passe réduit les erreurs et l'exposition dans un message
unique, mais ne protège pas contre une compromission complète de la boîte de
l'utilisateur. Le contrôle repose aussi sur le fil HMAC non devinable,
l'alignement strict de l'enveloppe SMTP avec l'en-tête From, l'adresse autorisée
et l'expiration. L'ancien `kitt@sentinel.mondomaine.example` reste un alias entrant
temporaire pour les conversations déjà émises ; tous les nouveaux messages
utilisent MAIA.

## Configuration du moteur et de l'identité

Deux tables portent la configuration vivante de l'instance, éditables depuis
l'admin (`/reglages`) sans redémarrage. Aucune des deux n'est requise pour
démarrer : tant qu'elles sont vides, l'instance fonctionne intégralement sur
son environnement de déploiement, sans watchdog externe ni base à préconfigurer.

`llm_role_providers` retient, une ligne par rôle (`verdict`, `conversation`),
le fournisseur actif : adaptateur, URL, modèle, paramètre de longueur et nom
du fichier de clé. Deux adaptateurs existent - `openai_compatible` pour
DeepSeek, OpenAI, Mistral et Ollama, `anthropic` pour Claude, qui parle un
protocole différent (`/v1/messages`, `x-api-key`, système séparé des
messages). Six préréglages remplissent ces colonnes en un geste depuis
l'admin (`deepseek`, `openai`, `mistral`, `ollama`, `anthropic`, `custom`) ;
`custom` seul reste ouvert, sans valeur imposée, et son fichier de clé se
déduit du rôle plutôt que d'être fixe, pour qu'un fournisseur maison diffère
entre verdict et conversation. La clé elle-même ne transite jamais par une
boîte aux lettres ni par cette table : elle est écrite en fichier `0600` dans
`provider_secrets_dir`, et la console qui la pose ne peut jamais la relire.

`instance_identity` est un singleton (`WHERE singleton = true`) qui retient
l'adresse d'action, ses alias, l'expéditeur des avis MAIA et le destinataire
de la sonde. Tant qu'aucune ligne n'y existe, ces quatre valeurs viennent de
l'environnement (`ACTION_ADDRESS`, `ACTION_ALIASES`, `ASSISTANT_SENDER`,
`PROBE_RECIPIENT`) ; posée une fois, la ligne prime et un bouton « Reprendre
la main » recopie l'environnement en base pour que l'exploitant en devienne
maître sans tout retaper. `instance_identity` est lue à chaud avec un cache
de 60 secondes - assez court pour qu'un changement posé en admin prenne effet
sans redémarrer un service, assez long pour ne pas requêter la base à chaque
courrier. Une base indisponible ou une table pas encore migrée retombe
silencieusement sur l'environnement : une erreur ici ne doit jamais bloquer
l'analyse ni l'envoi du courrier.

L'ordre de préséance, identique pour le moteur, est : le routage local
(`llm_local_routing`, par rôle - voir « Bascule vers un modèle local ») prime
sur la ligne de `llm_role_providers` pour ce rôle, qui prime elle-même sur les
variables d'environnement `DEEPSEEK_*`. Une instance qui n'a jamais touché ni
`llm_local_routing` ni `llm_role_providers` reste donc pleinement fonctionnelle
sur son seul environnement.

Deux exceptions restent volontairement hors de cette configuration en base et
vivent en variable d'environnement, parce qu'elles engagent autre chose que le
contenu du courrier : le nom annoncé en HELO par Postfix
(`SENTINEL_V3_MX_HOSTNAME`), qui doit correspondre à l'enregistrement MX
publié et au certificat TLS - le changer à chaud sans toucher au DNS ni au
certificat casserait la remise - et l'adresse d'écoute de l'admin
(`ADMIN_BIND_HOST`), qui est la seule frontière d'un service sans mot de
passe et doit donc rester une décision de démarrage, pas un réglage qui
prend effet en cours de service. `ADMIN_BIND_HOST` vaut par défaut l'adresse
Tailscale découverte sur l'hôte, et refuse d'écouter sur toutes les
interfaces sans l'accord explicite `ADMIN_BIND_UNRESTRICTED=true`.

Un encart de confidentialité, affiché en permanence sur `/reglages` et sur
`/etat`, dit rôle par rôle où part le contenu du courrier : soit vers l'URL du
fournisseur distant configuré, soit vers le modèle local si `llm_local_routing`
sert ce rôle - auquel cas rien ne sort, et un repli distant éventuel est
signalé en clair. C'est la seule information technique montrée à cet endroit :
l'exploitant sait toujours, sans avoir à l'interroger, où l'instance envoie le
contenu qu'elle examine.

## Couverture et corrélations

Les dix hooks synchrones examinent structure, cohérence d'identité, en-têtes,
authentification, Rspamd, chaîne Received, contenu, nature de l'envoi, URL et
pièces jointes. L'analyse profonde
ajoute les redirections et formulaires observés dans le sandbox URL, YARA,
macros, PDF, archives et OCR dans le sandbox fichier, ainsi que l'âge du domaine,
DNS, RDAP, ASN et pays.

L'âge exact et la date de création du domaine deviennent une preuve à décharge
quand le domaine est établi depuis au moins deux ans ; l'absence de donnée RDAP
reste une limite neutre et jamais une charge. Les symboles RBL/DBL de Rspamd sont
utilisés comme preuves de réputation bornées. L'absence de symbole de réputation
défavorable constitue seulement une faible décharge, pas un certificat de bonne
réputation. Les mélanges Unicode latin/cyrillique/grec et le punycode sont des
charges matérielles d'homographie. Les simples ambiguïtés ASCII comme `0/o` ou
`1/l/I` sont consignées mais restent neutres sans marque ou domaine de référence.
Un domaine IDNA/punycode constitué d'un seul script reste lui aussi neutre ; seul
un mélange de scripts ou une comparaison de référence peut devenir une charge.

Le contexte historique compare le même expéditeur sur le volume antérieur, les
labels humains, l'heure UTC, la taille moyenne et son écart-type, la fréquence
des pièces jointes et les pays de transport. Première observation, domaine
récent et heure/taille/pays inhabituels deviennent des indices explicites.

L'inspection URL regroupe les variantes texte/HTML équivalentes sur un même apex,
préserve séparément les libellés génériques pointant vers des articles distincts,
priorise les formulaires et appels à l'action, puis échantillonne chaque apex avant
d'approfondir une destination. Le budget s'adapte de 20 à 40 représentants selon
la diversité des apex. Le verdict final reçoit le nombre d'URL, de représentants, d'apex
couverts et de représentants non inspectés. Ce plafond est un contexte de
couverture, pas une incomplétude automatique. Seul un échec réel du sandbox ou
d'une pièce jointe rend la chaîne matériellement incomplète et impose le doute.

## Nature de l'envoi

Le reste du Code cherche la tromperie : usurpation, coercition, collecte de
secrets. Un envoi commercial de masse n'emprunte aucun de ces chemins, et son
absence de pression finissait donc par lui valoir un indice favorable.

Le hook `nature` décrit d'abord le cadre d'envoi à partir des seuls en-têtes
normalisés : `List-Unsubscribe`, `List-Id`, `Precedence`, `Feedback-ID`,
`Auto-Submitted`. Il distingue ainsi diffusion de masse, message automatique et
échange conversationnel. Ce cadre est un fait, jamais une intention : un envoi de
masse demandé par le destinataire reste parfaitement légitime.

Le caractère non sollicité naît de la conjonction, établie plus tard avec
l'historique : un envoi de masse dont l'expéditeur n'a aucun échange antérieur ni
confirmation humaine ne peut se prévaloir d'aucun abonnement consenti. Ce signal
est faible et disparaît dès le premier échange ou la première confirmation.

Le registre du discours vient en dernier et pèse peu : des promesses
invérifiables de santé ou d'enrichissement décrivent une rhétorique de
sollicitation, jamais un produit ni un secteur. Il ne peut pas fonder seul une
qualification de danger.

En contrepartie, l'absence de pression ne qualifie plus que le risque de
coercition. Elle ne crédite plus un envoi de masse, dont la légitimité dépend du
lien d'abonnement et non du ton employé.

## Rendu des captures

Le screenshot est produit par le renderer isolé hérité de SentiMail V2 : HTML nettoyé,
réseau coupé, JavaScript désactivé, formulaires et liens retirés, ressources
distantes bloquées et QR codes masqués. Les images CID sont incorporées dans un
budget de 5 Mio. La capture est tronquée à 1 200 px de haut : un corps dégradé
peut s'étendre sur des dizaines de milliers de pixels vides que la miniature de
l'avis transformerait en cadre blanc. Le PNG est joint à l'email MAIA ; en cas d'échec, la synthèse
texte reste envoyée. Une capture neutralise l'exécution, mais pas le risque
psychologique d'un texte trompeur : l'avertissement reste donc affiché.

## La référence d'un dossier

Un identifiant interne est un UUID : personne ne le lit à voix haute, personne
ne le recopie dans un échange, et un dossier dont on ne peut pas parler ne peut
pas être instruit. Chaque dossier porte donc une **référence courte** : une
lettre qui dit de quoi il s'agit, six caractères qui disent lequel.

| Forme | Objet | Où on la voit |
|---|---|---|
| `M-e9e8f2` | un message capté | `/courrier`, avis MAIA, journaux |
| `E-c62805` | un écart humain/modèle | `/ecarts` |
| `D-3f9c1a` | un récapitulatif | la lettre elle-même |

Elle est **dérivée** de l'identifiant du dossier, jamais stockée : rien à
migrer, et la même référence désigne le même dossier sur n'importe quelle copie
de la base. Elle n'est pas un secret - elle situe, elle ne protège rien.

Le bandeau de la console porte un champ « Aller au dossier » : y coller une
référence ouvre la page qui la concerne, quelle que soit celle d'où l'on vient.
`D-` est reconnu pour pouvoir dire qu'il vit dans une lettre et non dans une
table, plutôt que de renvoyer une erreur de saisie.

La forme est écrite deux fois - `sentimail_v3.code.reference` et
`sentimail_admin.reference` - parce que les deux images n'ont pas de source
commune. Toute évolution doit toucher les deux fichiers ensemble.

## Journalisation et diagnostic

Le collecteur, le moteur de verdict et MAIA écrivent des événements JSON sur
leur sortie standard. Un dossier peut être suivi de bout en bout avec les
identifiants internes `message_id`, `investigation_id`, `run_id`,
`conversation_id`, `conversation_message_id` et `outbox_id`. Toute ligne qui
porte un `message_id` porte aussi son champ `dossier` : l'identifiant reste,
parce qu'il est exact ; la référence vient à côté, parce qu'elle est celle
qu'on lit.

Les événements principaux sont :

- `message.captured`, `message.delivered` et `message.relay_deferred` pour le
  trajet SMTP ;
- `verdict.processing_started`, `verdict.complete` et `verdict.error` pour le
  verdict DeepSeek ;
- `directive.processing_started`, `directive.interpreted` et
  `directive.error` pour les réponses comprises par MAIA ;
- `outbox.sent` et `outbox.error` pour les réponses SMTP de MAIA.

Chaque événement contient un horodatage UTC et un niveau `info`, `warning` ou
`error`. Les journaux contiennent les étapes, tentatives, durées, résultats SMTP,
modèles, versions de prompt, classifications, identifiants de requête API et
compteurs de jetons. Ils n'enregistrent jamais l'objet, le corps, les pièces
jointes, le texte envoyé au LLM, les adresses complètes, les jetons d'action ou
les clés API. Seuls les domaines d'expéditeur et de destinataire sont exposés
quand ils facilitent le diagnostic.

Docker conserve cinq fichiers de 20 Mio par service. La base PostgreSQL reste
la source durable pour l'audit, la reproductibilité des verdicts et les
conversations ; les logs servent à reconstruire rapidement la chronologie
d'exécution sans dupliquer le contenu sensible des emails.

## Fin de vie d'une retenue

Un message retenu attend une décision humaine. Sans échéance, cette attente
devient un abandon silencieux. Après `HOLD_REMINDER_AFTER_DAYS` (trois jours par
défaut) sans aucune réponse, MAIA relance une fois par fenêtre et rouvre un
canal. Après `HOLD_DECISION_AFTER_DAYS` (trente jours), la retenue est tranchée :
un message qualifié de dangereux, ou dont l'expéditeur est en liste noire, est
classé sans être livré ; tout autre est livré avec sa mise en garde. Les deux
issues sont annoncées à l'utilisateur, auditées et réversibles.

Toute directive exécutée reçoit désormais une réponse, qui porte un nouveau
jeton. Sans elle, le jeton du dossier était consommé et l'utilisateur ne pouvait
plus se raviser. Une livraison fait exception : l'original livré porte déjà son
propre retour SMTP.

## Historique d'exploitation

L'état courant répond à « que se passe-t-il maintenant ». Chaque transition est
aussi conservée dans `operational_events`, ce qui répond à « est-ce que cela
arrive souvent » : un instantané ne peut pas y répondre, et les journaux
repartent de zéro à chaque redéploiement. Seules les transitions sont écrites,
et la fenêtre de suppression de la rétention s'y applique.

    docker compose exec collector python -m sentimail_v3.supervision.uptime --days 7

La santé publiée par le conteneur du superviseur est la sienne, pas celle du
système qu'il observe : un SentiMail dégradé se signale par son alerte et par
`operational_status`. Marquer le superviseur en panne pour autant ferait croire
à un observateur muet et bloquerait toute dépendance de service. Il ne se déclare
en panne que lorsqu'il ne peut plus alerter.

## Chiffrement de l'original

La rétention borne la durée pendant laquelle l'original existe ; elle ne dit
rien de sa confidentialité pendant ce temps, et une sauvegarde chiffrée ne
protège pas la base elle-même. L'EML est donc chiffré en AES-256-GCM avant
d'être écrit, avec une clé de 32 octets montée en secret lecture seule dans les
seuls services qui lisent ou écrivent l'original.

L'empreinte, les mesures et l'analyse portent sur le message original : seul son
stockage change. Le format porte un préfixe, si bien qu'un contenu hérité en
clair reste lisible et que la bascule se fait sans interruption. Sans clé
configurée, la capture continue en clair plutôt que d'échouer ; avec une clé, un
contenu chiffré n'est jamais rendu en silence si elle vient à manquer.

    docker compose exec collector python -m sentimail_v3.execution.encrypt_at_rest --apply

**La clé est le seul moyen de relire les originaux, y compris depuis une
sauvegarde.** Elle vit dans `secrets/raw_eml_key` sur le serveur et dans le
trousseau macOS sous `sentimail-v3-raw-eml-key`. La perdre rend tous les messages
conservés définitivement illisibles.

## Rétention

Un service dédié applique chaque heure une fenêtre en deux étages. Il refuse de
démarrer une passe si la fenêtre est plus courte que sept jours ou si la
suppression précède le dégonflage.

Après `RETENTION_REDACT_AFTER_DAYS` (30 jours par défaut), le contenu est effacé :
EML brut, corps texte et HTML, parties MIME, captures de revue, corps échangés
avec MAIA et pièces jointes déjà envoyées. Les en-têtes de trace et de sécurité
restent lisibles, car ils portent la preuve du trajet et de l'authentification.

Après `RETENTION_DELETE_AFTER_DAYS` (180 jours par défaut), le message et ses
tables filles sont supprimés, avec les événements d'appel LLM, les
enrichissements devenus orphelins et les seules entrées d'audit techniques à fort
volume.

Ne sont jamais purgés : les labels d'apprentissage, les listes d'expéditeurs, les
directives écrites par l'utilisateur, les interprétations qui en découlent et le
reste du journal d'audit. Un message encore en attente de décision n'est jamais
touché : sans original, une libération deviendrait impossible.

Chaque passe est tracée dans `audit_log` et dans `operational_status`. Le
superviseur compte séparément les messages qui auraient dû être dégonflés depuis
plus de deux jours : une rétention arrêtée devient une dégradation visible, pas
une conservation silencieuse. L'espace libéré est réutilisé par PostgreSQL pour
les écritures suivantes ; il n'est pas rendu au système sans réindexation
explicite.

## Superviseur anti-soft-fail

Un superviseur déterministe, indépendant de MAIA et du fournisseur LLM, contrôle
chaque minute qu'aucun échec partiel ne reste silencieux. Il surveille les hooks
en erreur, les investigations partielles, l'absence d'un des neuf hooks requis,
l'absence d'analyse profonde avant verdict, les enrichissements de domaine
manquants, les erreurs des sandbox externes et les erreurs d'interprétation des
réponses SMTP. Une livraison sans événement SMTP ou sans identifiant de mise en
file est elle aussi considérée comme dégradée. Il conserve jusqu'à douze exemples corrélés par message et
composant pour le diagnostic.

Tout compteur non nul place SentiMail en état dégradé et déclenche une alerte
SMTP lors de l'apparition d'une nouvelle cause ou d'une nouvelle occurrence. Les
occurrences sont agrégées par minute pour éviter une alerte par message. Ce
contrôle complète les garanties
de terminaison : après acceptation SMTP, chaque message doit soit être livré,
soit avoir un avis MAIA effectivement envoyé ; une retenue silencieuse entraîne
la livraison de secours. Les modules d'analyse peuvent donc rester fail-soft pour
ne pas interrompre le relais SMTP, mais leur dégradation n'est jamais un
fail-silent.

Le superviseur compare aussi chaque ordre final à l'état du dossier et du
message. Un ordre `deliver` encore retenu, un verdict absent du dossier ou une
divergence entre le verdict persisté et son exécution devient immédiatement un
`verdict_execution_mismatch` corrélé au message et déclenche l'alerte SMTP.

## Répondre à une question sans sortir de sa boîte

Une directive dit quoi faire d'un message ; une question attend une réponse.
Quand MAIA reconnaît une question de messagerie (`answer_question`), une boucle
bornée consulte la base pour son auteur : messages en attente, historique et
issue, motifs d'une retenue, listes enregistrées, statistiques.

Deux bornes tiennent cette liberté. Le destinataire n'est jamais un paramètre
choisi par le modèle : il vient du dossier de conversation authentifié et il est
injecté par le code à chaque consultation, ce qui rend inatteignable la boîte
d'un autre utilisateur, quelle que soit la formulation employée. Et la boucle
s'arrête après quatre consultations, avec ce qu'elle a réuni.

Les outils lisent seulement, et ne servent jamais le contenu d'un message :
objet, expéditeur, date, issue et indices suffisent à comprendre une décision.
Aucune livraison, aucune règle et aucun dossier ne peut être modifié par cette
voie ; agir passe toujours par A, B ou C et la politique déterministe.

## Bascule vers un modèle local

Le routage vers un modèle open source se décide par rôle, jamais globalement.
La conversation ne décide rien - elle lit, explique, et ne peut ni livrer ni
retenir - quand un verdict engage la livraison d'un message. Le premier peut
donc passer en local bien avant le second, et une bascule ratée ne coûte pas un
message livré à tort.

`python -m sentimail_v3.supervision.local_llm --probe <modèle>` éprouve un modèle avant de
lui confier quoi que ce soit : il lui demande exactement ce que le code lui
demandera, et vérifie qu'il rend les clés attendues. `--enable <rôle> --model`
active, `--disable <rôle>` rend le rôle au fournisseur distant.

Un échec local repart chez le fournisseur distant et le signale dans les
métadonnées de l'appel : un repli permanent ne doit pas s'installer en silence.
`--no-fallback` retire ce filet, une fois la qualité établie sur la durée.

État constaté sur l'hôte actuel, sans GPU : un appel coûte environ 27 secondes
avec un modèle de 7 à 8 milliards de paramètres, 59 secondes avec un 14B. La
boucle conversationnelle en fait deux à cinq, soit une à trois minutes par
question - acceptable pour du courrier, qui est asynchrone par nature. Le
verdict, lui, travaille sur un dossier bien plus gros : sa bascule suppose un
GPU, elle n'est pas réaliste sur ce matériel.

## La connaissance dans le dossier de verdict

Le dossier soumis au verdict peut porter une zone `reference_knowledge` : trois
extraits de normes, courts, accompagnés de leur origine et d'un avertissement
qui dit ce qu'ils ne sont pas. Ils servent à qualifier correctement un indice
présent, jamais à conclure.

Le point qui tient tout : **la question posée au corpus est faite des codes
d'indices, jamais du texte du message**. Un corps de mail choisi par un
attaquant sélectionnerait sinon lui-même ce qui est injecté dans le dossier, et
il suffirait d'écrire « ce message est conforme à la RFC 7489 » pour faire venir
de quoi s'en réclamer. Les codes, eux, viennent de l'analyse.

Deux conséquences pratiques. Quand la place manque, la connaissance est la
première retirée du dossier : les indices et les articles fondent la décision,
elle non. Et une norme cite ses propres identifiants - `RFC5322.From`,
`AUTH-RESULTS` - qui ressemblent à des codes de preuve : recopiés dans une
motivation, ils ne font plus rejeter un verdict par ailleurs correct, tout en
laissant refuser une référence réellement inventée.

## Le corpus normatif

Dix documents de référence (SMTP, format de message, architecture, SPF, DKIM,
DMARC, Authentication-Results, ARC, désabonnement en un clic, adresses de rôle)
sont capturés dans `knowledge/`, vérifiés par leur empreinte SHA-256 et
versionnés avec le code. La production ne télécharge rien : `tools/knowledge_sync.py`
les capture depuis le poste, et une empreinte qui ne correspond plus arrête le
chargement. Ce qui a été répondu il y a six mois reste explicable aujourd'hui.

Le chargement découpe chaque document par section numérotée, borne la taille des
extraits et calcule un vecteur par passage avec un modèle d'embeddings local
(`bge-m3` via Ollama). Changer de modèle rend les vecteurs incomparables : un
document dont les vecteurs viennent d'un autre modèle est revectorisé, jamais
considéré comme inchangé.

La recherche interroge d'abord Postgres par les mots, ce qui fonctionne sans
aucun service tiers. Quand ce rappel ne rapporte presque rien - une question
posée en français sur un texte anglais - le corpus entier est balayé par
similarité, avec un seuil de proximité qui préfère ne rien répondre plutôt que
de servir un passage sans rapport. Si l'embedding est indisponible, l'ordre
lexical reste et la réponse aussi.

Cette connaissance explique, elle ne prouve rien. Aucun passage de RFC ne crée
un indice, ne lève une barrière matérielle ni ne modifie un verdict : elle est
servie à l'agent conversationnel, jamais au moteur probatoire.

## Le budget d'appels au modèle

Deux plafonds se cumulent, et ils ne servent pas la même chose. Celui du domaine
assure l'équité : nul ne mange la part d'autrui. Le plafond global reste
au-dessus, car la dépense totale, elle, est commune.

Les verdicts se comptaient globalement : un domaine qui reçoit beaucoup épuisait
le quota des autres, et ces autres basculaient en retenue sans que rien chez eux
ne l'explique. Les échanges se comptaient par adresse, ce qui protège un
utilisateur d'un autre mais aucun domaine de son voisin.

Un domaine peut fixer ses propres plafonds dans `domains` ; une valeur absente
signifie « comme tout le monde », jamais « sans limite ». Le verrou de
réservation porte sur le domaine : verrouiller sur l'adresse laisserait deux
utilisateurs d'un même domaine franchir ensemble le plafond commun.

## Où vit quoi

Les modules sont rangés selon ce qu'ils font, pas selon leur ancienneté :

- `observation/` capte le courrier et le décrit : réception SMTP, analyse,
  enrichissement, constitution du dossier. Rien n'y décide, tout y constate.
- `code/` porte la règle applicable : articles, listes de l'utilisateur,
  autorisation des domaines, vocabulaire en clair, normes de la messagerie.
- `judgment/` tranche : éléments favorables et défavorables confrontés, verdict
  final et décision de livraison.
- `execution/` agit sur le courrier : livrer, retenir, chiffrer, purger. Elle
  applique un verdict, elle ne le réévalue jamais.
- `conversation/` parle à l'utilisateur, et seulement par SMTP.
- `supervision/` surveille l'ensemble : santé, cohérence, rejeu, mesure.

`config`, `crypto` et `llm` restent à la racine : transverses par nature,
ils n'appartiennent à aucun des six.

## Verrous contre l'empoisonnement et l'usurpation

Le contenu d'un email, les indices, la directive utilisateur et la réponse de
DeepSeek sont quatre objets distincts. Aucun texte provenant d'un email n'est
une instruction système et aucune sortie LLM n'est une autorisation. Le moteur
reste non contraignant ; toute action passe par une politique déterministe
indépendante du modèle.

Cette politique compare les verbes et qualifications explicitement écrits par
l'utilisateur à l'action et au verdict compris par MAIA. Si le LLM invente
une action, inverse « livre » et « ne livre pas », ou contredit une qualification
explicite, l'action et le label sont annulés. MAIA demande alors une
reformulation. La sortie brute du modèle et la décision de la politique sont
conservées séparément pour l'audit.

L'adresse `maia@sentinel.mondomaine.example` n'est pas un secret et ne prouve aucune
identité. Une réponse à MAIA doit présenter un jeton HMAC aléatoire, à durée
limitée et à usage unique ; seul son SHA-256 est stocké. Une conversation
spontanée exige un challenge envoyé exclusivement à la boîte protégée, puis une
réponse `CONFIRME MAIA <code>` portant le code à usage unique tiré pour ce
challenge. La phrase seule ne confirme plus rien : elle est publique, donc un
expéditeur usurpé pouvait la répondre sans jamais lire la boîte challengée. Le
code n'existe que dans ce courrier, n'est conservé que haché, vaut cinq minutes
et ne donne droit qu'à une tentative — bonne ou mauvaise, la réponse consomme
l'action, ce qui interdit d'essayer les codes un par un. Avant cette preuve de
possession, le texte n'est jamais transmis au moteur LLM. Les challenges sont
limités à un par tranche de cinq minutes pour éviter qu'une adresse `From`
usurpée ne provoque une boucle d'emails.

Enfin, seul le premier résultat d'authentification ajouté en tête par
`rspamd.sentimail` est pris en compte. Un faux `Authentication-Results` injecté
plus bas dans le message ne peut donc pas remplacer le verdict du relais de
confiance.
