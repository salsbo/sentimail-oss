---
author: J. Martin
lastModifiedBy: J. Martin
date: 2026-10-30
---

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

Le moteur est organisé en modules de faits, règles, préparation du modèle,
validation, acceptation et exécution. Chaque capture et chaque reprise gardent une
génération immuable. Le plan exécuté est conservé avec le run. La génération
`core-v1` est activée par une qualification sur le code et le corpus exacts,
après comparaison indépendante avec le moteur historique. Une comparaison ne
produit ni second appel au modèle ni seconde livraison. La procédure et les
limites de cette preuve sont décrites dans la
[refonte du cœur](refonte-2026-10-30.md).

Le moteur est activé par `SENTINEL_V3_DECISION_MODE` et applique le comportement
suivant :

- `legitimate` : original délivré intact, action SMTP distincte pour signaler
  une erreur ;
- `suspect`, `dangerous`, `undetermined` : notification SentiMail délivrée,
  original conservé en attente ;
- réponse authentifiée sur l'adresse MAIA : demande de libération ou correction du
  verdict ;
- un message déjà livré ne peut pas être retiré de la boîte.

Cinq faits du dossier interdisent la livraison quelle que soit la conviction
du verdict final : analyse profonde incomplète, enquête statique incomplète, preuve
matérielle de danger, retenue authentifiée demandée par l'utilisateur, et
contradiction entre promesse et destination avec identité non établie (CORR-019). Ils lui
sont énoncés explicitement. Un verdict qui les ignore est rejeté avant de
devenir contraignant, et sa seule issue restante est appliquée : demander l'avis
de l'utilisateur. Rejouer le modèle sur un fait immuable dépenserait des appels
pour aboutir au même ordre, et une couverture URL limitée n'appartient pas à
cette liste.

Une pièce jointe restée sans inspection rend toujours l'analyse incomplète
décisive. L'authentification prouve qui écrit, pas ce que contient le fichier :
un domaine aligné DMARC s'obtient en une heure, et un fichier que le bac à sable
n'a pas ouvert reste inconnu, quel que soit l'expéditeur. Cela couvre la panne
du service, le délai dépassé, la partie introuvable, le débordement du budget de
dix documents, de cent images matricielles (les types non enregistrés
`image/x-png` et `image/jpg`, encore déclarés par des expéditeurs authentifiés,
comptent comme images) et l'indice ATT-019. Les fichiers
ont aussi un budget cumulé de 25 Mio et de 120 secondes. Chaque fichier hors
budget reste explicitement marqué non inspecté ; aucun échantillon d'images
ne tient lieu d'inspection complète. Un lien qui refuse le bac à sable ne dérange
toujours pas un expéditeur authentifié sans charge. Mesure du 29 septembre
2026 : sur les 32 jours de la règle précédente, 7 messages ont été livrés sans
que leur pièce jointe soit inspectée, tous parce que le parseur et le bac à
sable ne définissaient pas la pièce jointe de la même façon (invitations et
images sans nom de fichier, de 4 à 7 ko). La définition est désormais unique.
Après correction, la règle aurait retenu 1 message sur 60 jours (service
fichier injoignable) et la lettre hebdomadaire d'un expéditeur autorisé qui
dépasse dix images.

Les règles du jugement (preuve matérielle, charge forte, couverture et
convergence des familles) se calculent sur la liste complète des indices, avant
l'ajustement du dossier à la taille du contexte du modèle. Le modèle peut lire
une vue tronquée ; la barrière, jamais.

Le moteur reçoit avant de statuer le seuil de confiance, l'état réel des analyses,
la couverture URL, les preuves matérielles et les règles SMTP authentifiées de
l'utilisateur. Il rend à la fois la classification et l'ordre final `deliver` ou
`ask_user`. Une réponse incohérente est rejetée et rejouée ; elle
n'est jamais corrigée ou contredite après coup par une politique de livraison.
Des confirmations humaines cohérentes peuvent abaisser progressivement le seuil
de confiance de 0,90 jusqu'à 0,82, sur un message dont DMARC authentifie
l'identité. Elles ne créent jamais d'immunité absolue.

Le SMTP accuse réception uniquement après la transaction de capture. Une panne
de base renvoie un code temporaire. Une retenue et son avis MAIA sont créés dans
la même transaction : l'état `held` ne peut donc pas précéder la mise en file de
l'avis. Cet avis est une fiche texte et HTML sans rendu actif. Il montre
l'adresse affichée et l'adresse d'enveloppe, une photo inerte du message
(miniature dans le corps, capture pleine jointe) et au plus trois extraits
textuels inertes pour que le destinataire sache quel contexte il doit juger.
Si la mise en file de l'avis échoue trois fois de suite (nouvelle tentative
après une puis trois secondes), si les cinq envois SMTP échouent, ou si la file
reste bloquée dix minutes, le mode de secours relit le dernier jugement du
dossier avant d'agir - il ne le retouche jamais : classification,
delivery_decision et filed_as_junk restent ceux que le juge a écrits. Un
message classé dangereux, ou qui porte une preuve matérielle de danger (un
indice défavorable rattaché à un article actif marqué
delivery_barrier=material_danger), reste retenu, et le superviseur lève
`fail_closed_holds` jusqu'à ce que l'avis parte ou qu'un exploitant tranche :
ce n'est pas une seconde décision qui contredirait le juge, c'est l'exécution
de sa décision qui attend de pouvoir se faire sans risque. Un message classé
indésirable part dans Indésirables, sous l'enveloppe neutralisée ; si cette
enveloppe elle-même ne peut pas être composée pour un message dangereux, le
même principe s'applique - l'ordre du juge (le classer en indésirable) n'est
pas annulé, son exécution est différée jusqu'à ce qu'un exploitant relance la
livraison avec le même classement. Le reste, douteux ou indéterminé sans
preuve matérielle, est livré en boîte de réception : perdre en silence un
message légitime coûte plus que livrer un douteux sans son avis. Chaque secours
est journalisé (`review.fail_open_requested` avec sa route,
`review.fail_closed`), réessayé en cas de panne SMTP, et remonte au
superviseur. Sur sept semaines de production, un seul secours s'est déclenché
(15 août 2026, un douteux, clos non distribuable) ; sept retenues sur soixante
jours auraient relevé de la retenue fermée, et aucune n'aurait concerné un
message que le juge avait classé légitime - cette route ne s'ouvre jamais sur
un verdict deliver.

Un réconciliateur examine aussi les anciens dossiers toutes les quelques
secondes. Il recrée l'avis d'une retenue orpheline après une minute ; s'il ne
peut pas le garantir, il applique le même secours. Une retenue fermée dont
l'avis n'est jamais parti est retentée au plus trois fois, à dix minutes
d'intervalle ; un avis épuisé ou bloqué ne l'est pas, faute de pouvoir le
recréer. Le watchdog compte séparément les retenues non protégées,
silencieuses et fermées, et alerte même si SentiMail était déjà dans un autre
état dégradé.

Les jetons ne sont conservés qu'après hachage. Ils authentifient le rattachement
au dossier ; le texte saisi par l'utilisateur est ensuite interprété par MAIA.

## La voie rapide des codes à usage unique

Un code de connexion attend derrière un écran : quarante-cinq secondes
d'inspection profonde suffisent à le périmer. La voie rapide
(`code/one_time_code.py`, appelée par `_express_judgment` avant toute analyse
profonde) livre donc sans juge un message qui remplit toutes ces conditions à
la fois :

- le hook contenu y a lu un code fourni et non demandé (CONTENT-008,
  CONTENT-009 ou CONTENT-010) ;
- le texte montre le code lui-même : quatre à huit chiffres, ou deux groupes
  de trois, près du mot « code ». Un lien « sécurisé » sans code n'ouvre pas
  la voie, un code promo non plus ;
- DMARC passe pour le domaine affiché ;
- l'adresse exacte de l'expéditeur a déjà été reçue par ce client,
  authentifiée, il y a au moins sept jours, après un jugement complet ; aucune
  règle B ni aucune étiquette spam ou dangereux ne la vise ;
- aucun indice adverse, aucun code de la liste de fermeture, aucune pièce
  jointe ;
- tous les liens restent chez l'expéditeur.

Une première observation ne part jamais par cette voie : c'est l'analyse
complète, et son enquêteur `sender_relation`, qui confronte une première fois
le nom revendiqué au domaine réel. La voie rapide ne se confirme pas
elle-même : un message qu'elle a livré ne compte pas dans l'ancienneté. Un
message livré sans aucun jugement, avec le seul verdict d'observation
(livraison de secours, courrier d'avant le mode décisionnel), ne compte pas non
plus : il n'a jamais été examiné. Le code montré ne prouve rien sur
l'expéditeur, un fraudeur peut écrire six chiffres ; il dit seulement que le
message est bien un code. La sécurité tient à l'adresse déjà reçue. Un vrai
code écarté passe par le chemin complet : il arrive plus tard, il n'est pas
perdu. La valeur du code n'est jamais écrite en base ni dans les journaux :
chaque candidat laisse une ligne `verdict.express_considered` qui ne porte que
trois booléens (`established`, `code_visible`, `granted`).

La liste de fermeture ne garde que des codes qu'un hook synchrone émet, et un
test le vérifie : la décision précède l'analyse profonde, et un code
qu'aucun hook synchrone ne produit ne referme rien. `RSPAMD_PHISHING_HEURISTIC`,
`RSPAMD_HIGH_SCORE` et `URL_DECEPTIVE_LINK_TEXT` y restent : l'observation les
pose aujourd'hui toujours en neutre, la règle de charge ne les voit donc pas.

Mesure du 29 septembre 2026, sur les 9 verdicts `express_path` de la
production (20 août au 27 septembre) : 2 restent rapides, deux codes de
connexion d'adresses connues. 7 sortent. Deux étaient hors cible : un faux avis
de double authentification du 1er septembre (M-61c057, livré, jamais relevé ;
il échoue sur les deux conditions : adresse jamais vue, aucun code dans le
texte) et une réclame à code promo (M-d11bcd, écartée par la condition du
code). Un troisième, faux (M-bf5cc4), était déjà refermé par la règle de
charge. Quatre vrais codes attendront le chemin complet : une première
observation (M-69a216), une adresse de messagerie personnelle reçue la veille
seulement (M-61d831), une adresse connue depuis six jours quand l'historique de
la base commençait (M-3644a7), et une adresse dont le seul précédent, le 19
août, avait été relâché sans jugement (M-53f3f5). Sur trente jours : 5
verdicts, 2 restent ; des 3 vrais codes, un seul (M-53f3f5) prend le chemin
long. Le détecteur de code, passé par la revue du 29 septembre sur les 953
messages conservés dont le texte parle de code : 29 détections, 29 vrais codes
de 15 émetteurs, aucune fausse alarme ; les codes promo alphanumériques du
corpus n'en déclenchent aucune. Sur les 5 verdicts express dont le corps est
encore conservé, il rend le résultat attendu les 5 fois. Coût légitime mesuré :
4 vrais codes sur 9 auraient pris le chemin long, environ 45 à 55 secondes de
plus chacun. Aucun message légitime n'est bloqué : le chemin long reste une
livraison, seulement plus lente.

## Conversation SMTP

Le canal conversationnel utilise `maia@sentinel.mondomaine.example`. Pour chaque dossier
retenu, l'assistant envoie une fiche qui commence par le niveau de confiance,
les écarts et les choix, puis attend une directive. La réponse revient au
collecteur uniquement par SMTP.
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

Deux rôles distants sont isolés et chacun a son fournisseur configurable
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
affirmation sur l'activité d'un expéditeur doit rester vérifiable : elle cite le
nom et l'adresse observés, l'activité publiée sur son domaine et l'objet du
message qui a été comparé. Une incohérence ne suffit jamais à affirmer un
détournement ; celui-ci reste une hypothèse à examiner.

Les codes à usage unique et les liens de vérification de compte sont des
fonctions communes à toute organisation qui gère des comptes. Ils ne sont donc
jamais comparés au cœur de métier publié par l'expéditeur. Leur objet explicite
prime sur le vocabulaire commercial éventuellement présent dans le pied de page.
Une limite d'analyse est présentée comme telle, jamais comme un danger.

Le texte actuel et le fil cité sont distingués par CONTENT-016
(`CONTENT_QUOTED_THREAD`, neutre). Les motifs restent recherchés dans le
message entier, y compris dans les citations et dans les deux parties MIME.
Les indices de pression, demande sensible, combinaison et contexte financier
précisent `text_scope` : `current_message` si le motif existe dans le texte
actuel, `quoted_or_combined` sinon. Ce second cas ne prouve pas que
l'expéditeur actuel demande l'acte. Le juge lit qui demande quoi à qui et si
la réponse adopte les instructions citées. Les avis conservent cette précision.
Une demande de virement reste observée même dans un faux fil cité : la découpe
ne retire aucune charge et ne crée aucune confiance.

RIB et IBAN relèvent des coordonnées bancaires, pas d'une demande de
transfert. Le hook ne pose `transfer_money` que sur une formulation de
transfert ; l'enquêteur ACT-001 apprécie ensuite l'action réellement attendue.
Le référencement client ou fournisseur, les contrats et les frais de mission
font partie du fonctionnement courant d'une organisation, dont le site public
ne décrit pas nécessairement tous les services internes.

Une citation attribuée au destinataire, « RE: », `In-Reply-To` ou `References`
ne prouvent aucun courrier envoyé par lui. La reconnaissance d'un échange
initié exige une trace indépendante du courrier sortant ; le MX entrant seul
n'en dispose pas. CONTENT-016 décrit une présentation, jamais cette preuve.

La preuve technique reste entière en base et à disposition de l'administrateur :

    docker compose exec collector python -m sentimail_v3.conversation.explain <message>

A et B sont des décisions déterministes : leur sens est écrit dans le registre
central du collecteur et aucun appel au fournisseur n'est effectué. Une panne,
une clé expirée ou un quota atteint ne peuvent donc pas perdre une réponse dont
la signification est déjà connue localement. C n'est jamais une action : le
bouton, la lettre seule et C suivi d'une explication ouvrent tous une directive
libre interprétée par le fournisseur LLM sélectionné, dans le dossier SMTP
authentifié et avec une confiance suffisante. Les mots préremplis par SentiMail
sont retirés avant l'appel ; toute ambiguïté laisse le message en attente et
provoque une question ciblée. Une précision écrite à côté d'un A ou d'un B est
conservée comme motif, sans jamais modifier l'action déterministe choisie.

### Ce qu'une réponse peut décider

Une réponse se lit sans sa citation, quel que soit son format. Quand le client
n'envoie que du HTML, chaque bloc devient une ligne et chaque citation est
marquée « > », comme dans un texte brut : la même découpe s'applique ensuite.
Sans cela, la réponse et l'avis cité tenaient sur une seule ligne, et les mots
du bouton A recopiés dans la citation décidaient à la place de la personne
(M-d8df0e, 28 septembre 2026).

Sont des décisions écrites : une lettre seule sur sa ligne, « réponse A », le
corps d'un bouton de SentiMail, même suivi d'une courte signature sans
consigne. Un « À » tapé seul vaut A : le clavier d'un téléphone français
corrige le « a ». Une lettre ne décide que si le texte qui l'entoure tient en
400 caractères. Une phrase sans lettre ne décide sans modèle que si le texte
entier y tient. Au-delà, le texte part au modèle.

Livrer est irréversible, et faire confiance à un expéditeur est durable. Sur un
message retenu que le Code tient pour matériellement dangereux, ou que le
verdict classe dangereux, seule une décision écrite livre. Une phrase sans
lettre, une explication après C ou un texte compris par le modèle déclenchent
une question, et le message reste retenu jusqu'à un « A ». La lettre garde son
pouvoir : c'est la réponse de la personne à la question posée sur ce message
(13 août, 54b593c). Sur un avis d'indésirable, A ne livre rien : il pose d'un
clic un label légitime et une confiance durable. Sur un message dangereux ou
porteur d'une preuve matérielle, ce clic est donc toujours redemandé, lettre
comprise, et seul un « A » répondu à la question le confirme. Sur un message
seulement classé spam ou suspect sans preuve matérielle, ce clic reste
immédiat : la redemande ne couvre que le cas mesuré comme risqué. Le
récapitulatif suit les mêmes règles.

## Ce qu'une qualification humaine apprend

Une réponse A ou B ne juge pas seulement un message : elle inscrit l'expéditeur
exact dans une liste, et elle conserve les indices qui accompagnaient ce message.
Ces indices deviennent un contexte probatoire pour les suivants : l'examen final apprend
combien de fois l'utilisateur a déjà qualifié lui-même des messages portant le
même indice, tous expéditeurs confondus, à partir de deux confirmations.

Ce profil renforce une charge déjà présente ; il n'en crée jamais et ne remplace
aucune preuve. Il est isolé par client : tous les domaines rattachés au même
client partagent cet apprentissage, sans le divulguer à un autre client. Les
messages restent jugés sur leurs propres preuves, avec la mémoire des décisions
prises pour leur organisation.

La mémoire conserve aussi la série de courrier confirmée (HIST-006). Au moins
deux messages distincts, authentifiés par DMARC, du même client doivent avoir
été qualifiés légitimes sans retour contraire. La série réunit le domaine From
exact, la nature « envoi de masse » et le List-ID, ou à défaut l'objet exact
normalisé. Les adresses peuvent varier à l'intérieur de ce domaine. Les
messageries publiques, plateformes partagées et relais de confidentialité
exigent toujours l'adresse exacte : Apple ne prouve pas FlightAware.
Ce contexte favorable ne crée aucune autorisation de domaine, ne réduit aucun
seuil et ne dispense d'aucune inspection. Il ne double pas HIST-001 quand
l'adresse exacte est déjà confirmée. Sa preuve figée dans le label survit à la
purge ; les anciens retours encore documentés sont repris par la migration 100.

## Listes d'expéditeurs par SMTP

Le registre d'apprentissage est autoportant : chaque label enregistre lui-même le
correspondant, le destinataire et l'objet témoin. Il reste donc lisible et
opposable au prochain message même après le dégonflage puis la suppression du
message d'origine par la rétention.

Les listes sont isolées par client et portent par défaut sur l'adresse exacte de
l'expéditeur, jamais implicitement sur tout son domaine. Une réponse A enregistre
l'expéditeur en liste blanche pour tous les domaines du client et désactive son
éventuelle entrée noire ; B effectue l'opération inverse. Chaque bascule reste
auditée, visible dans le registre et réversible.

L'identité effectivement observée par le MX reste blocable sous sa forme exacte
même si sa partie locale dépasse la limite SMTP de 64 caractères. Cette tolérance
ne vaut que pour un fait déjà capturé et rattaché à une réponse authentifiée : une
adresse saisie à la main ou importée reste soumise à la validation stricte.

Les corps préremplis sont des phrases lisibles, mais leur couple action et
qualification est ramené localement au choix A ou B après authentification du
jeton SMTP. Cette voie ne dépend d'aucun modèle. Une phrase contradictoire ne
devient aucun choix. Les réponses individuelles et les récapitulatifs recopient
les mêmes `clue_code` orientés dans le label afin que la qualification conserve
aussi la forme du dossier tranché.

La liste blanche est une preuve à décharge et peut abaisser le seuil de confiance
jusqu'au plancher de 0,82 uniquement quand DMARC authentifie aussi l'identité
affichée. Elle ne force jamais un verdict légitime et ne contourne ni une
analyse incomplète, ni une preuve matérielle de danger, ni une politique de
retenue active, ni une convergence défavorable. Un indice CORRELATION_
défavorable suspend la réduction de seuil et la posture d'expéditeur de
confiance : la confiance porte sur une identité habituelle, jamais sur un acte
ou un montage observé sur ce message. Mesure du 29 septembre 2026 sur 60 jours :
9 livraisons dépendaient d'un seuil réduit, aucune ne portait de convergence
défavorable ; 2 livraisons d'expéditeurs autorisés portaient
CORRELATION_FINANCIAL_FRAUD à une confiance de 0,90, égale au seuil plein. Le
seuil seul ne les aurait pas retenues ; la posture, si. La liste noire conclut les prochains messages de l'expéditeur
réel par l'état terminal `suppressed`, sans livrer l'original ni envoyer un
nouvel avis MAIA.

Un choix B (réponse, récapitulatif ou « ne livre plus ») ne retient jamais le
nom affiché ni l'adresse From telle quelle : ils sont écrits par l'expéditeur.
`code/sender_identity.py` relit l'authentification figée à la capture et
retient, dans l'ordre, le domaine du From si DMARC est aligné, le domaine
signataire DKIM, puis le domaine d'enveloppe si SPF passe. La règle porte sur
l'apex (`scope='domain'`) ; une messagerie publique (`PUBLIC_MAILBOXES`) garde
l'adresse exacte, une plateforme mutualisée n'est jamais retenue, un locataire
partagé (`onmicrosoft.com`) garde son sous-domaine. Sans identité prouvée, le
verdict humain est enregistré mais aucune règle n'est posée (audit
`sender_list.identity_unproven`). À l'arrivée, une règle de retenue ne
s'applique qu'aux adresses et domaines prouvés du nouveau message : un faux
« CIC » envoyé depuis truc.fr fait bannir truc.fr, et le vrai CIC reste hors
de la règle. L'événement `policy_suppressed` et sa ligne d'audit empêchent
qu'une suppression devienne une perte silencieuse ; le watchdog signale toute
suppression dépourvue de cette trace.

Un logiciel de messagerie peut répondre depuis un autre domaine du même client.
MAIA accepte cette réponse seulement si la partie locale est identique, si les
deux domaines sont actifs, vérifiés et rattachés au même client. Ainsi
`camille@client.example` peut répondre à une action adressée à
`camille@client.test`, mais ni une autre boîte ni un domaine voisin ne peut agir
sur son dossier. L'acceptation de l'alias est elle-même auditée.

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
réputation.

Le score agrégé de Rspamd (RSPAMD-003) et son symbole d'hameçonnage (RSPAMD-007)
restent neutres : le premier additionne des symboles déjà comptés ailleurs, à
commencer par ceux de l'authentification, et le second est le bruit ordinaire
des campagnes authentifiées (94 messages sous DMARC validé sur la base, dont 52
légitimes). Sans authentification, le symbole change de sens, comme la
divergence d'un lien entre DEEP-011 et DEEP-010 : CORR-018 (45) le réunit à un
défaut constaté, DMARC non validé. Mesure du 11 août au 29 septembre 2026
(49 jours, toute la base) : 3 messages, aucun légitime, tous déjà rangés ou
retenus. Le score reste neutre même sans authentification : 306 messages, dont
2 qualifiés légitimes par l'utilisateur, aucun dont l'issue aurait changé.
CORR-018 est transverse : ni famille de preuve, ni barrière de livraison.

CORR-002 (collecte d'identifiants) ne réunit plus des faits sans lien entre eux
(décision du mainteneur du 15 octobre 2026, pour tous les destinataires) : un
formulaire ambiant (DEEP-014, atteint par un lien sans rien de trompeur) ne
compte que s'il se trouve sur la destination étrangère relevée par DEEP-008,
DEEP-001 ou DOMAIN-004. M-d0d979 : la connexion LinkedIn derrière l'icône d'une
lettre d'information, les redirections chez son routeur d'envoi. Un lien direct
vers un domaine récent qui porte le formulaire reste un faisceau. Rejeu sur les
6 dossiers conservés (9 septembre au 15 octobre) : seul M-d0d979 perd le
faisceau.

CORR-006 (premier contact de marque) n'est pas dispensé pour un expéditeur
authentifié qui semble ne demander aucun acte : un lien que le bac à sable ne
lit pas (DEEP-013, jeton ou chemin en /verify/, pied de page) ne prouve pas
l'absence d'acte, et l'usurpateur qui authentifie son propre domaine le choisit
(revue de sécurité du 15 octobre 2026). La plateforme qui écrit au nom de son
client (M-6ba4cf, M-f40d86) en reste indiscernable : son lien n'est pas visité
non plus. Rejeu : une dispense limitée aux dossiers dont tous les liens ont été
lus en touchait 12 sur 188, aucun des deux.

Les mélanges Unicode latin/cyrillique/grec et le punycode sont des
charges matérielles d'homographie. Les simples ambiguïtés ASCII comme `0/o` ou
`1/l/I` sont consignées mais restent neutres sans marque ou domaine de
référence ; confrontées aux domaines officiels établis par la recherche, elles
fondent IDENTITY-010.
Un domaine IDNA/punycode constitué d'un seul script reste lui aussi neutre ; seul
un mélange de scripts ou une comparaison de référence peut devenir une charge.

Le contexte historique compare le même expéditeur sur le volume antérieur, les
labels humains, l'heure UTC, la taille moyenne et son écart-type, la fréquence
des pièces jointes et les pays de transport. Première observation, domaine
récent et heure/taille/pays inhabituels deviennent des indices explicites.
Une habitude se lit sur des jours : l'écart (HIST-003) exige au moins dix
messages antérieurs répartis sur au moins dix jours distincts. M-e36c20
(15 octobre 2026) : douze messages en quatre jours, dont cinq notifications de
la même minute, faisaient passer 11 h 33 (Paris) pour un écart. Mesure sur les
220 HIST-003 conservés depuis le 17 août : parmi les 189 posés sur au moins dix
messages, 77 reposaient sur moins de dix jours actifs, dont 69 légitimes ; les
5 défavorables portaient déjà une charge plus forte (CORRELATION_ à 80 ou 85,
DMARC en échec), une politique de retenue, ou ont été livrés malgré l'indice.

L'inspection URL regroupe les variantes texte/HTML équivalentes sur un même apex,
préserve séparément les libellés génériques pointant vers des articles distincts,
priorise les formulaires et appels à l'action, puis échantillonne chaque apex avant
d'approfondir une destination. Le budget s'adapte de 20 à 40 représentants selon
la diversité des apex. Le verdict final reçoit le nombre d'URL, de représentants, d'apex
couverts et de représentants non inspectés. Ce plafond est un contexte de
couverture, pas une incomplétude automatique. Aucun seuil absolu de liens non
inspectés ne s'y ajoute. Mesure du 29 septembre 2026 sur 60 jours : 301 des
2 917 livraisons légitimes authentifiées avaient au moins dix représentants non
inspectés ; limité aux analyses déjà incomplètes, le seuil aurait retenu 11
messages et n'aurait attrapé aucun indésirable. Le compteur sous-estime
d'ailleurs le reste : un lien de pied de page compte comme sélectionné puis
n'est pas ouvert. La réponse est dans la sélection du bac à sable, pas dans le
juge. Seul un échec réel du sandbox ou
d'une pièce jointe rend la chaîne matériellement incomplète et impose le doute.
Les espaces présents dans le chemin ou la requête sont normalisés en `%20` à
chaque redirection ; ils ne sont pas une panne. Une destination distante
structurellement invalide ou sans résolution DNS est un résultat négatif complet.
Les refus anti-SSRF et les limites opérationnelles restent, eux, des inspections
incomplètes. Le décodage QR est un enrichissement facultatif et son échec ne
dégrade jamais un fetch HTTP réussi.

Un mur anti-robot n'a pas le même sens selon ce qu'il répond. Le vrai refuse
le scanner par une erreur (403) : c'est le pare-feu qui parle, le constat reste
neutre. Le faux sas est servi en 200, hors du domaine de l'expéditeur, court,
ouvert sur le vocabulaire de vérification (« Verify you are human », « Slide
to verify », captcha) et sans aucun lien visible : DEEP-024 (80) en fait une
preuve matérielle de tromperie, barrière de livraison
(`material_kind=deceptive_verification_gate`). La règle vit dans
`code/verification_gate.py`. Sur les 60 jours précédant le 16 septembre 2026,
aucun message légitime ne portait une telle page ; les vrais murs légitimes
répondaient 403, la salle d'attente servie en 200 portait ses liens.

« Rien observé » n'est pas « rien à voir ». Un lien d'action qui mène, hors du
domaine de l'expéditeur, à une page HTML servie en 200, de 1 024 octets au
plus, sans texte, sans lien, sans formulaire, est une coquille dont tout se
joue dans un script que le bac à sable n'exécute pas : DEEP-025 (neutre,
`code/opaque_landing.py`) l'écrit au dossier pour que le juge lise « le
contrôle n'a rien pu lire » et non « aucune charge ». Neutre à dessein : sur
les 60 jours précédant le 17 septembre 2026, 105 indésirables, 2 dangereux,
24 suspects, mais aussi 8 légitimes (désinscriptions, jeu-concours, pages de
suivi d'un routeur d'emailing) se présentaient ainsi. Une page lourde dont
aucun texte ne sort, le squelette d'une application, une feuille de style, une
image, un refus ne sont pas des coquilles ; la désinscription en pied de page
et la navigation secondaire ne sont pas des liens d'action.

## Le domaine réel et ce que le message dit de lui

Trois lecteurs, un seul texte : le hook contenu, les enquêteurs profonds et le
dossier du juge lisent le texte brut du message, sinon le texte visible de son
HTML (`readable_text`). Sur un mail HTML seul, soit 30 % du courrier, le juge
et les enquêteurs recevaient un corps vide ; le 16 septembre 2026, un faux reçu
« Prime Famille » est parti à 0,95 sur ce vide. Le HTML brut ne part toujours
pas au juge, seul son texte ; `privacy.text_source` en dit la provenance.

Quand le HTML cache un texte que le text/plain répète en clair, `readable_text`
rend le texte que le HTML affiche, pas le texte brut (M-96852d, 30 octobre
2026 : un HTML qui ne rendait que « 616 » et un lien, un text/plain de lettre
d'information technique, et un juge qui a lu la lettre). Le texte caché se
mesure contre le HTML rendu seul (`mots_caches_inedits`) : y ajouter le texte
brut effaçait l'inédit dès qu'on le répétait. Mesure sur les 2 724 messages
livrés des 60 derniers jours : trois touchés, deux envois d'une même campagne
et un transfert. Le séparateur de texte caché comptait aussi pour masqué tout
paragraphe en `line-height:0` (Mailchimp) : 474 messages livrés voyaient leur
texte entier classé caché, ce que l'ajout du texte brut masquait depuis août.
Les motifs de masquage sont désormais ancrés sur le nom exact de la propriété.

CONTENT-017 relève les mots coupés à l'intérieur par un signe qui n'est pas une
apostrophe (accent aigu, prime, modificateur, marque combinante restée
orpheline après recomposition NFC). Un mot dans l'objet ou le nom affiché
suffit, quatre dans le corps ; l'élision (`l´été`, `aujourd´hui`) et la
contraction (`don´t`) ne comptent pas. CORR-020 le réunit, ou le texte caché
ou les écritures mêlées, à un expéditeur sans répondant en première
observation. Les enquêteurs profonds lisent l'objet et le nom affiché sans ces
signes (`sans_bruit`), pour que « Carte A′̍meli » désigne l'Assurance Maladie.

Cinq enquêteurs profonds passent par le registre sur chaque message : `requested_action`,
`cousin_domain` (le domaine sosie, IDENTITY-010, décrit plus bas, sans appel au
modèle ni recherche), et `sender_relation`, qui remplace `identity_claim` et
`activity_coherence`. `sender_activity` compare séparément le contenu au métier publié ;
`action_destination` confronte la promesse aux liens inspectés. Les cinq
figurent dans `REQUIRED_DEEP_HOOKS`. Les
deux anciens décidaient d'abord s'ils regardaient (nom qui ne désigne rien,
site muet, expéditeur connu) et un « skip » ne laissait rien au dossier. Le
nouveau regarde toujours et n'accuse que sur pièces, en trois temps :

1. au nom de qui le message se présente, lu par le modèle dans le nom affiché,
   l'objet et le texte visible, et retenu seulement si tous les mots du nom
   sont écrits dans le message ; sinon le nom affiché, s'il désigne une
   organisation et non une personne ;
2. le rapport de ce nom avec le domaine réel, sur ce qu'une recherche rend de
   chacun (DEEP-022, DEEP-021), ou rien à chercher quand le domaine porte le
   nom ; un fait de propriété ou un domaine authentifié déjà livré gardent
   leur effet ;
3. sinon le constat d'identité reste non établi : sans répondant public
   lorsqu'aucune source pertinente ne répond du domaine, non vérifié lorsqu'une
   recherche manque ou que le rapport n'est pas tranché. Une activité publiée
   n'établit pas à elle seule le rapport avec le nom revendiqué.

Depuis le 13 octobre 2026, `sender_activity` a son propre passage : nom et
domaine concordants, recherche ayant établi une propriété, réfutation ou
identité inconnue ne dispensent jamais de confronter le contenu au métier.
Il compare la page d'accueil, sinon les résultats qui concernent exactement
le domaine ; les homonymes sans référence au domaine ne lui prêtent aucun
métier. Sans activité exploitable ou sans réponse du modèle, DEEP-027 dit
« cohérence non établie », neutre, jamais « cohérent » par défaut. Le métier
d'une messagerie publique, d'une plateforme mutualisée ou d'un relais de
confidentialité ne devient jamais celui de ses utilisateurs : le référentiel
d'infrastructures existant rend ce rapprochement non établi, tout en conservant
l'examen de leurs liens.

`action_destination` utilise les observations déjà recueillies par le bac à
sable, sans revisiter les liens. Le modèle compare l'opération annoncée, le
bouton et la fonction de sa destination. DEEP-029 exige deux citations vérifiées
localement : un extrait du message ou du bouton et un extrait de la destination
inspectée (chemin ou contenu). Une simple redirection, un domaine tiers, une
page illisible, un lien protégé ou une connexion préalable ne prouvent rien.
Un sas de vérification humaine ou un simple chargeur de page reste non concluant ;
sa présence ne suffit pas à prétendre qu'une autre fonction est observée.
Un logo ou une signature ne fonde jamais une contradiction : un lien sans
libellé propre (vide, ou qui n'est qu'une adresse) et qui mène à l'accueil d'un
site. Les deux traits sont exigés ensemble ; seuls, chacun est à la main de
l'usurpateur (revue de sécurité du 15 octobre 2026) : un bouton-image sans
texte alternatif ou une URL seule sur sa ligne vers une page précise, ou un vrai
bouton vers un leurre hébergé à la racine de son domaine, restent confrontés.
Un formulaire n'a jamais de libellé et l'est toujours. Un refus s'écrit
`contradiction_refused` (`unlabeled_site_home`, `ungrounded`). M-e36c20
(15 octobre 2026) : une demande d'affiliation à une mutuelle, sans aucun lien,
a été confrontée à la signature du message, une URL nue vers l'accueil du site
de l'employeur ; c'était la seule contradiction de production depuis le
13 octobre, et elle était fausse.
Les images et liens secondaires sont exclus (contextes `footer` et
`secondary_navigation` écrits par le parseur ; jusqu'au 15 octobre 2026, la
liste d'exclusion portait des noms jamais émis et 56 contrôles sur 178 ont
reçu des liens de pied de page ou de réseaux) ; les liens d'action sont répartis
par groupes de huit sans omettre les groupes suivants. Les paramètres des URL
sont réduits à leurs noms, sans leurs valeurs. Une inspection non concluante
reste DEEP-028 neutre ; une panne du modèle est conservée aux faits du hook.

CORR-019 réunit l'identité non établie (sans répondant ou non vérifiée) et cette
contradiction positive. Il impose `ask_user`, même sous DMARC réussi et même si
le modèle rend `deliver` ou, sans preuve matérielle indépendante, `junk` :
le validateur rejette ce candidat avant
qu'il devienne contraignant. Ce faisceau ne prouve pas une collecte ni un
danger matériel ; il demande un avis. Une preuve matérielle indépendante
permettant déjà le classement en indésirables conserve cet effet. L'absence
d'identité seule ne retient pas.
Les règles et le corpus d'apprentissage conservent `identity_destination_conflict`
avant toute réduction du dossier. Le classifieur local ne peut pas contourner
cette barrière.

Le superviseur vérifie la présence de chacun des cinq enquêteurs, après son
activation, et compte leurs erreurs de cohérence dans `coherence_hook_failures`.
Un lien absent rend `action_destination` non applicable, distinct d'une panne.

Le nom revendiqué n'est pas toujours le nom affiché entier. Dans « X via
Y », « X from Y », « X chez Y », « X pour le compte de Y », « X de la part
de Y », « X au nom de Y », « X on behalf of Y » ou « X par l'intermédiaire
de Y », X est celui qui écrit, souvent une personne, et Y l'organisation ou
le service au nom duquel le message part : c'est Y qui se confronte au
domaine (`relayed_organisation`), que le nom vienne du nom affiché ou du
modèle qui l'a recopié. Pour « via », Y est le service qui porte le message ;
pour « pour le compte de » ou « on behalf of », Y est l'organisation
représentée : dans les deux cas, c'est d'elle qu'on attend le domaine. Si Y
n'est que de l'habillage (« Service Client Amazon via Email »), X reste le
nom revendiqué. Le repli sur le nom affiché ne pose jamais comme
organisation un nom en forme de nom de personne (`names_a_person`) : civilité
en tête, « NOM Prénom » en deux mots (capitales de quatre lettres au moins,
en dessous c'est un sigle), prénom et initiale (« Paige B »), adresse
d'envoi qui sépare les noms (« sophia.wong@ »), ou adresse d'entreprise qui
colle l'initiale de l'un au nom entier de l'autre, quatre lettres au moins
(« elambertini@ » pour « Eva Lambertini », « durandj@ » pour « Jean
Durand »). M-e36c20 (15 octobre 2026) : une gestionnaire RH cherchée comme une
organisation n'avait aucun rapport public avec son employeur, et l'identité
passait pour non établie. Le refus s'écrit
`claim_refused: person_name` ; un domaine qui porte déjà le nom garde son
constat concordant. Enfin, pour un nom de plusieurs mots, un domaine n'est
officiel (`porte_le_nom`) que si son étiquette en porte au moins deux, ou si
elle n'est faite que de morceaux du nom (laposte pour « La
Poste-Colissimo », lidl pour « Lidl France ») : rbourgeois.fr ne suffit plus
pour « BOURGEOIS Muriel » (M-633c24, 25 septembre 2026, enseignante écrivant
par PRONOTE depuis le domaine de l'éditeur : DEEP-022 puis CORR-006 à tort).
Un nom d'un seul mot garde la règle d'avant : le mot dans l'étiquette.

Quand la recherche sur le nom ne rend aucun domaine qui le porte (« Prime
Video » rendait amazon.jobs, aboutamazon.com, amazon.com), `about_name` relit
`organisation_lookups` : un nom retenu qui contient tous les mots du nom
cherché prête ceux de ses domaines qui les portent tous (`primevideo.com`,
retenu sous « amazon prime video »). Un nom d'un seul mot n'en hérite pas. La
mémoire était jusque-là seulement écrite ; relue, elle permet DEEP-022 là où le
modèle constatait déjà l'absence de rapport. Sur les 60 jours précédant le
25 septembre 2026, 282 dossiers n'avaient aucun domaine officiel : la mémoire
en change un seul, M-8d026c.

À ce constat s'ajoute DEEP-026 (`IDENTITY_DISPLAY_NAME_DISGUISED`, 70) quand
le nom affiché imite par des sosies l'organisation que le corps revendique :
« lnfosPRlME » pour « Prime Video ». `code/sosies.py` ramène au même signe les
caractères que l'œil confond (l, I, 1 ; 0 et o ; « rn » et m ; « vv » et w) :
le squelette dit que deux écritures se confondent, jamais laquelle est la
bonne, et ne sert donc jamais seul. Le mot revendiqué doit se lire dans un mot
du nom (entier, à son début ou à sa fin) et manquer à son écriture réelle ; une
forme juridique (« SARL ») n'est pas un nom à imiter. Un domaine attribué à
l'organisation l'écarte, un domaine authentifié déjà livré le rend neutre. Il
compte comme identité empruntée : avec la première observation, il pose
CORR-006. Le caractère ambigu seul reste IDENTITY-007, neutre, qui voit
désormais aussi le l minuscule en tête de mot du nom affiché devant une
consonne et le l minuscule entre deux majuscules. Rejeu sur 60 jours : un seul
déclenchement, M-8d026c ; croisé sur 785 noms et 219 organisations, aucun
autre nom que les deux faux « PRlME ».

Le lecteur d'organisation peut recopier le déguisement lui-même. Le
26 octobre 2026, « AppIe <noreply@jobfinder.fr> » (M-38cfc3) a été lu
« AppIe » alors que le corps écrivait « Apple » : DEEP-026 comparait le
déguisement à lui-même, la recherche portait sur « AppIe » et ne rendait
aucun domaine officiel, et le juge a posé la question. Désormais, un mot du
nom revendiqué qui porte un caractère sosie (au sens d'IDENTITY-007) prend
l'écriture d'un mot du sujet ou du corps de même squelette qui n'en porte
aucun (`ecriture_du_message`). La recherche, le démenti et DEEP-026 portent
alors sur « Apple ». Jamais dans l'autre sens : un nom écrit en clair ne prend
pas le sosie d'un pied de page. Sous DMARC valide, CORR-001 ne pose pas, et le
profil d'usurpation matériel ne force donc pas le classement : DEEP-026 et
CORR-006 arrivent au juge, qui décide.

Le domaine lui-même peut imiter. IDENTITY-010 (`IDENTITY_COUSIN_DOMAIN`, 65)
compare l'adresse d'envoi aux domaines officiels que les recherches passées ont
établis : `organisation_lookups`, relue avec le filtre du nom (`porte_le_nom`)
et sans les hôtes que la recherche ne tient jamais pour officiels
(`_NOT_OFFICIAL`), parce que la table garde des lignes écrites avant ce filtre
(549 apex bruts, 208 retenus). L'étiquette de l'apex, ou un morceau d'au moins
cinq lettres du domaine complet, doit avoir le squelette d'une étiquette
officielle de cinq lettres au moins sans l'écrire : « exemp1ebanque » pour
« exemplebanque », « rn » pour « m ». Aucune liste de marques : la référence est
ce que la recherche a rendu pour les organisations que le courrier réel a
revendiquées. L'enquêteur `cousin_domain` passe après `sender_relation`, pour
comparer aussi les domaines que la revendication du message courant vient
d'établir. Un apex lui-même officiel n'imite personne, un fait de propriété
(délégation NS, signataire DKIM) l'écarte, un domaine authentifié déjà livré le
rend neutre. Il compte comme identité empruntée (CORR-001, CORR-006, CORR-017)
et forme CORR-004 avec un domaine récent ou des réponses détournées ; il
n'entre pas dans le profil d'usurpation matériel, réservé au nom accolé. Il ne
voit pas une faute de frappe (lettre ajoutée, retirée ou intervertie), un tiret
ajouté, une autre extension (une enseigne en .fr et la même en .ca ont la même
étiquette), ni un domaine que `_NOT_OFFICIAL` exclut de toute mémoire. Mesure
du 11 août au 29 septembre 2026 (49 jours, 4 565 messages) : aucun message
touché, aucun légitime ; aucune collision de squelette entre deux étiquettes
réelles parmi 5 025 apex observés. La distance d'édition d'une lettre touchait
15 messages, dont 13 légitimes : écartée. C'est une protection latente, pas la
correction d'un faux négatif connu. Du 27 août au 29 septembre 2026, CORR-004
était actif sans que rien ne puisse produire son indice.

Une recherche en panne n'est pas une recherche vide. Le moteur lève
`SearchUnavailable` quand il n'a pas pu répondre (`rejected` : clé ou compte
refusés, 401, 403, 432 ; `error` : délai, réseau, erreur de son côté), et une
liste vide veut dire qu'il a répondu ne rien savoir. La panne remonte au
rapport (`searched: false`, `search_unavailable`) puis à l'enquêteur, qui
l'écrit aux faits du passage, ne rappelle pas le moteur pour le domaine, et
finit « non vérifié » si la page d'accueil ne permet pas de confronter le
métier. Du 15 au 17 septembre 2026, une clé refusée en silence avait fait
passer « Amazon » pour un nom sans domaine officiel (M-373976 : DEEP-022
jamais posé, juge en doute là où il rejette dans 51 cas sur 60) et des
newsletters connues pour des expéditeurs « sans répondant », le fait qui
nourrit CORR-014.

Le hook contenu pose CONTENT-015 (neutre) dès que le message parle d'un
paiement, d'un reçu, d'un abonnement ou de coordonnées bancaires, même sans
rien demander. CORR-014 réunit contexte financier, sans répondant public et
première observation : le leurre de transaction fictive, qui fonde une question
à l'utilisateur, jamais un classement sans preuve matérielle. Un apex qui a
déjà livré ici l'exclut. Sur les 30 jours précédant le 16 septembre, aucun
message légitime ne réunissait les trois faits. CORR-016 (55) est sa sœur :
contexte financier ou paiement demandé, première observation, et un lien
d'action vers une page opaque (DEEP-025) ; là où CORR-014 lit le vide autour
de l'expéditeur, elle lit le vide au bout du lien. Même technique
`FAKE_TRANSACTION_LURE`, même limite : une question, pas un classement. Sur
les 60 jours précédant le 17 septembre 2026, 7 messages réunissaient ses trois
faits, aucun légitime ; les deux faux reçus « Prime » des 16 et 17 septembre
en font partie, et le second n'avait pas de CORR-014 parce que son expéditeur,
un compte détourné, a un répondant public.

CORR-017 (80) lit le nom au lieu du vide : contexte financier ou paiement
demandé, identité empruntée (nom affiché déguisé, organisation démentie,
domaine sosie), première observation. Une authentification valide ne la défait
pas : elle prouve le domaine d'envoi, pas la marque affichée. La fausse facture
Apple TV du 29 septembre 2026 (M-2a9365, « Support AppIe » depuis un domaine
tiers authentifié) n'avait ni CORR-014 ni CORR-016, et le juge a posé la
question. Un apex qui a déjà livré ici l'exclut. Sur les 60 jours précédents,
3 messages réunissaient ses trois faits, aucun légitime.

Un métier sans rapport ne raconte pas la même histoire selon
l'authentification. CORR-007 (compte détourné) exige un DMARC validé et aucun
défaut d'authentification. Sinon, CORR-015 (80) pose l'adresse empruntée :
métier sans rapport, défaut d'authentification, première observation, apex
jamais livré ici. Les deux ne se posent jamais ensemble. Sur les 60 jours
précédant le 16 septembre 2026, 93 messages réunissaient les faits de CORR-015,
aucun légitime ; sans la première observation, trois légitimes.

Deux faisceaux ont été mesurés et écartés le 29 septembre 2026. Une variante de
CORR-007 pour un expéditeur déjà établi (adresse connue, DMARC validé, aucun
défaut, métier sans rapport) touchait 154 messages dont 93 livrés légitimes ;
limitée aux expéditeurs ni autorisés ni confirmés et à un écart de
comportement, 8 messages dont 5 livrés légitimes ; l'apex établi en première
observation, 4 messages, tous légitimes. L'incohérence de métier se trompe trop
sur les expéditeurs connus pour porter seule un compte détourné. Un faisceau
texte masqué (CONTENT-013), envoi de masse sans historique et apex jamais livré
touchait 11 messages, dont 2 lettres d'information livrées légitimes, sans rien
changer aux 9 autres, déjà rangés ou retenus ; la police nulle de Rspamd, hors
du Code depuis le 13 septembre, en touchait 36 dont 14 légitimes. Les deux cas
qui l'appelaient (M-3c041b, M-14984b) avaient un historique local : aucun
faisceau de première observation ne les aurait vus.

Coût : un à deux appels Flash par message (lecture de la revendication, puis
rapport ou métier), recherches en cache trente jours par nom et par domaine.
Le superviseur compte `sender_relation_silent` : un passage de cet enquêteur
sans constat est un contournement et sonne au premier. Il compte aussi le
moteur de recherche : `organisation_search_rejected` (état 0 ou 1 : des refus
postérieurs au dernier succès inscrit dans `search_lookups`, sur sept jours ;
retombe seul à la première recherche qui rend au moins un résultat, puisqu'une
recherche vide ne s'inscrit pas ; sonne au premier, et une panne qui dure ne
réveille pas l'alerte à chaque nom cherché ; le nombre de refus reste au
détail dans `organisation_search_rejections`) et
`organisation_search_errors_last_hour` (sonne à trois). La lettre dit le
geste : renouveler la clé dans `secrets/search_api_key` puis recréer le
service `verdict`.

## Nature de l'envoi

Le reste du Code cherche la tromperie : usurpation, coercition, collecte de
secrets. Un envoi commercial de masse n'emprunte aucun de ces chemins, et son
absence de pression finissait donc par lui valoir un indice favorable.

Le hook `nature` décrit d'abord le cadre d'envoi à partir des seuls en-têtes
normalisés : `List-Unsubscribe`, `List-Id`, `Precedence`, `Feedback-ID`,
`Auto-Submitted`. Il distingue ainsi diffusion de masse, message automatique et
échange conversationnel. `X-CSA-Complaints` et `X-Report-Abuse` restent observés,
mais un canal de plainte seul décrit l'infrastructure d'envoi et ne suffit pas à
transformer une notification transactionnelle en diffusion de masse. Ce cadre
est un fait, jamais une intention : un envoi de masse demandé par le destinataire
reste parfaitement légitime.

Le caractère possiblement non sollicité naît de la conjonction, établie plus
tard avec l'historique : un envoi de masse dont l'adresse exacte n'a aucun
échange antérieur ni confirmation humaine ne dispose encore d'aucune preuve
locale qu'il était attendu. Ce signal faible n'affirme ni que le domaine parent
est inconnu, ni que le destinataire n'est pas abonné. Il disparaît dès le
premier échange ou la première confirmation.

Le registre du discours vient en dernier et pèse peu : des promesses
invérifiables de santé ou d'enrichissement décrivent une rhétorique de
sollicitation, jamais un produit ni un secteur. Il ne peut pas fonder seul une
qualification de danger.

En contrepartie, l'absence de pression ne qualifie plus que le risque de
coercition. Elle ne crédite plus un envoi de masse, dont la légitimité dépend du
lien d'abonnement et non du ton employé.

## Adresses, photo et extraits dans les avis

Un avis de décision ne reproduit pas le message entier. Pour un message retenu,
le niveau de confiance est le premier bloc visible, suivi du nom et de
l'adresse affichés, de l'adresse d'enveloppe (et de l'adresse de réponse quand
elle diffère), d'une photo inerte du message, des écarts, de trois courts
extraits textuels au plus et des choix A, B et C. La photo vient du bac à sable
de rendu : miniature rattachée au corps, capture pleine en pièce jointe ; un
rendu impossible laisse partir l'avis sans image.

Les phrases qui portent une demande sensible sont prioritaires dans les
extraits ; à défaut, les premiers passages substantiels donnent le contexte du
doute. Le remplissage invisible des préentêtes est retiré, une phrase ne se
coupe que sur une ponctuation suivie d'un blanc, et chaque URL devient
« [lien] ». Domaines et adresses restants sont rendus non cliquables.

Un message déjà classé en indésirable suit la même présentation : objet,
adresses, photo, trois motifs télégraphiques au plus, trois extraits et le
bouton qui livre l'original en cas de faux positif. Dans les deux cas,
l'original chiffré reste conservé par le dossier et livrable par une directive
authentifiée.

L'enveloppe lit les en-têtes d'origine sur une seule ligne. Un mot encodé peut
se décoder en saut de ligne ; la bibliothèque refusait alors de composer
l'enveloppe, et le message partait tel quel, annoté, sans que rien ne le dise :
trois objets de ce genre en sept semaines, dont un indésirable le 20 septembre
2026. Si l'enveloppe échoue quand même, un message que le Code tient pour
dangereux n'est pas livré intact : il revient à la retenue sous alerte
`fail_closed_holds` - le juge l'avait classé indésirable, pas ask_user ; ce
n'est donc pas un rappel à l'avis humain, c'est la même décision qui attend de
pouvoir s'exécuter sans laisser passer le contenu original. Un indésirable
ordinaire part annoté dans Indésirables, liens actifs ; l'événement de
livraison le dit (`junk_envelope=annotated_original`), le journal aussi
(`delivery.junk_envelope_fallback`), et le superviseur l'alerte.

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
  verdict DeepSeek ; `verdict.error` porte `retry` (`scheduled`, `immediate`
  ou `exhausted`) et `retry_in_seconds`, l'attente avant l'essai planifié ;
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

Un message retenu attend une décision humaine. Après `HOLD_REMINDER_AFTER_DAYS`
(trois jours par défaut) sans aucune réponse, MAIA relance une fois par fenêtre,
un courrier par dossier. La relance conserve une version texte et une version
HTML avec les mêmes boutons A, B et C que l'avis initial en pied de mail. Leurs
réponses préremplies portent le jeton du dossier, ajouté à l'expédition.
Elle indique la référence courte `M-…` du message dans les deux versions et
reprend la photo neutralisée de l'avis initial : miniature dans le corps HTML
et capture pleine jointe quand une miniature existe. Aucun nouveau rendu ni
chargement distant n'est nécessaire. Sans photo disponible, la relance part
avec sa référence et ses boutons, sans image cassée.
Après `HOLD_DECISION_AFTER_DAYS` (sept jours), le
dossier est abandonné : rien n'est livré, rien n'est classé, rien n'est appris,
aucun courrier ne part, et le message reste consultable dans la console jusqu'à
la rétention (`hold.ignored_without_reply`).

L'avis déjà envoyé reste compté comme une sollicitation, même après l'abandon.
L'absence de réponse ne crée aucune qualification et n'efface pas une
qualification humaine active. La mesure distingue la première exécution,
l'état final et les suppressions ou échecs sans livraison prouvée.

Un courrier ne demande jamais une position sur plusieurs messages (décision du
mainteneur du 15 octobre 2026) : trois messages en attente font trois courriers. Le
récapitulatif numéroté (`digest.py`) est coupé par défaut (`DIGEST_ENABLED`
faux) ; les réponses aux récapitulatifs déjà envoyés restent lues.

Deux réglages par destinataire, dans `participant_preferences`
(`conversation/review_preferences.py`) :

- `hold_reminders_enabled` à faux : aucune relance, le premier avis est le
  seul ;
- `ask_only_on_real_doubt` à vrai : le juge ne pose une question que sur un vrai
  doute (`judgment_rules.real_doubt`) : preuve matérielle de danger,
  convergence défavorable CORRELATION_, retenue authentifiée, pièce jointe non
  analysée, ou verdict dangereux. Sinon il livre, même sur un verdict suspect,
  une confiance basse ou une analyse inachevée, ou il classe un indésirable
  certain. Une demande d'avis ou un jugement rejeté devient une livraison
  (`delivery_without_question`, contradiction `ask_without_real_doubt`) : le
  pendant de `waiting_judgment`, avant que le jugement ne devienne contraignant.
  Sur les seize avis d'une destinataire du 15 septembre au 15 octobre 2026,
  sept restaient (comptes détournés, collecte d'identifiants, extorsion,
  premiers contacts de marque), neuf auraient été livrés.

L'opérateur vide la file d'un destinataire, sans courrier, avec la même issue
que l'échéance (`operator_cleared_queue`) :

    docker compose exec assistant python -m sentimail_v3.execution.hold_lifecycle <adresse>

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
Le dégonflage couvre aussi le HTML et les miniatures conservés dans l'outbox.
Les avis qui attendent encore leur envoi gardent leur contenu.

Après `RETENTION_DELETE_AFTER_DAYS` (180 jours par défaut), le message et ses
tables filles sont supprimés, avec les événements d'appel LLM, les
enrichissements devenus orphelins et les seules entrées d'audit techniques à fort
volume.

Ne sont jamais purgés : les labels d'apprentissage, les listes d'expéditeurs, les
directives écrites par l'utilisateur, les interprétations qui en découlent et le
reste du journal d'audit. Un message encore en attente de décision n'est jamais
touché : sans original, une libération deviendrait impossible.
Un dossier abandonné (`ignored`) n'attend plus de décision : même si son état
SMTP reste `held`, il suit les fenêtres normales de dégonflage et de suppression.
La purge et sa sonde partagent ce même critère.

Chaque passe est tracée dans `audit_log` et dans `operational_status`. Le
superviseur compte séparément les messages qui auraient dû être dégonflés depuis
plus de deux jours : une rétention arrêtée devient une dégradation visible, pas
une conservation silencieuse. L'espace libéré est réutilisé par PostgreSQL pour
les écritures suivantes ; il n'est pas rendu au système sans compactage
explicite.

## Réutilisation des observations et expédition des avis

Les nouvelles occurrences d'une entité réutilisent un enrichissement `rdap+dns`
encore valable pour le même type et la même valeur exacte. Un résultat déjà
rattaché reste immuable. L'expiration est revérifiée au rattachement ; une
erreur ou une absence reste identifiée comme telle et ne devient pas un succès.
La sélection des occurrences en attente et la recherche du cache possèdent des
index dédiés. Un succès complet vaut sept jours ; une erreur, une absence
globale ou une source temporairement en panne vaut une heure. Une absence DNS
normale (`NXDOMAIN` ou `NoAnswer`) n'est pas une panne de source.
L'âge d'un domaine est dérivé de sa date de création à la date de réception du
message : partager le cache ne fige pas cet âge, et rejouer un ancien message
ne le vieillit pas. Une page d'accueil expéditeur est partagée entre les enquêteurs,
y compris lorsqu'elle est absente ou refuse la lecture : ce résultat ne
déclenche pas une seconde visite immédiate.

L'assistant traite les conversations et expédie les avis dans deux boucles
indépendantes, avec un pool de connexions borné. Une attente de modèle ou de
relance ne bloque plus l'outbox. Le battement de santé n'est renouvelé qu'après
progression des deux boucles ; une boucle arrêtée ne peut donc pas être masquée
par l'activité de l'autre. Les reprises SMTP attendent depuis la dernière
tentative, avec les cinq essais et les modes de secours existants.

## Superviseur anti-soft-fail

Un superviseur déterministe, indépendant de MAIA et du fournisseur LLM, contrôle
chaque minute qu'aucun échec partiel ne reste silencieux. Il surveille les hooks
en erreur, les investigations partielles, l'absence d'un des neuf hooks requis,
l'absence d'analyse profonde avant verdict, les enrichissements de domaine
manquants, les erreurs des sandbox externes et les erreurs d'interprétation des
réponses SMTP. Une livraison sans événement SMTP ou sans identifiant de mise en
file est elle aussi considérée comme dégradée. Il compte aussi les chemins
d'échec de la livraison : les retenues fermées par le secours
(`fail_closed_holds`), les secours de la dernière heure
(`review_fail_open_last_hour`) et les replis d'enveloppe de la dernière heure
(`junk_envelope_fallbacks_last_hour`). Il conserve jusqu'à douze exemples corrélés par message et
composant pour le diagnostic.

Tout compteur non nul place SentiMail en état dégradé et déclenche une alerte
SMTP lors de l'apparition d'une nouvelle cause ou d'une nouvelle occurrence. Les
occurrences sont agrégées par minute pour éviter une alerte par message. Ce
contrôle complète les garanties
de terminaison : après acceptation SMTP, chaque message doit soit être livré,
soit avoir un avis MAIA effectivement envoyé ; une retenue silencieuse entraîne
le mode de secours, qui retient sous alerte un message que le Code tient pour
dangereux, sans jamais rouvrir son verdict. Les modules d'analyse peuvent donc rester fail-soft pour
ne pas interrompre le relais SMTP, mais leur dégradation n'est jamais un
fail-silent.

L'alerte nomme les messages derrière les compteurs de retard : sujet, temps
écoulé depuis l'acceptation et étape en cours (appel au modèle encore ouvert
avec son palier, juge en échec avec son nombre de tentatives, nouvel essai
planifié qui n'a pas démarré à son échéance, dossier en instruction, ou aucun
juge libre). Un message qui attend dans les temps un essai planifié après une
panne passagère du modèle n'y figure pas : il n'est pas en retard (voir
« Essais du juge après un échec »). Elle finit par « À faire » : un geste précis
pour les codes qui en appellent un (crédit du fournisseur, sauvegarde,
rétention, porte SMTP, relais), sinon rien à faire avant trente minutes sans
rémission, avec le journal à ouvrir selon l'étape. La lettre de rémission
raconte l'épisode : sa durée depuis l'alerte, et le sort de chaque message qui
attendait (livré, retenu avec avis, bloqué par une règle) avec son temps
d'attente. Le message-témoin est décrit pour ce qu'il vérifie : envoyé et
capturé, jamais jugé.

La console rend le verdict du superviseur sur `/sante/superviseur`, sous la
forme que la sonde centrale `json_health` consomme : `ok` vaut vert, tout
autre état vaut rouge avec ses causes, et un relevé vieux de plus de cinq
minutes vaut « superviseur muet ». `/sante/pipeline` ne dit que si un message
entre encore ; sans cette route, un juge qui traîne ne se voyait que dans la
lettre de MAIA.

Un refus `HTTP 402` du fournisseur de verdict est distingué des autres erreurs
du modèle : dès le premier verdict définitivement refusé, l'alerte de MAIA dit
explicitement que le solde du fournisseur est épuisé. Elle reste dédupliquée
comme les autres alertes techniques et ne révèle ni clé ni contenu de message.
Le moteur de recherche est tenu de même : un refus de clé
(`organisation_search_rejected`) sonne au premier et nomme le fichier de
secret à renouveler, les erreurs passagères
(`organisation_search_errors_last_hour`) sonnent à trois.

Le superviseur compare aussi chaque ordre final à l'état du dossier et du
message. Un ordre `deliver` encore retenu, un verdict absent du dossier ou une
divergence entre le verdict persisté et son exécution devient immédiatement un
`verdict_execution_mismatch` corrélé au message et déclenche l'alerte SMTP.
Le compteur `feedback_application_mismatches` applique la même exigence aux
retours SMTP authentifiés : après deux minutes, chaque qualification doit être
une vérité terrain portable, porter les signaux observés et avoir produit la
politique expéditeur demandée. Une politique opposée plus récente est reconnue
comme un changement d'avis et n'est pas signalée.

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
La conversation et les analyses auxiliaires ne décident rien : elles lisent,
expliquent ou produisent un indice que le verdict devra encore confronter. Elles
peuvent donc passer en local bien avant le verdict. Les appels
`requested_action` et `sender_relation` partagent le rôle local `analysis` ;
leur repli distant reste le fournisseur du verdict.

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
verdict, lui, travaille sur un dossier bien plus gros. Il ne passe pas par le
routage Ollama : sa réduction de coût suit la cascade contrôlée ci-dessous.

## Cascade de verdict Flash vers Pro

Un classifieur local peut précéder cette cascade après constitution du dossier.
Il apprend uniquement les indices structurés et s'abstient sur toute ambiguïté.
Son installation commence en observation ; les décisions locales exigent une
évaluation sur des verdicts LLM exclus de l’entraînement, sans revue humaine
obligatoire. Les corrections A/B alimentent les réentraînements. Les propositions
locales passent par le validateur du verdict avant
acceptation. Entraînement, garde d'activation, exploitation et retour arrière :
[Classifieur local](classifieur-local.md).

Le choix du modèle dépend uniquement de la forme du dossier, jamais d'un
expéditeur ou d'un destinataire. Une preuve matérielle, une analyse décisive
incomplète, une retenue explicitement demandée, des indices favorables et
défavorables mêlés, ou l'absence d'indice orienté part directement au modèle
premium. Seul un dossier complet et univoque, uniquement favorable, peut commencer sur
le modèle économique. Un dossier purement défavorable part directement sur Pro :
Flash ne pourrait pas le conclure seul.

Même dans ce cas, Flash ne peut conclure seul qu'à une livraison légitime, sans
doute, au-dessus du seuil augmenté d'une marge, et sans indice défavorable. Une
demande d'avis, un classement en indésirables, une confiance proche du seuil,
une contradiction ou une réponse invalide escalade vers Pro avant que le
verdict ne devienne contraignant. Chaque appel réserve son propre quota et
conserve son modèle, son palier et le motif de l'escalade.

La configuration possède trois modes : `off` conserve le modèle historique ;
`shadow` appelle Flash sur les dossiers simples mais applique toujours le
verdict de Pro ; `enforced` autorise Flash à conclure les seuls dossiers simples
qui passent les contrôles précédents. Les comparaisons `shadow` conservent
classification, décision, confiance et divergence, jamais le contenu du mail.

En mode `enforced`, un contrôle continu vise un dossier éligible à Flash sur
vingt, choisi par l'empreinte de l'identifiant du run, jamais par le
correspondant. Pro examine cet échantillon avant l'acceptation du verdict. Une
référence indisponible, refusée par le quota ou invalide laisse la proposition
Flash déjà validée ; un vrai motif d'escalade continue d'exiger Pro. Si Pro
refuse la livraison proposée par Flash, son jugement valide est appliqué avant
acceptation et les décisions futures passent en `shadow`, uniquement si la
paire et la marge configurées n'ont pas changé. La comparaison conserve les
versions du dossier figé : une modification du Code pendant l'appel ne lui
permet pas de qualifier le nouveau contexte. Aucun verdict accepté n'est
retouché et chaque changement automatique de mode est audité.

```text
python -m sentimail_v3.supervision.model_routing --status
python -m sentimail_v3.supervision.model_routing --shadow \
  --economy-model deepseek-v4-flash --premium-model deepseek-v4-pro
python -m sentimail_v3.supervision.model_routing --enforce
```

La commande d'activation contraignante est bloquée tant que le comparatif ne
compte pas au moins 50 dossiers, 95 % d'accords et aucun cas où Flash livrerait
un message que Pro aurait retenu. Ces comparaisons doivent correspondre à la
paire de modèles, la marge, la version du prompt, celle des règles et
l'empreinte du Code exactes de la configuration cible. La validation et
l'activation ont lieu sous le même verrou ; les anciens relevés non versionnés
ne qualifient plus une nouvelle activation. Un compte fournisseur sans crédit (`HTTP
402`) n'appelle pas Pro une seconde fois : les deux paliers partagent le même
solde, et le Watchdog envoie déjà l'alerte explicite.

## Essais du juge après un échec

Un échec du juge laisse le message en analyse : il n'est ni livré ni remis à
l'humain tant qu'un essai reste à venir. La suite dépend de la cause.

Une panne passagère du modèle (`LlmError` : délai total dépassé, `HTTP 408`,
`409`, `425`, `429` ou `5xx`, réponse vide ou illisible) planifie le nouvel
essai plus tard : 15 minutes après le premier échec, 1 heure après le deuxième,
4 heures après le troisième. Cela fait quatre essais au plus et 5 h 15
d'attente cumulée, sans compter la durée des essais eux-mêmes. L'escalade
humaine (retenue avec avis MAIA, ou mode de secours) ne vient qu'après l'échec
du quatrième. Le 15 octobre 2026, de 1 h à 5 h UTC, l'API répondait `HTTP 200`
sans jamais finir sa réponse : sept dossiers ont épuisé leurs trois essais
rapprochés entre 27 minutes et une heure après leur capture, tous pendant la
même lenteur.

Toute autre erreur garde la cadence historique : trois essais, chacun repris
dès la fin du précédent (au plus tôt 15 secondes par essai déjà fait après son
début), puis l'escalade. Un refus de crédit (`HTTP 402`), une clé refusée ou
une requête rejetée (autres `4xx`), une configuration absente, un quota de
verdict atteint ou une réponse inexploitable en font partie : attendre ne les
répare pas, et le 402 doit être signalé tout de suite. Une erreur de transport
`httpx` que le client ne convertit pas en `LlmError` reste aussi sur cette
cadence.

L'échéance est écrite dans `verdict_runs.next_attempt_at` (migration 102). Un
run en erreur sans `completed_at` attend un essai ; `completed_at` marque
l'épuisement, et un dossier épuisé n'est jamais repris par le juge. Au
démarrage, un essai coupé en plein travail repasse en erreur et repart
aussitôt ; il compte comme fait. Une échéance passée pendant l'arrêt part au
premier tour, une échéance à venir attend son heure.

Pendant l'attente, le superviseur et l'agent d'entretien ne comptent le
message ni en retard d'analyse, ni immobilisé, ni en échec. Ils le comptent de
nouveau quand l'échéance est dépassée de plus de 15 minutes sans que l'essai
démarre, ou quand un essai planifié tourne depuis plus de 15 minutes :
`verdict_retries_overdue` dégrade alors le superviseur, et l'entretien
redevient « dossier immobilisé ». Quinze minutes couvrent l'essai le plus long
observé pendant la panne (12 minutes : analyse profonde puis 120 secondes
d'appel), qu'un des deux juges doit finir avant de prendre l'essai dû ; le
superviseur exige en plus deux relevés consécutifs. Un dossier dont les quatre
essais ont échoué lève `verdict_retries_exhausted` dès le premier, pendant une
heure ; l'entretien le compte parmi les analyses en échec. Son rejeu
automatique ne touche que des dossiers épuisés : rejouer une attente
supprimerait le run et relancerait le dossier dans la panne.

## Corpus entraînable et banc d'essai

Le corpus permanent ne garde jamais le corps, le sujet, une adresse, une URL ou
une motivation libre du modèle. Il conserve le dossier probatoire compact, son
empreinte, sa version, un groupe de découpage stable et une cible enseignante
limitée à la classification, la décision, la confiance et les codes de preuve.
Même l'énoncé libre d'un indice est exclu : seules sa référence d'article, sa
direction, sa force et sa confiance survivent. L'export reconstruit aussi les
anciennes vues par liste blanche avant de les écrire.
Une ancienne ligne portant le nom `sentinel-v3-training-view-1` est reconnue
comme l'alias exact de `sentimail-v3-training-view-1` : le renommage du produit
ne doit pas retirer silencieusement une partie du corpus.

Un dossier est une matière unique et peut recevoir plusieurs annotations. Une
réponse SMTP authentifiée est une préférence de boîte (`user` et
`mailbox_preference`) : elle dit ce que ce destinataire veut recevoir. Une revue
spécialisée est une qualification de sécurité (`expert` et `security`). Si les
deux existent, l'expertise sert à mesurer la sécurité universelle sans effacer
la préférence de l'utilisateur. Deux expertises contradictoires rendent
l'échantillon inéligible tant que le désaccord n'est pas instruit.

L'export écrit quatre JSONL distincts, un manifeste et une empreinte de dataset.
Les quasi-duplicats portant les mêmes familles et codes d'indices restent dans
le même groupe : ils ne peuvent pas être à la fois appris et testés. Le mode
strict refuse un label humain sans dossier ou une contradiction non résolue.

```text
python -m sentimail_v3.supervision.dataset /exports/corpus-2026-08-28
python -m sentimail_v3.supervision.dataset /exports/corpus-strict --strict
python -m sentimail_v3.supervision.adjudication 124 legitimate \
  --reason-code confirmed_legitimate --operator revue-securite
```

L'adjudication accepte aussi l'identifiant d'un exemple de forme : elle crée sa
contrepartie humaine sans recopier de contenu personnel. Un nouveau verdict et
un nouveau feedback alimentent désormais automatiquement la provenance, la
cible enseignante et le groupe de découpage.

Le banc d'essai lit seulement l'export. Il ne possède aucune connexion à la
base opérationnelle et aucun chemin vers la livraison. Il accepte Ollama ou un
endpoint compatible OpenAI, valide la réponse avec le parseur du juge et rend
la matrice, les divergences de livraison, la comparaison au modèle enseignant,
la latence, les jetons et un coût estimé si les prix sont fournis.

```text
python -m sentimail_v3.supervision.benchmark \
  /exports/corpus-2026-08-28 /exports/qwen-test \
  --provider ollama --base-url http://ollama:11434 --model qwen2.5:14b

python -m sentimail_v3.supervision.benchmark \
  /exports/corpus-2026-08-28 /exports/candidat-api \
  --provider openai_compatible --base-url https://fournisseur.example/v1 \
  --model modele-candidat --api-key-file /run/secrets/candidat_api_key
```

Le passage de la gate opérationnelle exige 100 % de sorties valides et aucune
livraison d'un message qualifié indésirable. La gate de sécurité reste
inéligible tant que le jeu de test ne contient pas d'annotations expertisées.
Un accord avec le modèle enseignant mesure une imitation ; il ne remplace jamais
l'accord avec une vérité humaine indépendante.

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

Chaque appel au fournisseur distant a aussi une durée totale
(`REMOTE_LLM_DEADLINE_SECONDS`, 120 s par défaut). Le délai httpx
(`DEEPSEEK_TIMEOUT_SECONDS`) borne chaque lecture, pas l'appel : un serveur
qui a rendu ses en-têtes puis fait traîner le corps tient la ligne tant qu'il
émet un octet toutes les 180 s. Le 14 septembre 2026, un appel Flash a duré
901 s ainsi. Le dépassement devient une `LlmError`, la seule erreur que le
repli d'un palier vers l'autre rattrape, et chaque échec d'appel laisse une
ligne `verdict.model_call.error` avec le palier, le modèle, la durée et le type
d'erreur. Le budget est calé sur les mesures de 30 jours : Pro p95 15 s,
maximum 26 s ; Flash p95 7 s. Le palier économique a son propre budget
(`ECONOMY_LLM_DEADLINE_SECONDS`, 30 s) : un Flash suspendu ne coûte pas le
budget de Pro avant le repli.

## Le dossier compact soumis au juge

Mesure du 2 septembre sur quinze dossiers de production : le prompt de verdict
pesait 35 000 tokens, dont 60 000 caractères de Code entier recopiés à chaque
appel et 18 000 d'entités pour l'essentiel redondantes ; seul le prompt système
profitait du cache de préfixe du fournisseur, parce que tout l'invariant
fermait la marche.

Le dossier ne porte plus que le texte des articles qu'un indice a déclenchés
(`code_articles`) et un index d'une ligne par article de l'édition
(`code_index`). Un critère qui n'est pas un indice n'entre pas au jugement :
le juge n'a donc rien perdu, et il peut toujours nommer un article de l'index
pour dire qu'il ne s'applique pas, sans que le validateur y voie une preuve
inventée. Les entités arrivent décodées, sans les attributs qui recopient
l'URL, plafonnées à quatre URL par hôte au-delà desquelles on compte au lieu de
lister, et coupées à 512 caractères.

L'ordre des sections est celui du cache : `schema`, `privacy`, le registre des
techniques et l'index du Code ouvrent le dossier, tout ce qui dépend du message
vient ensuite. Ce qui ne change pas d'un message à l'autre se paie au tarif
cache-hit ; ce qui change reste ce qu'il a toujours été.

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

Un message livré ne porte aucun pied de page : écrit dans le corps, il repartait
chez l'expéditeur dans chaque réponse citée. Pour signaler un message livré, on
écrit à MAIA en réponse à ce message. Sans jeton dans `References` ni dans
l'objet, `In-Reply-To` puis `References` désignent le message livré à la boîte
qui écrit, et seulement à elle ; la conversation est rattachée à son dossier et
le challenge nomme l'objet visé. Ce rattachement ne prouve rien : l'identifiant
est connu de tout le fil, le challenge par code reste donc exigé. Un jeton lu
dans le corps ne vaut que s'il est le seul, car un fil ancien cite un pied de
page par échange.

Enfin, seul le premier résultat d'authentification ajouté en tête par
`rspamd.sentimail` est pris en compte. Un faux `Authentication-Results` injecté
plus bas dans le message ne peut donc pas remplacer le verdict du relais de
confiance.

Les réponses à MAIA arrivent par la soumission authentifiée du serveur de
messagerie des participants, puis par le relais interne. Mesure du 29
septembre : 217 réponses sur 223, aucune par le MX public. L'adresse d'action
n'est pas un domaine protégé : le MX public ne la route pas vers le collecteur.
L'enrôler, ou lui donner une route directe, ouvrirait un chemin sans
authentification SMTP. Il faudrait alors exiger un en-tête d'origine
authentifiée avant d'accepter une décision. Lier le compte SASL à l'enveloppe
casserait un participant qui écrit sous l'adresse d'un autre domaine de son
client.


## Bornes et observations réutilisables

Les inspections externes d'un dossier partagent une échéance de 240 secondes
(`DEEP_ANALYSIS_DEADLINE_SECONDS`). Les URLs disposent de 90 secondes
(`URL_ANALYSIS_DEADLINE_SECONDS`), de deux inspections simultanées
(`URL_ANALYSIS_CONCURRENCY`, bornée de un à quatre) et d'une inspection par
apex. Les enquêteurs auxiliaires disposent de 45 secondes au plus
(`DEEP_HOOK_DEADLINE_SECONDS`), dans la limite restante. Les preuves déjà
terminées sont conservées. Une analyse décisive interrompue reste explicitement
incomplète et ne lève aucune barrière. Les écritures en base sont attendues
séparément. Le bac à sable fichier borne à 30 secondes son attente et son
processus d'inspection, dont il arrête aussi les descendants.

Le cache temporaire ne réutilise que les observations réussies du même message
et de la même empreinte de contenu, code, corpus et configuration, pendant
six heures. Il ne conserve aucune erreur pour éviter de répéter l'inspection.
Une observation attachée à un verdict contraignant reste immuable. Les
observations d'une investigation encore ouverte peuvent être remplacées lors
d'un essai, sous verrou, sans multiplier leurs indices ni leurs totaux.

La représentation visible versionnée du courrier est calculée à la capture
puis utilisée par l'analyse, le juge et la revue humaine. La purge efface cette
copie et le cache. La revue refuse la qualification légitime d'un ancien HTML
sans cette représentation, pour éviter d'apprendre sur du texte masqué.

Chaque tentative réelle de modèle est inscrite dans `llm_attempt_events`,
sans contenu, URL ni secret, y compris les replis, erreurs et annulations.
Les tokens inconnus restent inconnus. Le superviseur et la console montrent
les volumes sur une fenêtre UTC de 24 heures, leur couverture et leurs modèles.
Ces lignes techniques sont purgées après 180 jours. Une question MAIA est
bornée à six tentatives réseau réelles et 120 secondes par défaut
(`ASSISTANT_QUESTION_DEADLINE_SECONDS`), interprétation et replis compris.
Une panne de cette mesure ne fait pas échouer l'appel.


## Capture des courriers malformés

Un échec interne du décodeur structuré d’un en-tête ne fait pas disparaître
le message. Le lecteur conserve sa valeur brute, expose un
`InvalidHeaderDefect` et continue les autres en-têtes et parties MIME. Ce repli
ne prouve pas une identité valide ; les règles d’authentification restent
applicables. Le défaut structurel entre dans les indices déjà normés.

PostgreSQL refuse le caractère NUL dans ses champs texte et JSONB. Seules ces
projections remplacent U+0000 par U+FFFD. L’EML, l’empreinte d’ingestion, les
empreintes des en-têtes et parties, les tailles et les mesures d’octets
restent calculés sur l’original intact. La même protection s’applique aux
constats profonds, aux caches et aux textes de verdict avant leur persistance.

Le témoin de capture est supprimé avant jugement par conception. Son succès
ne garantit pas qu’un autre message ne rencontre aucun défaut de capture.
La santé native du MX contrôle donc aussi sa file entrante ; un message qui
y attend plus de dix minutes rend le contrôle négatif. Une notification que
Postfix adresse lui-même à l'extérieur est comptée à part, sans rendre le
contrôle négatif. L’inventaire central
consomme cet état, en plus de la sonde SMTP et du témoin.
