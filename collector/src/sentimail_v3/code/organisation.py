"""À qui appartient un domaine, et deux domaines relèvent-ils du même maître.

Un groupe possède plusieurs marques et autant de domaines : ses liens de suivi
partent d'un domaine et aboutissent à un autre sans que rien ne soit caché. Vu
du seul apex, cela ressemble pourtant à une redirection vers un tiers - le
motif même du détournement. Sans savoir qui possède quoi, l'observation ne peut
pas distinguer les deux, et retient des messages parfaitement ordinaires.

Le RDAP répond à cette question quand le registre le veut bien. Beaucoup
masquent désormais le titulaire, et c'est légitime : l'absence de réponse ne
prouve alors rien du tout, ni dans un sens ni dans l'autre. Ce module ne
conclut donc jamais sur du vide.

Le bureau d'enregistrement est écarté volontairement : des millions de domaines
partagent le leur, et le retenir ferait de tout l'internet une seule maison.
"""

from __future__ import annotations

import re
import unicodedata

import tldextract

# Rôles RDAP qui désignent le titulaire réel, à l'exclusion des intermédiaires
# techniques (registrar, reseller, abuse) qui sont partagés par tous.
_OWNER_ROLES = frozenset({"registrant", "administrative", "technical"})
# Mentions par lesquelles un registre indique qu'il ne dira rien.
#
# « anonymi » attrapait « anonymisé » mais pas « Anonymous », ni « Ano Nymous »
# - le libellé qu'OVH inscrit à la place du titulaire. Deux domaines masqués
# chez le même bureau partageaient alors une signature et passaient pour
# appartenir au même maître, ce que ce module s'interdit précisément.
# L'espace facultatif couvre les libellés coupés en deux mots.
_REDACTED = re.compile(
    r"redact|privacy|protect|whois\s*guard|not\s*disclosed|non\s*divulgu|"
    r"data\s*protected|gdpr|masked|ano\s*nym|withheld|obscured|"
    r"identity\s*shield|domains\s*by\s*proxy|contact\s*privacy",
    re.IGNORECASE,
)
# Adresses de contact des bureaux d'enregistrement et hébergeurs : partagées
# par tous leurs clients, elles ne désignent aucune organisation. Le module
# écarte déjà les messageries publiques pour la même raison.
_REGISTRAR_MAILBOXES = frozenset(
    {
        "ovh.net",
        "ovh.com",
        "gandi.net",
        "godaddy.com",
        "namecheap.com",
        "cloudflare.com",
        "ionos.com",
        "ionos.fr",
        "online.net",
        "scaleway.com",
        "amazon.com",
        "markmonitor.com",
        "cscglobal.com",
        "nameshield.net",
        "safebrands.com",
        "eurodns.com",
        "tucows.com",
        "enom.com",
        "key-systems.net",
        "internet.bs",
    }
)
_LEGAL_SUFFIX = re.compile(
    r"\b(s\.?a\.?s\.?u?|s\.?a\.?r\.?l|s\.?a|ltd|limited|llc|inc|gmbh|bv|nv|"
    r"plc|ag|spa|srl|oy|ab|as|co|corp|company|group|groupe|holding)\b",
    re.IGNORECASE,
)
# Messageries publiques : un contact chez elles ne dit rien de l'organisation.
PUBLIC_MAILBOXES = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "outlook.fr",
        "hotmail.com",
        "hotmail.fr",
        "live.com",
        "live.fr",
        "msn.com",
        "yahoo.com",
        "yahoo.fr",
        "aol.com",
        "free.fr",
        "orange.fr",
        "wanadoo.fr",
        "laposte.net",
        "sfr.fr",
        "neuf.fr",
        "bbox.fr",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "gmx.fr",
        "gmx.de",
        "web.de",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "zoho.com",
        "tutanota.com",
    }
)


def _normalize(value: str) -> str:
    stripped = unicodedata.normalize("NFKD", value)
    ascii_only = "".join(c for c in stripped if not unicodedata.combining(c))
    without_legal = _LEGAL_SUFFIX.sub(" ", ascii_only.casefold())
    return re.sub(r"[^a-z0-9]+", " ", without_legal).strip()


def _vcard_values(entity: dict[str, object], field: str) -> list[str]:
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return []
    values: list[str] = []
    for entry in card[1]:
        if (
            isinstance(entry, list)
            and len(entry) >= 4
            and str(entry[0]).casefold() == field
            and isinstance(entry[3], str)
        ):
            values.append(entry[3])
    return values


def organisation_signature(rdap: object) -> set[str]:
    """Les identifiants par lesquels un titulaire se reconnaît d'un domaine à l'autre.

    Un ensemble vide signifie « on ne sait pas », jamais « ce n'est pas la même
    organisation ».
    """
    if not isinstance(rdap, dict):
        return set()
    signature: set[str] = set()
    for entity in rdap.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = {str(role).casefold() for role in entity.get("roles") or []}
        if not roles & _OWNER_ROLES:
            continue
        for raw in _vcard_values(entity, "org") + _vcard_values(entity, "fn"):
            if _REDACTED.search(raw):
                continue
            normalized = _normalize(raw)
            if len(normalized) >= 3:
                signature.add(normalized)
        for raw in _vcard_values(entity, "email"):
            domain = raw.rsplit("@", 1)[-1].casefold().strip()
            if (
                domain
                and domain not in PUBLIC_MAILBOXES
                and domain not in _REGISTRAR_MAILBOXES
                and "." in domain
            ):
                signature.add("@" + domain)
    return signature


def same_organisation(left: set[str], right: set[str]) -> bool:
    """Vrai seulement si les deux titulaires se recoupent explicitement."""
    return bool(left and right and left & right)


def same_organisation_destinations(
    urls: list[dict[str, object]],
    *,
    sender_apex: str,
    organisations: dict[str, set[str]],
) -> list[str]:
    """Les destinations qui, bien qu'ailleurs, appartiennent au même titulaire.

    C'est la différence entre un groupe qui fait transiter ses liens par ses
    propres domaines et une redirection vers un tiers. Sans cette lecture, les
    deux se ressemblent, et le second motif fait retenir le premier.
    """
    sender = organisations.get(sender_apex) or set()
    if not sender:
        return []
    found: list[str] = []
    for url in urls:
        destination = str(url.get("final_apex") or "")
        if not destination or destination == sender_apex or destination in found:
            continue
        if same_organisation(sender, organisations.get(destination) or set()):
            found.append(destination)
    return found


# Les hébergeurs DNS qu'un très grand nombre de domaines sans rapport
# partagent. Chez eux, la délégation ne dit rien : deux clients de Cloudflare
# n'ont aucun lien entre eux. Chez un opérateur qui héberge son propre DNS,
# elle dit tout - il faut contrôler un domaine pour le déléguer.
#
# C'est une donnée de référence, versionnée avec le code : elle ne dit pas
# « ce domaine est fiable », elle dit « ce serveur de noms est mutualisé ».
# Le constat qui en découle reste générique et vaut pour tout domaine.
SHARED_DNS_PROVIDERS: frozenset[str] = frozenset(
    {
        # Hébergeurs et CDN mondiaux
        "cloudflare.com",
        "akam.net",
        "akamaiedge.net",
        "akadns.net",
        "ultradns.com",
        "ultradns.net",
        "dynect.net",
        "nsone.net",
        "azure-dns.com",
        "azure-dns.net",
        "azure-dns.org",
        "azure-dns.info",
        "googledomains.com",
        "google.com",
        "domaincontrol.com",
        "registrar-servers.com",
        "name.com",
        "dnsmadeeasy.com",
        "constellix.com",
        "he.net",
        "cloudns.net",
        "hostinger.com",
        "wixdns.net",
        "squarespacedns.com",
        "shopifydns.com",
        "myshopify.com",
        # Hébergeurs européens et français
        "ovh.net",
        "ovh.com",
        "gandi.net",
        "online.net",
        "scaleway.com",
        "ionos.com",
        "ionos.fr",
        "1and1.com",
        "hetzner.com",
        "hetzner.de",
        "infomaniak.ch",
        "bookmyname.com",
        "nameshield.net",
        "safebrands.net",
    }
)
# Amazon nomme ses serveurs awsdns-NN.{com,net,org,co.uk} : le motif est plus
# sûr qu'une énumération, que chaque nouvelle extension prendrait en défaut.
_SHARED_DNS_PATTERNS = (re.compile(r"^awsdns-\d+\.[a-z.]+$"),)


# Le suffixe public, embarqué : aucune requête réseau au moment de juger.
_NS_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def _nameserver_apex(host: str) -> str:
    """L'apex enregistrable d'un serveur de noms.

    Découper sur les deux derniers labels paraît suffisant et ne l'est pas :
    « ns-2.awsdns-53.co.uk » donnerait « co.uk », et tous les domaines
    britanniques partageraient alors une même signature. Le suffixe public
    tranche seul ces cas, et il est déjà embarqué.
    """
    extrait = _NS_EXTRACT(host.casefold().strip().rstrip("."))
    if not extrait.domain or not extrait.suffix:
        return ""
    return f"{extrait.domain}.{extrait.suffix}"


def nameserver_signature(records: object) -> set[str]:
    """Ce que la délégation DNS atteste, ou rien si elle est mutualisée.

    Un domaine délégué à ses propres serveurs signe ce qu'il possède : pour
    faire pointer un domaine vers eux, il faut le contrôler. C'est la seule
    attestation qui survive aux certificats de validation de domaine, qui ne
    nomment plus aucune organisation, et au RDAP, que le RGPD a refermé.

    Un hébergeur mutualisé ne signe rien : deux clients de Cloudflare n'ont
    aucun lien, et les rapprocher ferait de tout l'internet une seule maison.
    """
    if not isinstance(records, (list, tuple, set)):
        return set()
    apexes: set[str] = set()
    for record in records:
        if not isinstance(record, str):
            continue
        apex = _nameserver_apex(record)
        if not apex or apex in SHARED_DNS_PROVIDERS:
            continue
        if any(motif.match(apex) for motif in _SHARED_DNS_PATTERNS):
            continue
        apexes.add("ns:" + apex)
    # Deux apex distincts signifient une délégation partagée entre opérateurs :
    # elle n'atteste plus personne en particulier.
    return apexes if len(apexes) == 1 else set()


def authentication_signature(domain: str, dkim_domain: object) -> set[str]:
    """Ce que la signature DKIM atteste du maître du message.

    Une signature valide prouve que le détenteur du domaine signataire a
    approuvé ce message : deux domaines signés par le même « d= » relèvent du
    même maître. Le fait est déjà dans l'en-tête, aucune requête n'est
    nécessaire.

    Une messagerie publique ne signe aucune organisation : tout le monde y
    envoie, et s'en servir rapprocherait des inconnus.
    """
    signataire = str(dkim_domain or "").casefold().strip().rstrip(".")
    if not signataire or "." not in signataire:
        return set()
    if signataire in PUBLIC_MAILBOXES:
        return set()
    return {"dkim:" + signataire}
