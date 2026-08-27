"""Les infrastructures d'envoi mutualisées, et comment les reconnaître.

Une plateforme d'emailing (SendGrid, Mailgun, SES, Brevo…) signe et route le
courrier de milliers de clients depuis une infrastructure commune. Un compte
jetable y produit un message parfaitement authentifié : SPF, DKIM et DMARC
passent, mais pour le domaine de la PLATEFORME, pas pour la marque affichée.

Cette table est une donnée de référence, versionnée avec le code, au même
titre que le référentiel de marques : elle ne dit pas « ce message est un
spam », elle dit « ce message transite par une infrastructure mutualisée ».
Le constat qui en découle est neutre - il retire à l'authentification son
crédit de légitimité de marque - et ne devient défavorable que par
corrélation avec un autre signal (marque imitée, domaine jeune, collecte de
mot de passe).

Un client sérieux configure son propre domaine de bounce et d'authentification
(l'apex n'est alors plus celui de la plateforme) : ce cas n'est pas concerné,
c'est justement ce qui distingue l'envoi délégué propre du compte jetable.
"""

from __future__ import annotations

import tldextract

# apex mutualisé -> nom de plateforme. L'apex, pas le sous-domaine : la
# comparaison se fait après réduction, donc u1807017.wl2.sendgrid.net rejoint
# sendgrid.net. Ne mettre ici que des apex d'INFRASTRUCTURE PARTAGÉE, jamais
# un domaine qu'un client peut configurer comme sien.
SHARED_ESP_APEXES: dict[str, str] = {
    "sendgrid.net": "sendgrid",
    "sendgrid.info": "sendgrid",
    "mailgun.org": "mailgun",
    "mailgun.net": "mailgun",
    "mg.gg": "mailgun",
    "amazonses.com": "amazonses",
    "brevo.com": "brevo",
    "sendinblue.com": "brevo",
    "mailjet.com": "mailjet",
    "mlsend.com": "mailerlite",
    "mailerlite.com": "mailerlite",
    "sparkpostmail.com": "sparkpost",
    "ccsend.com": "constantcontact",
    "rsgsv.net": "mailchimp",
    "mcsv.net": "mailchimp",
    "mcdlv.net": "mailchimp",
    "klaviyomail.com": "klaviyo",
    "sailthru.com": "sailthru",
    "cmail19.com": "campaignmonitor",
    "cmail20.com": "campaignmonitor",
    "createsend.com": "campaignmonitor",
    "mandrillapp.com": "mandrill",
    "postmarkapp.com": "postmark",
    "mtasv.net": "postmark",
    "sparkpost.com": "sparkpost",
    "mailengine1.com": "sailthru",
}

# Fragments qui, présents dans un Received ou un en-tête technique, trahissent
# la plateforme même sans passer par le domaine de bounce.
SHARED_ESP_MARKERS: dict[str, str] = {
    "geopod-ismtpd": "sendgrid",
    "x-sg-eid": "sendgrid",
    "x-sg-id": "sendgrid",
    "x-mailgun-": "mailgun",
    "x-ses-": "amazonses",
    "x-mailjet-": "mailjet",
    "x-mc-user": "mandrill",
    "x-cmail-": "campaignmonitor",
}

_extract = tldextract.TLDExtract(suffix_list_urls=())


def _apex(domain: str) -> str:
    value = _extract((domain or "").casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)


def shared_esp_provider(domain: str) -> str | None:
    """Le nom de la plateforme mutualisée d'un domaine, ou None."""
    return SHARED_ESP_APEXES.get(_apex(domain))


def shared_esp_marker(header_blob: str) -> str | None:
    """La plateforme trahie par un fragment d'en-tête, ou None."""
    lowered = (header_blob or "").casefold()
    for fragment, provider in SHARED_ESP_MARKERS.items():
        if fragment in lowered:
            return provider
    return None
