from __future__ import annotations

import re

_MAIL_TERMS = re.compile(
    r"\b(?:e-?mail|mail|courriel|message|spam|phishing|hame[cç]onnage|exp[eé]diteur|"
    r"destinataire|domaine|lien|url|pi[eè]ce\s+jointe|livr\w*|lib[eé]r\w*|reten\w*|bloqu\w*|"
    r"autorise\w*|l[eé]gitime|suspect|dangereu\w*|ind[eé]termin[eé]|bo[iî]te|smtp|"
    r"spf|dkim|dmarc|maia|sentinel|newsletter|arnaque|authentification|signal\w*|"
    r"r[eè]gle\w*|apprentissage|m[eé]moire|verdict\w*|non\s+sollicit[eé]\w*|"
    r"liste\s+(?:blanche|noire)|whitelist|blacklist|import\w*)\b",
    re.IGNORECASE,
)
_THREAD_ANSWERS = re.compile(
    r"^(?:oui|non|c['’]est\s+(?:moi|bon|l[eé]gitime)|je\s+(?:confirme|connais)|"
    r"livre(?:-le)?|ne\s+livre\s+pas|spam|arnaque)[.!\s]*$",
    re.IGNORECASE,
)
_OUT_OF_SCOPE = re.compile(
    r"\b(?:m[eé]t[eé]o|recette|cuisine|voyage|h[oô]tel|restaurant|horoscope|"
    r"bourse|bitcoin|football|match|pr[eé]sident|politique|po[eè]me|chanson|"
    r"traduis|traduire|r[eé]dige\s+(?:un\s+)?(?:contrat|code)|python|javascript|"
    r"devoirs?|math[eé]matiques?|itin[eé]raire|vacances?)\b",
    re.IGNORECASE,
)


def conversation_scope(text: str, *, has_email_case: bool) -> str:
    """Retourne mail, out_of_scope ou ambiguous sans appeler de modèle."""
    cleaned = " ".join(text.split())[:8000]
    if not cleaned:
        return "out_of_scope"
    if _MAIL_TERMS.search(cleaned) or (has_email_case and _THREAD_ANSWERS.fullmatch(cleaned)):
        return "mail"
    if _OUT_OF_SCOPE.search(cleaned):
        return "out_of_scope"
    return "ambiguous"
