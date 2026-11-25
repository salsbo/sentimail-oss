"""Ce que le bac à sable a vu dans une pièce jointe, dit critère par critère.

L'analyse de fichier était déjà là, et elle est riche : YARA, macros Office,
JavaScript et actions de lancement dans les PDF, inspection d'archives en
profondeur, chiffrement, taux de compression, OCR, extraction d'URL. Trente
champs par pièce jointe.

Le jugement n'en recevait que deux bits : « matériel » si le score dépassait
sept dixièmes, « incomplet » sinon. Un document à macros, une archive protégée
par mot de passe, un exécutable déguisé et un PDF qui lance un programme
produisaient donc le même indice unique - ou aucun, en dessous du seuil. Le
travail perdu ne l'était pas à l'analyse, mais à la traduction.

Chaque constat retrouve donc son nom, sa force et son article. Une macro n'est
pas un exécutable, une archive chiffrée n'est pas un PDF avec liens, et le
destinataire a le droit de savoir lequel il a reçu.

Contrairement au métier de l'expéditeur ou à l'acte réclamé, rien ici ne
s'apprécie : une macro est là ou elle n'y est pas. C'est le domaine où une
observation calculée est juste, et où un jugement serait moins fiable.
"""

from __future__ import annotations

from typing import Any

# Constat du bac à sable -> (code d'indice, article, direction, force, énoncé).
# La force dit ce que le fait coûte s'il est exploité : une macro qui ouvre un
# terminal n'est pas de la même nature qu'un document qui en contient une.
_FINDING_RULES: dict[str, tuple[str, str, str, int, str]] = {
    "OFFICE_SHELL_EXEC": (
        "ATTACHMENT_MACRO_SHELL", "ATT-010", "adverse", 95,
        "Un document joint contient une macro qui lance des commandes système.",
    ),
    "OFFICE_AUTO_EXEC": (
        "ATTACHMENT_MACRO_AUTO", "ATT-011", "adverse", 85,
        "Un document joint contient une macro programmée pour se lancer à l’ouverture.",
    ),
    "OFFICE_HAS_MACROS": (
        "ATTACHMENT_MACRO", "ATT-012", "adverse", 60,
        "Un document joint contient des macros.",
    ),
    "PDF_JAVASCRIPT": (
        "ATTACHMENT_ACTIVE_DOCUMENT", "ATT-013", "adverse", 75,
        "Un document joint mentionne du JavaScript.",
    ),
    "PDF_LAUNCH_ACTION": (
        "ATTACHMENT_ACTIVE_DOCUMENT", "ATT-013", "adverse", 85,
        "Un document joint mentionne une action de lancement ou un fichier embarqué.",
    ),
    "ARCHIVE_ENCRYPTED_ENTRY": (
        "ATTACHMENT_ENCRYPTED_ARCHIVE", "ATT-014", "adverse", 70,
        "Une archive jointe est protégée par un mot de passe, ce qui empêche "
        "toute vérification de son contenu.",
    ),
    "ARCHIVE_DANGEROUS_MEMBER_EXTENSION": (
        "ATTACHMENT_EXECUTABLE_MEMBER", "ATT-015", "adverse", 85,
        "Une archive jointe contient un fichier capable d’exécuter du code.",
    ),
    "ARCHIVE_COMPRESSION_RATIO_EXCEEDED": (
        "ATTACHMENT_COMPRESSION_ANOMALY", "ATT-016", "adverse", 65,
        "Une archive jointe se décompresse dans des proportions anormales.",
    ),
    "IMAGE_OCR_TEXT": (
        "ATTACHMENT_IMAGE_TEXT", "ATT-017", "neutral", 0,
        "Une image jointe porte du texte, lu par reconnaissance de caractères.",
    ),
}
# Les articles qui établissent un dommage matériel, et non un simple soupçon :
# du code s'exécute, ou une signature de malveillance correspond. Ils portent la
# barrière de livraison, comme DEEP-004 la portait avant d'être remplacé par ces
# constats nommés - le nommage ne devait pas faire disparaître la barrière.
#
# Volontairement étroite. Un document à macros est banal en entreprise, une
# archive chiffrée empêche de vérifier sans rien prouver, et une compression
# anormale n'est qu'un indice. Poser une barrière sur ces trois-là ferait
# demander un avis sur du courrier de travail ordinaire.
MATERIAL_ARTICLES = frozenset({"ATT-010", "ATT-011", "ATT-015", "ATT-018"})

# Les constats qui disent seulement qu'une vérification n'a pas abouti. Ce sont
# des limites, jamais des charges : ne pas savoir n'accuse personne.
_INCOMPLETE_CODES = frozenset(
    {
        "OFFICE_PARSE_ERROR",
        "OFFICE_MACRO_EXTRACTION_ERROR",
        "PDF_PARSE_ERROR",
        "PDF_EXTRACTION_BUDGET_EXCEEDED",
        "IMAGE_OCR_ERROR",
        "YARA_ERROR",
        "ARCHIVE_PARSE_ERROR",
        "ARCHIVE_FORMAT_UNSUPPORTED",
        "ARCHIVE_INSPECTION_ERROR",
        "ARCHIVE_ENTRY_READ_ERROR",
        "ARCHIVE_DEPTH_LIMIT_EXCEEDED",
        "ARCHIVE_ENTRY_LIMIT_EXCEEDED",
        "ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED",
        "ARCHIVE_TEXT_BUDGET_EXCEEDED",
        "ARCHIVE_TEXT_DECODE_INCOMPLETE",
        "ARCHIVE_OCR_BUDGET_EXCEEDED",
        "ARCHIVE_OCR_ERROR",
    }
)
# Le bac à sable trace aussi son propre travail : ces constats-là ne décrivent
# pas le fichier, et les compter accuserait des pièces jointes ordinaires.
_IGNORED_SEVERITIES = frozenset({"info"})


def _add(
    found: dict[str, dict[str, object]],
    code: str,
    article: str,
    direction: str,
    strength: int,
    statement: str,
    filename: str,
) -> None:
    """Un constat par nature, en comptant les pièces concernées."""
    existing = found.get(code)
    if existing is None:
        found[code] = {
            "clue_code": code,
            "article_code": article,
            "direction": direction,
            "strength": strength,
            "confidence": 0.9,
            "statement": statement,
            "facts": {"filename": filename, "occurrences": 1, "filenames": [filename]},
        }
        return
    facts = existing["facts"]
    assert isinstance(facts, dict)
    facts["occurrences"] = int(facts.get("occurrences") or 1) + 1
    noms = facts.get("filenames")
    if isinstance(noms, list) and filename not in noms and len(noms) < 8:
        noms.append(filename)


def attachment_clues(analyses: Any) -> list[dict[str, object]]:
    """Les indices tirés de ce que le bac à sable a réellement vu."""
    if not isinstance(analyses, list):
        return []
    found: dict[str, dict[str, object]] = {}
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
        filename = str(analysis.get("filename") or "(sans nom)")
        findings = analysis.get("findings")
        for finding in findings if isinstance(findings, list) else []:
            if not isinstance(finding, dict):
                continue
            code = str(finding.get("code") or "")
            severity = str(finding.get("severity") or "").casefold()
            if severity in _IGNORED_SEVERITIES:
                continue
            rule = _FINDING_RULES.get(code)
            if rule is not None:
                _add(found, *rule, filename)
                continue
            if code.startswith("YARA_"):
                strength = 95 if severity in {"critical", "high"} else 55
                _add(
                    found,
                    "ATTACHMENT_YARA_MATCH",
                    "ATT-018",
                    "adverse",
                    strength,
                    "Une pièce jointe correspond à une signature de code malveillant.",
                    filename,
                )
                continue
            if code in _INCOMPLETE_CODES:
                _add(
                    found,
                    "ATTACHMENT_ANALYSIS_BLOCKED",
                    "ATT-019",
                    "neutral",
                    0,
                    "Une pièce jointe n’a pas pu être entièrement inspectée.",
                    filename,
                )
        urls = analysis.get("extracted_urls")
        if isinstance(urls, list) and urls:
            _add(
                found,
                "ATTACHMENT_EMBEDDED_URL",
                "ATT-020",
                "neutral",
                0,
                "Une pièce jointe contient des liens vers l’extérieur.",
                filename,
            )
        if analysis.get("analysis_incomplete"):
            _add(
                found,
                "ATTACHMENT_ANALYSIS_BLOCKED",
                "ATT-019",
                "neutral",
                0,
                "Une pièce jointe n’a pas pu être entièrement inspectée.",
                filename,
            )
    return list(found.values())
