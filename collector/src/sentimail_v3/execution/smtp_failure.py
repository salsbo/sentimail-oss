"""Distinguer un échec SMTP à réessayer d'un refus qui ne changera jamais.

Un relais qui répond « 4.x.x » demande de repasser plus tard : la file d'attente
existe pour ça. Un relais qui répond « 5.x.x » a tranché - la boîte n'existe
pas, l'adresse est refusée - et rien dans une nouvelle tentative ne le fera
changer d'avis. Confondre les deux coûte cher : le 15 août, un avis destiné à
une adresse inexistante a été réémis cinq fois, puis le message d'origine a été
livré vers la même adresse, également refusé, laissant le dossier « différé »
pour toujours et le superviseur en dégradation permanente.

Le code de réponse suffit à trancher ; le texte du refus, lui, varie d'un
relais à l'autre et ne doit jamais servir de critère.
"""

from __future__ import annotations

from aiosmtplib.errors import SMTPRecipientsRefused, SMTPResponseException


def _is_permanent_code(code: object) -> bool:
    return isinstance(code, int) and 500 <= code < 600


def is_permanent_rejection(error: BaseException) -> bool:
    """Vrai quand le relais a définitivement refusé, sans recours possible.

    Un lot dont un seul destinataire reste réessayable n'est pas définitif :
    abandonner priverait ce destinataire d'un envoi encore possible.
    """
    if isinstance(error, SMTPRecipientsRefused):
        refusals = list(error.recipients or [])
        return bool(refusals) and all(
            _is_permanent_code(getattr(refusal, "code", None)) for refusal in refusals
        )
    if isinstance(error, SMTPResponseException):
        return _is_permanent_code(getattr(error, "code", None))
    return False
