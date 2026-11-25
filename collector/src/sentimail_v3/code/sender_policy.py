"""Une préférence de boîte ne s'applique qu'à l'identité réellement prouvée."""

from typing import Any

from sentimail_v3.code.sender_identity import ProvenIdentity


async def authenticated_hold(connection: Any, message_id: str, identity: ProvenIdentity | None) -> bool:
    """Même périmètre client et mêmes cibles que la règle B historisée."""
    if identity is None or not identity.proven:
        return False
    return bool(await connection.fetchval(
        """SELECT EXISTS (
            SELECT 1 FROM sender_policies sp
            WHERE EXISTS (
                SELECT 1 FROM messages m, unnest(m.envelope_recipients) recipient
                WHERE m.id=$1::uuid
                  AND sentimail_same_client(recipient,sp.participant_email)
            )
              AND sp.active=true AND sp.action='hold'
              AND ((sp.scope='sender' AND sp.value_normalized=ANY($2::text[]))
                OR (sp.scope='domain' AND EXISTS (
                    SELECT 1 FROM unnest($3::text[]) proven(domain)
                    WHERE proven.domain=sp.value_normalized
                       OR right(proven.domain,length(sp.value_normalized)+1)
                          = '.'||sp.value_normalized
                )))
        )""",
        message_id, list(identity.addresses), list(identity.domains),
    ))
