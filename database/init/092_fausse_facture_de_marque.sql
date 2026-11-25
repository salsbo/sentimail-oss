-- 29 septembre 2026 : « Support AppIe <facturation@fournisseur.example> » facture 99 € un
-- abonnement Apple TV (M-2a9365). Un I majuscule tient la place du l ; le
-- domaine est authentifié et publiquement connu. CORR-014 exigeait un
-- expéditeur sans répondant, CORR-016 une page vide : aucune ne s'est posée,
-- et le juge, voyant une authentification valide, a posé la question.
--
-- CORR-017 : finalité de paiement, identité empruntée, première observation.
-- C'est l'identité empruntée qui porte le faisceau, quel que soit l'état de
-- l'authentification : une marque ne facture pas sous le nom d'une autre.
-- Mesure sur 60 jours : 3 messages réunissaient les trois faits, aucun
-- légitime (une fausse amende ANTAI classée dangereuse, un envoi .ru classé
-- indésirable, M-2a9365).

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (
    SELECT id FROM code_editions
    WHERE status = 'active'
    ORDER BY created_at DESC LIMIT 1
) e
CROSS JOIN (VALUES
    ('CORR-017', 'Convergence : fausse facture à l''enseigne d''une marque',
     'Le message annonce un paiement, un reçu ou un abonnement ; il se présente sous le nom d''une marque qu''il emprunte (nom affiché déguisé, organisation démentie, domaine sosie) ; cet expéditeur écrit pour la première fois. Aucun des trois faits ne suffit. Réunis, ils décrivent la fausse facture : un achat jamais fait, facturé au nom d''une marque connue par quelqu''un qui n''est pas elle. Une authentification valide ne défait pas le faisceau : elle prouve le domaine d''envoi, pas la marque affichée.',
     'adverse', 80, 'high',
     'Un apex qui a déjà livré ici l''exclut. Une marque citée sans être empruntée (une agence qui nomme son client) ne fournit pas d''identité empruntée et ne réunit pas le faisceau.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["CORRELATION_BRAND_TRANSACTION_LURE"]'::jsonb
WHERE technique_code = 'FAKE_TRANSACTION_LURE'
  AND NOT indicator_clues ? 'CORRELATION_BRAND_TRANSACTION_LURE';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.brand_transaction_lure',
    '{"new_correlation":"CORR-017","technique":"FAKE_TRANSACTION_LURE","cases":["M-2a9365"]}'::jsonb
);
