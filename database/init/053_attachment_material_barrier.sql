-- Rend aux constats de pièce jointe la barrière de livraison que DEEP-004
-- portait. En nommant chaque constat (migration 052), l'article global a
-- disparu du dossier - et avec lui la seule barrière matérielle que le bac à
-- sable savait poser. Un document à macro shell produisait donc une charge de
-- 95 sans plus rien interdire : le jugement pouvait conclure à la livraison.
--
-- Étroite à dessein : seuls les constats où du code s'exécute ou une signature
-- de malveillance correspond. Les macros ordinaires (ATT-012), l'archive
-- chiffrée (ATT-014) et la compression anormale (ATT-016) restent des charges
-- fortes sans barrière, faute d'établir un dommage.
UPDATE code_articles
SET parameters = parameters || jsonb_build_object(
        'delivery_barrier', 'material_danger',
        'material_kind', CASE article_code
            WHEN 'ATT-018' THEN 'malware_signature_match'
            WHEN 'ATT-015' THEN 'executable_in_archive'
            ELSE 'active_code_execution'
        END
    ),
    limitations = limitations ||
        ' Cette qualification est une barrière de livraison explicite même si le LLM conclut légitime.'
WHERE article_code IN ('ATT-010','ATT-011','ATT-015','ATT-018')
  AND parameters->>'delivery_barrier' IS DISTINCT FROM 'material_danger';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.attachment_material_barrier_restored',
    '{"version":"0.5.3","replaces":"DEEP-004","material_articles":["ATT-010","ATT-011","ATT-015","ATT-018"],"reason":"named_findings_dropped_the_delivery_barrier"}'::jsonb
);
