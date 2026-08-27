-- Le corpus n'est plus seulement normatif. Trois natures coexistent, et le
-- juge doit pouvoir les distinguer : les normes disent ce que le courrier doit
-- être, la doctrine adverse comment on s'en sert pour tromper, et les fiches
-- apprises ce que les qualifications du destinataire ont montré ici.

ALTER TABLE knowledge_documents DROP CONSTRAINT knowledge_documents_nature_check;
ALTER TABLE knowledge_documents ADD CONSTRAINT knowledge_documents_nature_check
    CHECK (nature IN ('normative', 'adversarial', 'learned'));
