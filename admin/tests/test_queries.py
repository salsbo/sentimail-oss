from __future__ import annotations

import json
import unittest

from sentimail_admin import queries

# Colonnes réellement présentes dans database/init : une requête qui citerait
# autre chose échouerait en production, pas ici. Ce garde-fou fige donc ce que
# la console a le droit de lire.
COLONNES_MESSAGES = {
    "id",
    "captured_at",
    "delivered_at",
    "delivery_status",
    "subject",
    "from_header",
    "envelope_from",
    "envelope_recipients",
}
COLONNES_INTERDITES = {"raw_eml", "body_text", "body_html", "text_content"}


class RequetesDomaineTests(unittest.TestCase):
    def test_la_liste_ne_prend_aucun_parametre(self) -> None:
        requete = queries.list_domains()
        self.assertEqual(requete.params, ())
        self.assertIn("FROM domains", requete.sql)
        self.assertIn("verification_token", requete.sql)

    def test_un_domaine_ajoute_naît_en_attente(self) -> None:
        requete = queries.insert_domain("mondomaine.example", "operateur@mondomaine.example")
        self.assertEqual(requete.params, ("mondomaine.example", "operateur@mondomaine.example"))
        self.assertIn("'pending'", requete.sql)
        self.assertIn("ON CONFLICT (fqdn) DO NOTHING", requete.sql)
        self.assertIn("RETURNING", requete.sql)

    def test_le_contact_facultatif_reste_nul(self) -> None:
        requete = queries.insert_domain("mondomaine.example", None)
        self.assertEqual(requete.params, ("mondomaine.example", None))

    def test_les_valeurs_ne_sont_jamais_interpolees(self) -> None:
        fqdn = "exemple'; DROP TABLE domains; --"
        requete = queries.insert_domain(fqdn, None)
        self.assertNotIn("DROP TABLE", requete.sql)
        self.assertEqual(requete.params[0], fqdn)

    def test_l_activation_exige_une_preuve_et_ne_la_fabrique_pas(self) -> None:
        requete = queries.activate_domain("a2a2e0f0-0000-4000-8000-000000000001")
        self.assertIn("status = 'active'", requete.sql)
        # La console ne date jamais une vérification qu'elle n'a pas faite.
        self.assertNotIn("verified_at =", requete.sql)
        self.assertNotIn("coalesce(verified_at", requete.sql)
        # Et elle n'active rien tant que la preuve manque.
        self.assertIn("verified_at IS NOT NULL", requete.sql)
        self.assertIn("WHERE id = $1", requete.sql)
        self.assertEqual(requete.params, ("a2a2e0f0-0000-4000-8000-000000000001",))

    def test_la_suspension_ne_touche_que_l_etat(self) -> None:
        requete = queries.suspend_domain("a2a2e0f0-0000-4000-8000-000000000001")
        self.assertIn("status = 'suspended'", requete.sql)
        self.assertNotIn("verified_at =", requete.sql)
        self.assertIn("RETURNING fqdn, status", requete.sql)

    def test_les_mutations_visent_une_ligne_par_identifiant(self) -> None:
        for fabrique in (queries.activate_domain, queries.suspend_domain):
            with self.subTest(fabrique=fabrique.__name__):
                sql = fabrique("id").sql
                self.assertIn("WHERE id = $1", sql)
                self.assertNotIn("WHERE fqdn", sql)


class RequetesLectureTests(unittest.TestCase):
    def test_le_courrier_ne_lit_que_des_metadonnees(self) -> None:
        requete = queries.recent_messages(50)
        selection = requete.sql.split("FROM")[0]
        for colonne in COLONNES_MESSAGES:
            self.assertIn(colonne, selection)
        for interdite in COLONNES_INTERDITES:
            self.assertNotIn(interdite, requete.sql)

    def test_le_courrier_est_borne_et_recent_d_abord(self) -> None:
        requete = queries.recent_messages(120)
        self.assertIn("ORDER BY captured_at DESC", requete.sql)
        self.assertIn("LIMIT $1", requete.sql)
        self.assertEqual(requete.params, (120,))

    def test_l_historique_operationnel_est_borne(self) -> None:
        requete = queries.operational_events(25)
        self.assertIn("FROM operational_events", requete.sql)
        self.assertIn("ORDER BY observed_at DESC", requete.sql)
        self.assertEqual(requete.params, (25,))

    def test_l_etat_courant_est_trie_par_composant(self) -> None:
        requete = queries.operational_status()
        self.assertIn("FROM operational_status", requete.sql)
        self.assertEqual(requete.params, ())

    def test_le_registre_reunit_regles_et_retours(self) -> None:
        requete = queries.learning_participants()
        self.assertIn("FROM sender_policies", requete.sql)
        self.assertIn("FROM labels", requete.sql)
        self.assertIn("is_ground_truth = true", requete.sql)
        self.assertEqual(requete.params, ())

    def test_les_regles_sont_filtrees_par_destinataire(self) -> None:
        requete = queries.participant_policies("operateur@mondomaine.example")
        self.assertIn("lower(participant_email) = $1", requete.sql)
        # 682 règles ne se lisent pas : la requête filtre et borne.
        self.assertIn("ILIKE", requete.sql)
        self.assertIn("LIMIT $3", requete.sql)
        self.assertEqual(requete.params, ("operateur@mondomaine.example", "", 200))

    def test_les_retours_sont_filtres_et_bornes(self) -> None:
        requete = queries.participant_labels("operateur@mondomaine.example", 200)
        self.assertIn("lower(participant_email) = $1", requete.sql)
        self.assertIn("LIMIT $2", requete.sql)
        self.assertEqual(requete.params, ("operateur@mondomaine.example", 200))
        for interdite in COLONNES_INTERDITES:
            self.assertNotIn(interdite, requete.sql)


class TraceDesModificationsTests(unittest.TestCase):
    def _payload(self, requete: queries.Query) -> dict:
        return json.loads(requete.params[2])

    def test_l_acteur_porte_l_adresse_appelante(self) -> None:
        requete = queries.audit_entry(
            action="admin.domain_added", target="mondomaine.example", client_ip="100.64.0.7"
        )
        self.assertEqual(requete.params[0], "admin_console:100.64.0.7")
        self.assertEqual(requete.params[1], "admin.domain_added")

    def test_la_charge_porte_la_cible_et_l_adresse(self) -> None:
        payload = self._payload(
            queries.audit_entry(
                action="admin.domain_activated",
                target="mondomaine.example",
                client_ip="100.64.0.7",
            )
        )
        self.assertEqual(payload["target"], "mondomaine.example")
        self.assertEqual(payload["client_ip"], "100.64.0.7")
        self.assertEqual(payload["interface"], "admin_console")

    def test_le_detail_du_changement_est_conserve(self) -> None:
        payload = self._payload(
            queries.audit_entry(
                action="admin.domain_suspended",
                target="mondomaine.example",
                client_ip="100.64.0.7",
                details={"status": "suspended", "domain_id": "abc"},
            )
        )
        self.assertEqual(payload["status"], "suspended")
        self.assertEqual(payload["domain_id"], "abc")

    def test_l_agent_est_tronque(self) -> None:
        payload = self._payload(
            queries.audit_entry(
                action="admin.domain_added",
                target="mondomaine.example",
                client_ip="100.64.0.7",
                user_agent="M" * 900,
            )
        )
        self.assertEqual(len(payload["user_agent"]), 200)

    def test_la_charge_est_du_json_valide_et_parametree(self) -> None:
        requete = queries.audit_entry(
            action="admin.domain_added",
            target="'; DROP TABLE audit_log; --",
            client_ip="100.64.0.7",
        )
        self.assertNotIn("DROP TABLE", requete.sql)
        self.assertIn("VALUES ($1, $2, $3::jsonb)", requete.sql)
        self.assertEqual(
            self._payload(requete)["target"], "'; DROP TABLE audit_log; --"
        )


if __name__ == "__main__":
    unittest.main()


class MesureTests(unittest.TestCase):
    """La console lit la mesure, elle ne la calcule pas.

    Le calcul vit dans le collector, que cette image n'embarque pas. La console
    lit le rapport déjà publié dans `operational_status`, exactement comme elle
    lit l'état du superviseur.
    """

    def test_la_mesure_se_lit_dans_l_etat_operationnel(self) -> None:
        requete = queries.evaluation_report()
        self.assertIn("operational_status", requete.sql)
        self.assertIn("details", requete.sql)

    def test_le_composant_est_un_parametre_lie(self) -> None:
        requete = queries.evaluation_report()
        self.assertIn("$1", requete.sql)
        self.assertEqual(requete.params, ("evaluation",))

    def test_la_mesure_ne_lit_aucun_contenu_de_message(self) -> None:
        requete = queries.evaluation_report()
        for interdite in COLONNES_INTERDITES:
            self.assertNotIn(interdite, requete.sql)


class RequetesMoteurParRoleTests(unittest.TestCase):
    """Le moteur se choisit par rôle : deux lignes, jamais la clé.

    ``llm_role_providers`` remplace le singleton unique : verdict et
    conversation peuvent pointer vers des fournisseurs différents. La requête
    ne cite jamais la colonne qui porterait un secret - il n'y en a pas, la
    clé vit sur disque.
    """

    def test_la_lecture_porte_les_deux_roles_jamais_la_cle(self) -> None:
        requete = queries.role_providers()
        self.assertEqual(requete.params, ())
        self.assertIn("llm_role_providers", requete.sql)
        self.assertIn("role", requete.sql)
        self.assertIn("secret_filename", requete.sql)
        self.assertNotIn("cle", requete.sql.casefold())

    def test_set_role_provider_upsert_une_ligne(self) -> None:
        q = queries.set_role_provider(
            "verdict",
            "openai_compatible",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "max_tokens",
            "deepseek_api_key",
            {"thinking": {"type": "disabled"}},
            "93.184.216.1",
        )
        self.assertIn("ON CONFLICT (role)", q.sql)
        self.assertIn("body_extras", q.sql)
        self.assertNotIn("cle", q.sql.casefold())

    def test_set_role_provider_porte_les_bons_parametres(self) -> None:
        q = queries.set_role_provider(
            "conversation",
            "anthropic",
            "https://api.anthropic.com",
            "claude-sonnet-4-5",
            "max_tokens",
            "anthropic_api_key",
            {},
            "admin_console:100.64.0.1",
        )
        self.assertEqual(
            q.params,
            (
                "conversation",
                "anthropic",
                "https://api.anthropic.com",
                "claude-sonnet-4-5",
                "max_tokens",
                "anthropic_api_key",
                "{}",
                "admin_console:100.64.0.1",
            ),
        )
        self.assertIn("llm_role_providers", q.sql)
        self.assertIn("RETURNING", q.sql)

    def test_set_role_provider_serialise_les_extras_en_jsonb(self) -> None:
        q = queries.set_role_provider(
            "verdict",
            "openai_compatible",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "max_tokens",
            "deepseek_api_key",
            {"thinking": {"type": "disabled"}},
            "93.184.216.1",
        )
        self.assertEqual(q.params[6], '{"thinking": {"type": "disabled"}}')
        self.assertIn("::jsonb", q.sql)


class RequetesIdentiteInstanceTests(unittest.TestCase):
    """L'identité de l'instance : un singleton, comme le moteur l'était."""

    def test_la_lecture_ne_prend_aucun_parametre(self) -> None:
        requete = queries.instance_identity_row()
        self.assertEqual(requete.params, ())
        self.assertIn("instance_identity", requete.sql)
        self.assertIn("action_address", requete.sql)

    def test_l_ecriture_upsert_le_singleton(self) -> None:
        requete = queries.set_instance_identity(
            "action@sentimail.mondomaine.example",
            ["alias@sentimail.mondomaine.example"],
            "maia@mondomaine.example",
            "sonde@sentimail.mondomaine.example",
            "admin_console:100.64.0.1",
        )
        self.assertIn("ON CONFLICT (singleton)", requete.sql)
        self.assertEqual(
            requete.params,
            (
                "action@sentimail.mondomaine.example",
                ["alias@sentimail.mondomaine.example"],
                "maia@mondomaine.example",
                "sonde@sentimail.mondomaine.example",
                "admin_console:100.64.0.1",
            ),
        )
