from __future__ import annotations

import unittest

from sentimail_admin.naming import (
    SaisieInvalide,
    clamp_limit,
    normalize_address_list,
    normalize_admin_email,
    normalize_base_url,
    normalize_email_address,
    normalize_fqdn,
    normalize_identifier,
    normalize_local_role,
    normalize_model_name,
    normalize_preset,
    normalize_quota,
    normalize_role,
    normalize_sender_address,
    verification_record,
)


class NormalisationDuDomaineTests(unittest.TestCase):
    def test_la_casse_et_les_espaces_disparaissent(self) -> None:
        self.assertEqual(normalize_fqdn("  Mondomaine.EXAMPLE  "), "mondomaine.example")

    def test_le_point_final_est_tolere(self) -> None:
        self.assertEqual(normalize_fqdn("mondomaine.example."), "mondomaine.example")

    def test_un_domaine_unicode_devient_du_punycode(self) -> None:
        self.assertEqual(normalize_fqdn("Café.fr"), "xn--caf-dma.fr")

    def test_les_sous_domaines_sont_conserves(self) -> None:
        self.assertEqual(
            normalize_fqdn("Mail.Sentinel.Mondomaine.example"), "mail.sentinel.mondomaine.example"
        )

    def test_une_adresse_email_est_refusee(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn("operateur@mondomaine.example")

    def test_une_url_est_refusee(self) -> None:
        for saisie in ("https://mondomaine.example", "mondomaine.example/apps", "mondomaine.example:8080"):
            with self.subTest(saisie=saisie), self.assertRaises(SaisieInvalide):
                normalize_fqdn(saisie)

    def test_un_domaine_sans_extension_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn("localhost")

    def test_une_saisie_vide_est_refusee(self) -> None:
        for saisie in ("", "   ", None):
            with self.subTest(saisie=saisie), self.assertRaises(SaisieInvalide):
                normalize_fqdn(saisie)

    def test_les_points_doubles_sont_refuses(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn("mondomaine..org")

    def test_un_espace_interne_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn("mondomaine .org")

    def test_les_caracteres_hors_alphabet_sont_refuses(self) -> None:
        for saisie in ("bes_le.org", "mondomaine!.org", "mondomaine,org.fr"):
            with self.subTest(saisie=saisie), self.assertRaises(SaisieInvalide):
                normalize_fqdn(saisie)

    def test_un_tiret_en_bord_d_etiquette_est_refuse(self) -> None:
        for saisie in ("-mondomaine.example", "mondomaine-.org", "www.-mondomaine.example"):
            with self.subTest(saisie=saisie), self.assertRaises(SaisieInvalide):
                normalize_fqdn(saisie)

    def test_une_etiquette_trop_longue_est_refusee(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn("a" * 64 + ".org")

    def test_un_domaine_trop_long_est_refuse(self) -> None:
        trop_long = ".".join(["a" * 63] * 4) + ".org"
        with self.assertRaises(SaisieInvalide):
            normalize_fqdn(trop_long)

    def test_une_extension_invalide_est_refusee(self) -> None:
        for saisie in ("mondomaine.f", "192.168.50.73"):
            with self.subTest(saisie=saisie), self.assertRaises(SaisieInvalide):
                normalize_fqdn(saisie)

    def test_la_normalisation_est_idempotente(self) -> None:
        une_fois = normalize_fqdn("Café.FR.")
        self.assertEqual(normalize_fqdn(une_fois), une_fois)


class ContactDuDomaineTests(unittest.TestCase):
    def test_un_contact_vide_reste_vide(self) -> None:
        self.assertIsNone(normalize_admin_email(""))
        self.assertIsNone(normalize_admin_email(None))

    def test_le_contact_est_normalise(self) -> None:
        self.assertEqual(
            normalize_admin_email("  Operateur@Mondomaine.EXAMPLE "), "operateur@mondomaine.example"
        )

    def test_un_contact_sans_arobase_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_admin_email("operateur.mondomaine.example")

    def test_un_contact_a_deux_arobases_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_admin_email("a@b@mondomaine.example")

    def test_un_contact_sans_partie_locale_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_admin_email("@mondomaine.example")

    def test_un_contact_dont_le_domaine_est_invalide_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_admin_email("operateur@localhost")


class IdentifiantEtLimitesTests(unittest.TestCase):
    def test_un_uuid_est_accepte_et_normalise(self) -> None:
        self.assertEqual(
            normalize_identifier("A2A2E0F0-0000-4000-8000-000000000001"),
            "a2a2e0f0-0000-4000-8000-000000000001",
        )

    def test_une_injection_sql_n_est_pas_un_identifiant(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_identifier("' OR 1=1 --")

    def test_un_identifiant_absent_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_identifier("")

    def test_la_limite_est_ramenee_dans_la_plage(self) -> None:
        self.assertEqual(clamp_limit("10", default=100, maximum=500), 10)
        self.assertEqual(clamp_limit("100000", default=100, maximum=500), 500)
        self.assertEqual(clamp_limit("-5", default=100, maximum=500), 1)
        self.assertEqual(clamp_limit("beaucoup", default=100, maximum=500), 100)
        self.assertEqual(clamp_limit(None, default=100, maximum=500), 100)


class EnregistrementDeVerificationTests(unittest.TestCase):
    def test_le_nom_txt_est_prefixe(self) -> None:
        self.assertEqual(verification_record("mondomaine.example"), "_sentimail.mondomaine.example")


class PlafondTests(unittest.TestCase):
    def test_un_champ_vide_fait_heriter_de_l_instance(self) -> None:
        self.assertIsNone(normalize_quota(""))
        self.assertIsNone(normalize_quota("   "))
        self.assertIsNone(normalize_quota(None))

    def test_un_plafond_a_zero_est_refuse(self) -> None:
        # Zéro bloquerait toute analyse : ce n'est pas un réglage, c'est une
        # panne, et elle se dit en laissant le champ vide.
        with self.assertRaises(SaisieInvalide):
            normalize_quota("0")

    def test_un_plafond_est_un_nombre(self) -> None:
        self.assertEqual(normalize_quota("42"), 42)
        for saisie in ("-1", "12.5", "beaucoup", "20 "):
            if saisie.strip().isdigit():
                continue
            with self.assertRaises(SaisieInvalide, msg=saisie):
                normalize_quota(saisie)

    def test_un_plafond_demesure_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_quota("999999999")


class ModeleTests(unittest.TestCase):
    def test_un_nom_de_modele_ollama_est_accepte(self) -> None:
        self.assertEqual(normalize_model_name(" Qwen2.5:7B "), "qwen2.5:7b")
        self.assertEqual(normalize_model_name("library/bge-m3"), "library/bge-m3")

    def test_un_nom_de_modele_ne_porte_pas_n_importe_quoi(self) -> None:
        for saisie in ("", "modèle avec espace", "modele;rm -rf", "a" * 120):
            with self.assertRaises(SaisieInvalide, msg=saisie):
                normalize_model_name(saisie)

    def test_seuls_les_deux_roles_existent(self) -> None:
        self.assertEqual(normalize_role("verdict"), "verdict")
        self.assertEqual(normalize_role("CONVERSATION"), "conversation")
        for saisie in ("", "livraison", "admin"):
            with self.assertRaises(SaisieInvalide, msg=saisie):
                normalize_role(saisie)

    def test_l_analyse_est_un_role_local_sans_etre_un_fournisseur(self) -> None:
        self.assertEqual(normalize_local_role("ANALYSIS"), "analysis")
        with self.assertRaises(SaisieInvalide):
            normalize_role("analysis")


class BaseUrlTests(unittest.TestCase):
    """L'adresse où part le courrier vers le moteur : http(s) uniquement.

    Un fournisseur nommé n'existe plus dans la configuration : c'est l'URL qui
    dit où part le courrier. Elle doit donc être une adresse web valide, jamais
    un schéma inattendu ni du texte libre.
    """

    def test_les_urls_http_et_https_sont_acceptees(self) -> None:
        self.assertEqual(
            normalize_base_url("https://api.deepseek.com"), "https://api.deepseek.com"
        )
        self.assertEqual(
            normalize_base_url(" http://host.docker.internal:11434/v1 "),
            "http://host.docker.internal:11434/v1",
        )

    def test_base_url_refuse_autre_chose_que_http(self) -> None:
        for mauvais in ("ftp://x", "javascript:alert(1)", "api.deepseek.com", ""):
            with self.subTest(mauvais=mauvais):
                with self.assertRaises(SaisieInvalide):
                    normalize_base_url(mauvais)

    def test_base_url_refuse_l_espace(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_base_url("https://api.deepseek.com/ chemin")

    def test_base_url_refuse_hote_vide_identifiants_controle_et_port_invalide(self) -> None:
        for mauvais in (
            "https://",
            "http:///v1",
            "http:api.deepseek.com",
            "https://user:pass@api.deepseek.com",
            "https://user@api.deepseek.com",
            "https://api.deepseek.com/\x00v1",
            "https://api.deepseek.com/\r\nX: y",
            "https://api.deepseek.com:99999",
            "https://api.deepseek.com:abc",
            "https://api.deepseek.com:0",
        ):
            with self.subTest(mauvais=repr(mauvais)), self.assertRaises(SaisieInvalide):
                normalize_base_url(mauvais)

    def test_base_url_accepte_un_port_valide(self) -> None:
        self.assertEqual(
            normalize_base_url("http://127.0.0.1:8080/v1"),
            "http://127.0.0.1:8080/v1",
        )


class NormalizePresetTests(unittest.TestCase):
    """Le préréglage choisi doit être une clé connue de ``presets.PRESETS``."""

    def test_les_presets_connus_sont_acceptes(self) -> None:
        for nom in ("deepseek", "openai", "mistral", "ollama", "anthropic", "custom"):
            with self.subTest(nom=nom):
                self.assertEqual(normalize_preset(nom), nom)

    def test_la_casse_est_tolere(self) -> None:
        self.assertEqual(normalize_preset("DeepSeek"), "deepseek")

    def test_un_preset_inconnu_est_refuse(self) -> None:
        for saisie in ("gemini", "", "  "):
            with self.subTest(saisie=saisie):
                with self.assertRaises(SaisieInvalide):
                    normalize_preset(saisie)


class NormalizeHostileNetworkTests(unittest.TestCase):
    """Une adresse ou une plage du registre : publique, jamais l'infrastructure.

    L'administrateur peut bannir une adresse ou une plage entière ; la
    validation refuse tout ce qui bloquerait sa propre infrastructure -
    réseaux privés, loopback, CGNAT/Tailscale - et toute saisie qui n'est
    pas une adresse.
    """

    def test_une_adresse_publique_passe(self) -> None:
        from sentimail_admin.naming import normalize_hostile_network

        self.assertEqual(normalize_hostile_network("93.184.216.99"), "93.184.216.99/32")

    def test_une_plage_publique_passe(self) -> None:
        from sentimail_admin.naming import normalize_hostile_network

        self.assertEqual(
            normalize_hostile_network("93.184.216.0/24"), "93.184.216.0/24"
        )

    def test_une_plage_avec_bits_hote_est_normalisee(self) -> None:
        from sentimail_admin.naming import normalize_hostile_network

        self.assertEqual(
            normalize_hostile_network("93.184.216.99/24"), "93.184.216.0/24"
        )

    def test_les_adresses_internes_sont_refusees(self) -> None:
        from sentimail_admin.naming import SaisieInvalide, normalize_hostile_network

        for value in ("192.168.50.73", "10.0.0.0/8", "127.0.0.1",
                      "100.100.50.50", "0.0.0.0/0"):
            with self.subTest(value=value):
                with self.assertRaises(SaisieInvalide):
                    normalize_hostile_network(value)

    def test_le_reste_est_refuse(self) -> None:
        from sentimail_admin.naming import SaisieInvalide, normalize_hostile_network

        for value in ("", "pas-une-ip", "evil.com", "1.2.3.4.5"):
            with self.subTest(value=value):
                with self.assertRaises(SaisieInvalide):
                    normalize_hostile_network(value)


class NormalizeEmailAddressTests(unittest.TestCase):
    """L'identité de l'instance : des adresses, validées via ``parseaddr``.

    Un saut de ligne, où qu'il soit, est le vecteur d'une injection d'en-tête
    SMTP (un ``Bcc:`` ajouté à la faveur d'un champ mal filtré) : il est
    refusé avant même que ``parseaddr`` ne voie la valeur.
    """

    def test_une_adresse_nue_est_acceptee_et_repliee_en_casse(self) -> None:
        self.assertEqual(
            normalize_email_address("  Operateur@Mondomaine.EXAMPLE "), "operateur@mondomaine.example"
        )

    def test_un_nom_affiche_est_ignore_seule_l_adresse_reste(self) -> None:
        self.assertEqual(
            normalize_email_address("Alex Martin <operateur@mondomaine.example>"),
            "operateur@mondomaine.example",
        )

    def test_sans_arobase_dans_l_adresse_c_est_refuse(self) -> None:
        for saisie in ("", "  ", "pas-une-adresse", "Nom Sans Adresse"):
            with self.subTest(saisie=saisie):
                with self.assertRaises(SaisieInvalide):
                    normalize_email_address(saisie)

    def test_un_saut_de_ligne_est_refuse_partout(self) -> None:
        for saisie in (
            "operateur@mondomaine.example\r\nBcc: cible@evil.example",
            "operateur@mondomaine.example\n",
            "\noperateur@mondomaine.example",
        ):
            with self.subTest(saisie=repr(saisie)):
                with self.assertRaises(SaisieInvalide):
                    normalize_email_address(saisie)


class NormalizeSenderAddressTests(unittest.TestCase):
    """L'expéditeur MAIA garde son nom affiché : c'est ce qui part en ``From``."""

    def test_le_format_nom_adresse_est_conserve(self) -> None:
        self.assertEqual(
            normalize_sender_address("MAIA - SentiMail <maia@mondomaine.example>"),
            "MAIA - SentiMail <maia@mondomaine.example>",
        )

    def test_une_adresse_nue_reste_nue(self) -> None:
        self.assertEqual(normalize_sender_address("maia@mondomaine.example"), "maia@mondomaine.example")

    def test_sans_arobase_c_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_sender_address("MAIA - SentiMail <pas-une-adresse>")

    def test_un_saut_de_ligne_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_sender_address("MAIA <maia@mondomaine.example>\r\nBcc: evil@example.com")

    def test_une_saisie_vide_est_refusee(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_sender_address("")


class NormalizeAddressListTests(unittest.TestCase):
    """Les alias de l'instance : une liste, séparée par des virgules."""

    def test_plusieurs_alias_sont_separes_et_normalises(self) -> None:
        self.assertEqual(
            normalize_address_list(" Kitt@Sentinel.Mondomaine.example , autre@mondomaine.example "),
            ["kitt@sentinel.mondomaine.example", "autre@mondomaine.example"],
        )

    def test_une_liste_vide_reste_vide(self) -> None:
        self.assertEqual(normalize_address_list(""), [])
        self.assertEqual(normalize_address_list(None), [])
        self.assertEqual(normalize_address_list("   "), [])

    def test_un_seul_alias_invalide_refuse_toute_la_liste(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_address_list("kitt@sentinel.mondomaine.example, pas-une-adresse")

    def test_un_saut_de_ligne_est_refuse(self) -> None:
        with self.assertRaises(SaisieInvalide):
            normalize_address_list("kitt@sentinel.mondomaine.example\r\nBcc: evil@example.com")


if __name__ == "__main__":
    unittest.main()
