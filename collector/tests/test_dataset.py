from __future__ import annotations

import unittest

from sentimail_v3.supervision.dataset import SPLITS, _bucket, split_of


def sample(codes: list[str], families: list[str]) -> dict[str, object]:
    return {
        "dossier": {
            "evidence_families": families,
            "clues": [{"clue_code": code} for code in codes],
        }
    }


class SplitTests(unittest.TestCase):
    def test_two_messages_of_the_same_campaign_never_split(self) -> None:
        # Meme famille, memes indices : deux envois d'une meme campagne.
        first = sample(["AUTH_DMARC_FAIL", "NATURE_BULK_MAILING"], ["auth", "nature"])
        second = sample(["NATURE_BULK_MAILING", "AUTH_DMARC_FAIL"], ["nature", "auth"])
        self.assertEqual(_bucket(first), _bucket(second))
        self.assertEqual(split_of(_bucket(first)), split_of(_bucket(second)))

    def test_a_different_attack_lands_in_its_own_bucket(self) -> None:
        phishing = sample(["URL_SANDBOX_FORM", "AUTH_DMARC_FAIL"], ["url", "auth"])
        newsletter = sample(["NATURE_BULK_MAILING"], ["nature"])
        self.assertNotEqual(_bucket(phishing), _bucket(newsletter))

    def test_the_split_is_stable_across_runs(self) -> None:
        bucket = _bucket(sample(["AUTH_DMARC_PASS"], ["auth"]))
        self.assertEqual(split_of(bucket), split_of(bucket))
        self.assertIn(split_of(bucket), {name for name, _ in SPLITS})

    def test_every_bucket_lands_somewhere(self) -> None:
        for value in ("0" * 16, "f" * 16, "7fffffff00000000", "80000000ffffffff"):
            self.assertIn(split_of(value), {name for name, _ in SPLITS})

    def test_the_shares_are_a_whole(self) -> None:
        self.assertAlmostEqual(sum(share for _, share in SPLITS), 1.0, places=6)


if __name__ == "__main__":
    unittest.main()
