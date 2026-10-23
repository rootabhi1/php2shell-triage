import unittest

from php2shell_triage import (
    assess_evidence, extract_version_from_headers, is_patched,
    parse_version, validate_target_url,
)


class VersionAssessmentTests(unittest.TestCase):
    def test_rejects_unsupported_or_credentialed_urls(self):
        for url in ("file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com", "https:///missing-host"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_target_url(url)

    def test_normalizes_url_and_removes_fragment(self):
        self.assertEqual(
            validate_target_url("HTTPS://example.com/path#fragment"),
            "https://example.com/path",
        )

    def test_unverified_evidence_cannot_override_passive_verdict(self):
        verdict, score, details, level = assess_evidence(
            "https://example.com",
            {"runtime_version": "8.3.35", "runtime_verified": False},
        )
        self.assertEqual(verdict, "")
        self.assertEqual(score, 0)
        self.assertEqual(level, "operator_supplied_unverified")
        self.assertTrue(details)

    def test_verified_runtime_evidence_has_explicit_verdict(self):
        verdict, score, details, level = assess_evidence(
            "https://example.com",
            {
                "runtime_version": "8.3.35",
                "runtime_verified": True,
                "evidence_source": "authenticated package inventory",
            },
        )
        self.assertEqual(verdict, "AFFECTED VERSION VERIFIED (upstream threshold)")
        self.assertEqual(score, 95)
        self.assertEqual(level, "operator_verified")

    def test_verified_fixed_runtime_evidence(self):
        verdict, score, details, level = assess_evidence(
            "https://example.com",
            {"runtime_version": "8.3.36", "runtime_verified": True},
        )
        self.assertEqual(verdict, "FIXED VERSION VERIFIED (upstream threshold)")
        self.assertEqual(level, "operator_verified")

    def test_parse_version(self):
        self.assertEqual(parse_version("8.3.36"), (8, 3, 36))
        self.assertIsNone(parse_version("unknown"))

    def test_fixed_release_boundaries(self):
        self.assertFalse(is_patched((8, 2, 34)))
        self.assertTrue(is_patched((8, 2, 35)))
        self.assertFalse(is_patched((8, 3, 35)))
        self.assertTrue(is_patched((8, 3, 36)))
        self.assertFalse(is_patched((8, 4, 26)))
        self.assertTrue(is_patched((8, 4, 27)))
        self.assertFalse(is_patched((8, 5, 11)))
        self.assertTrue(is_patched((8, 5, 12)))

    def test_unsupported_eol_branches_are_not_marked_safe(self):
        self.assertFalse(is_patched((8, 1, 31)))
        self.assertFalse(is_patched((7, 4, 33)))
        self.assertFalse(is_patched((5, 6, 40)))

    def test_unknown_future_branch_is_inconclusive(self):
        self.assertIsNone(is_patched((9, 0, 1)))

    def test_extracts_php_version_from_powered_by_header(self):
        version, source = extract_version_from_headers(
            {"X-Powered-By": "PHP/8.3.35"}
        )
        self.assertEqual(version, "8.3.35")
        self.assertEqual(source, "X-Powered-By")

    def test_prefers_server_header_when_both_disclose_php(self):
        version, source = extract_version_from_headers(
            {"Server": "PHP/8.4.27", "X-Powered-By": "PHP/8.3.35"}
        )
        self.assertEqual(version, "8.4.27")
        self.assertEqual(source, "Server")


if __name__ == "__main__":
    unittest.main()
