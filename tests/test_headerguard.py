import unittest
import headerguard

class HeaderGuardTests(unittest.TestCase):
    def test_case_insensitive_headers(self):
        h = headerguard.Headers([("Content-Type", "text/html"), ("X-Test", "one")])
        self.assertEqual(h.get("content-type"), "text/html")
        self.assertIn("x-test", h)

    def test_set_cookie_headers_remain_separate(self):
        h = headerguard.Headers([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        self.assertEqual(len(h.cookies), 2)

    def test_secure_baseline_has_grade_a(self):
        headers = [
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Cross-Origin-Embedder-Policy", "require-corp"),
            ("X-Frame-Options", "DENY"),
        ]
        report = headerguard.analyze(headers, "https://example.test", "https://example.test", 200)
        self.assertEqual(report.grade, "A")
        self.assertNotIn("HG001", [x.rule for x in report.findings])

    def test_report_only_is_not_enforced_csp(self):
        report = headerguard.analyze(
            [("Content-Security-Policy-Report-Only", "default-src 'self'")],
            "https://example.test"
        )
        self.assertIn("HG004", [x.rule for x in report.findings])

    def test_header_text_parser(self):
        items, status = headerguard.parse_header_text(
            "HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\n"
        )
        self.assertEqual(status, 200)
        self.assertEqual(items, [("X-Test", " yes")])

if __name__ == "__main__":
    unittest.main()
