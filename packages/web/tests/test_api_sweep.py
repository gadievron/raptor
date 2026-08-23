"""OpenAPI ffuf scale sweep: raw-request generation, marker regex,
soft-404 calibration, and the candidate re-verification funnel."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.web.api_testing import (
    ApiOperation,
    build_raw_request,
    sweep_match_regex,
)
from packages.web.discovery.calibration import derive_soft404_filters
from packages.web.ffuf import FfufConfig, FfufRunner


def _response(status: int, body: str, history: list | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = body.encode()
    resp.text = body
    resp.history = list(history or [])
    return resp


class TestSweepMatchRegex(unittest.TestCase):
    def test_matches_static_error_signatures(self):
        pattern = re.compile(sweep_match_regex())
        self.assertTrue(pattern.search("You have an error in your SQL syntax"))
        self.assertTrue(pattern.search("root:x:0:0:root:/root:/bin/bash"))
        self.assertTrue(pattern.search("uid=33(www-data) gid=33(www-data)"))
        self.assertFalse(pattern.search("Welcome to our SQL tutorial page"))

    def test_baseline_dependent_classes_stay_out(self):
        # ssti's "49" marker without a baseline leg would match half the
        # web; the sweep regex must not carry it.
        pattern = re.compile(sweep_match_regex())
        self.assertFalse(pattern.search("Showing 49 results"))


class TestBuildRawRequest(unittest.TestCase):
    def _op(self, **kwargs) -> ApiOperation:
        defaults = dict(
            method="POST",
            url="https://api.example.test:8443/v1/users",
            query_params=["verbose"],
            body_template={"user": {"name": "raptor-baseline"}, "age": 1},
            string_body_fields=[("user", "name")],
        )
        defaults.update(kwargs)
        return ApiOperation(**defaults)

    def test_request_shape_and_keyword_position(self):
        raw = build_raw_request(
            self._op(), "https://api.example.test:8443", ("user", "name"),
        )
        self.assertIsNotNone(raw)
        head, _, body = raw.partition("\n\n")
        lines = head.split("\n")
        self.assertEqual(lines[0], "POST /v1/users?verbose=1 HTTP/1.1")
        self.assertIn("Host: api.example.test:8443", lines)
        self.assertEqual(
            1, sum(1 for line in lines if line.startswith("Host")),
        )
        self.assertIn('"name": "FUZZ"', body)
        self.assertNotIn("Content-Length", head)  # ffuf recomputes it

    def test_engine_scope_parser_accepts_generated_request(self):
        """The builder and the engine's strict parseRawRequest-mirroring
        scope check must agree, or every sweep dies at validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            wordlist = tmp / "payloads.txt"
            wordlist.write_text("' OR 1=1--\n", encoding="utf-8")
            base = "https://api.example.test:8443"
            raw = build_raw_request(self._op(), base, ("user", "name"))
            request_file = tmp / "req.txt"
            request_file.write_text(raw, encoding="utf-8")

            text = FfufRunner(base, tmp)._read_scoped_request_file(
                FfufConfig(wordlist=wordlist, request_file=request_file),
            )
            self.assertIn("FUZZ", text)

    def test_rejects_off_origin_and_missing_field(self):
        base = "https://api.example.test:8443"
        self.assertIsNone(
            build_raw_request(
                self._op(url="https://evil.test/v1/users"),
                base, ("user", "name"),
            )
        )
        self.assertIsNone(
            build_raw_request(self._op(), base, ("user", "missing")),
        )
        self.assertIsNone(
            build_raw_request(self._op(body_template=None), base, ("x",)),
        )


class TestSoft404Calibration(unittest.TestCase):
    def test_stable_body_derives_filter_size(self):
        client = MagicMock()
        client.get.return_value = _response(200, "not found page")
        self.assertEqual(
            derive_soft404_filters(client, "https://example.test"),
            {"filter_size": len("not found page")},
        )

    def test_jittering_body_with_stable_words_derives_filter_words(self):
        client = MagicMock()
        client.get.side_effect = [
            _response(200, "missing page abc"),
            _response(200, "missing page abcdef"),
            _response(200, "missing page a"),
        ]
        self.assertEqual(
            derive_soft404_filters(client, "https://example.test"),
            {"filter_words": 3},
        )

    def test_redirecting_wildcard_derives_nothing(self):
        """The scan client follows redirects; ffuf does not. A filter
        derived from the post-redirect page measures the wrong response
        layer and silently filters nothing."""
        client = MagicMock()
        client.get.return_value = _response(
            200, "login page", history=[_response(302, "")],
        )
        self.assertEqual(
            derive_soft404_filters(client, "https://example.test"), {},
        )

    def test_honest_404_and_instability_derive_nothing(self):
        client = MagicMock()
        client.get.return_value = _response(404, "nope")
        self.assertEqual(derive_soft404_filters(client, "https://t"), {})

        client.get.side_effect = [
            _response(200, "a"), _response(500, "b"), _response(200, "c"),
        ]
        self.assertEqual(derive_soft404_filters(client, "https://t"), {})

        client.get.side_effect = OSError("boom")
        self.assertEqual(derive_soft404_filters(client, "https://t"), {})


class TestVerifyJsonCandidate(unittest.TestCase):
    def test_first_confirming_class_wins_and_is_relabeled(self):
        from packages.web.fuzzer import WebFuzzer

        fuzzer = WebFuzzer(MagicMock(), None)
        hits = {"command_injection": {"vulnerability_type": "command_injection",
                                      "attack_vector": "json_body"}}
        fuzzer._test_json_payload = MagicMock(
            side_effect=lambda u, b, f, p, vt: hits.get(vt),
        )

        finding = fuzzer.verify_json_candidate(
            "https://t/api", {"name": "x"}, ("name",), "; id",
        )

        self.assertEqual(finding["attack_vector"], "json_body_sweep")
        self.assertIn(finding, fuzzer.findings)
        self.assertIsNone(
            fuzzer.verify_json_candidate(
                "https://t/api", {"name": "x"}, ("name",), "benign",
                vulnerability_types=["sqli"],
            )
        )


class TestScannerSweepPhase(unittest.TestCase):
    def _scanner(self, tmpdir: str, **kwargs):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            return WebScanner(
                "https://api.example.test", None, Path(tmpdir), **kwargs,
            )

    def test_sweep_candidates_are_reverified_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "payloads.txt"
            wordlist.write_text("' OR 1=1--\n", encoding="utf-8")
            scanner = self._scanner(tmpdir, ffuf_api_wordlist=wordlist)
            scanner.execution_policy = MagicMock()
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.verify_json_candidate.return_value = {
                "vulnerability_type": "sqli", "attack_vector": "json_body_sweep",
            }
            op = ApiOperation(
                method="POST",
                url="https://api.example.test/v1/users",
                body_template={"name": "raptor-baseline"},
                string_body_fields=[("name",)],
            )
            recorded = []
            ffuf_result = {"results": [
                {"url": "https://api.example.test/v1/users", "status": 500,
                 "input": {"FUZZ": "' OR 1=1--"}},
                {"url": "https://api.example.test/v1/users", "status": 500},
            ]}
            with patch("packages.web.scanner.FfufRunner") as runner_cls:
                runner_cls.return_value.run.return_value = ffuf_result
                scanner._api_scale_sweep(
                    [op], lambda u, p, raw, vec: recorded.append((u, p, vec)),
                )

            # Exactly the entry with an input map became a candidate, it
            # was re-verified first-party, and the request file exists
            # with owner-only permissions.
            scanner.fuzzer.verify_json_candidate.assert_called_once_with(
                op.url, op.body_template, ("name",), "' OR 1=1--",
            )
            self.assertEqual(
                recorded, [(op.url, "name", "json_body_sweep")],
            )
            request_file = Path(tmpdir) / "api-sweep-00.request"
            self.assertTrue(request_file.is_file())
            self.assertEqual(request_file.stat().st_mode & 0o777, 0o600)
            self.assertIn("FUZZ", request_file.read_text(encoding="utf-8"))

    def test_sweep_off_without_wordlist(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            scanner.execution_policy = MagicMock()
            with patch("packages.web.scanner.FfufRunner") as runner_cls:
                scanner._api_scale_sweep(
                    [MagicMock()], lambda *a: self.fail("recorded"),
                )
            runner_cls.return_value.run.assert_not_called()
            scanner.execution_policy.authorize.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class TestVerifyClassAttribution(unittest.TestCase):
    """Class labels must not outrun the evidence: only static-signature
    classes are candidates, ordered by the payload's own shape."""

    def _fuzzer(self, confirming: set[str]):
        from packages.web.fuzzer import WebFuzzer

        fuzzer = WebFuzzer(MagicMock(), None)
        fuzzer._test_json_payload = MagicMock(
            side_effect=lambda u, b, f, p, vt: (
                {"vulnerability_type": vt, "attack_vector": "json_body"}
                if vt in confirming else None
            ),
        )
        return fuzzer

    def test_passwd_dump_from_traversal_payload_labels_traversal(self):
        # /etc/passwd content satisfies BOTH the command-output and the
        # file-content markers; the ../ payload shape disambiguates.
        fuzzer = self._fuzzer({"command_injection", "path_traversal"})
        finding = fuzzer.verify_json_candidate(
            "https://t/api", {"f": "x"}, ("f",), "../../../etc/passwd",
        )
        self.assertEqual(finding["vulnerability_type"], "path_traversal")

    def test_command_shaped_payload_prefers_command_injection(self):
        fuzzer = self._fuzzer({"command_injection", "path_traversal"})
        finding = fuzzer.verify_json_candidate(
            "https://t/api", {"f": "x"}, ("f",), "; cat /tmp/x | id",
        )
        self.assertEqual(
            finding["vulnerability_type"], "command_injection",
        )

    def test_ssti_is_never_a_default_candidate(self):
        """The sweep's matcher cannot fire on ssti's arithmetic marker,
        so an ssti label here would fabricate evidence (any page
        containing a standalone '49' would 'confirm')."""
        fuzzer = self._fuzzer(set())
        fuzzer.verify_json_candidate(
            "https://t/api", {"f": "x"}, ("f",), "' OR 1=1--",
        )
        tried = {
            call.args[4] for call in fuzzer._test_json_payload.call_args_list
        }
        from packages.web.markers import STATIC_SIGNATURE_CLASSES
        self.assertEqual(tried, set(STATIC_SIGNATURE_CLASSES))
        self.assertNotIn("ssti", tried)


class TestReplayShapePartition(unittest.TestCase):
    def test_json_and_graphql_hits_never_reach_the_replay_oracle(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir, \
                patch("packages.web.scanner.WebClient"), \
                patch("packages.web.scanner.WebCrawler"):
            scanner = WebScanner("https://t.example", None, Path(tmpdir))
        hits = [
            {"attack_vector": "query_param", "endpoint": "https://t/a",
             "parameter": "q", "method": "GET"},
            {"attack_vector": "request_body", "endpoint": "https://t/b",
             "parameter": "f", "method": "POST"},
            {"attack_vector": "json_body", "endpoint": "https://t/c",
             "parameter": "user.name", "method": "POST"},
            {"attack_vector": "json_body_sweep", "endpoint": "https://t/c",
             "parameter": "user.name", "method": "POST"},
            {"attack_vector": "graphql_argument", "endpoint": "https://t/g",
             "parameter": "search.q", "method": "POST"},
        ]

        contexts, skipped = scanner._partition_replayable_hits(hits)

        self.assertEqual(len(contexts), 2)
        self.assertEqual(skipped, 3)
        for hit in hits[2:]:
            self.assertEqual(hit["verification"]["status"], "skipped")
            self.assertIn("shape", hit["verification"]["reason"])
