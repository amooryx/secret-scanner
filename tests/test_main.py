import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main
import rclib


class SecretScannerTests(unittest.TestCase):
    def scan(self, target):
        ctx = rclib.Context(args=argparse.Namespace(), tool="secret-scanner", target=target)
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main.run(ctx)
        return code, ctx, output.getvalue(), errors.getvalue()

    def test_dotted_windows_file_path_is_read_locally(self):
        secret = "AKIA" + "A" * 16
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "settings.json"
            source.write_text(secret, encoding="ascii")
            with patch("main.urllib.request.urlopen") as urlopen:
                code, ctx, output, errors = self.scan(str(source))

        self.assertEqual(code, 0)
        self.assertEqual(len(ctx.findings), 1)
        urlopen.assert_not_called()
        self.assertEqual(errors, "")
        self.assertNotIn(secret, output)
        self.assertNotIn(secret, json.dumps(ctx.to_json()))
        self.assertEqual(ctx.findings[0].detail, "")

    def test_explicit_http_url_is_fetched_and_finding_is_redacted(self):
        secret = "ghp_" + "A" * 36

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return secret.encode("ascii")

        with patch("main.urllib.request.urlopen", return_value=Response()) as urlopen:
            code, ctx, output, errors = self.scan("https://example.test/config")

        self.assertEqual(code, 0)
        urlopen.assert_called_once()
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(errors, "")
        self.assertNotIn(secret, output)
        self.assertNotIn(secret, json.dumps(ctx.to_json()))

    def test_http_error_is_actionable_without_echoing_url(self):
        url = "https://example.test/config?token=not-for-output"
        with patch(
            "main.urllib.request.urlopen",
            side_effect=main.urllib.error.HTTPError(url, 404, "Not Found", {}, None),
        ):
            code, _, output, errors = self.scan(url)

        self.assertEqual(code, 1)
        self.assertIn("HTTP 404", errors)
        self.assertNotIn("not-for-output", output + errors)


if __name__ == "__main__":
    unittest.main()
