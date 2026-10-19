"""One failed analyzer invocation must not hide the remaining sessions."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_batch_analyze import batch_analyze


class BatchExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sessions = [self.root / "first.jsonl", self.root / "second.jsonl"]
        for index, session in enumerate(self.sessions):
            session.write_text(
                json.dumps(
                    {
                        "type": "user",
                        "message": {"role": "user", "content": "Inspect the project. " * 100},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            os.utime(session, (200 - index, 200 - index))

    def run_batch(self, outcomes: list) -> tuple[str, str]:
        temporary_paths = []
        remaining = iter(outcomes)

        def analyze(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            temporary_paths.append(Path(arguments[1]))
            outcome = next(remaining)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        arguments = [
            "batch-analyze.py",
            "--dir",
            str(self.root),
            "--dim",
            "perf",
            "--min-steps",
            "1",
            "--binary",
            "fixture-analyzer",
        ]
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", arguments), patch.object(
            batch_analyze, "find_conversation_files", return_value=self.sessions
        ), patch.object(batch_analyze.subprocess, "run", side_effect=analyze):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                batch_analyze.main()
        self.assertEqual(len(temporary_paths), 2)
        self.assertTrue(all(not path.exists() for path in temporary_paths))
        return output.getvalue(), errors.getvalue()

    def assert_first_failed(self, outcome: object) -> None:
        output, errors = self.run_batch(
            [outcome, subprocess.CompletedProcess([], 0, stdout='{"accepted":true}', stderr="")]
        )
        self.assertEqual(json.loads(output)["_session_id"], "second")
        self.assertIn("Done: 1 analyzed, 0 skipped, 1 failed", errors)
        self.assertEqual(errors.count("  OK (perf)"), 1)

    def test_spawn_errors_count_as_failures_and_continue(self) -> None:
        for error in (
            OSError("spawn failed"),
            FileNotFoundError("fixture missing"),
            PermissionError("not executable"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assert_first_failed(error)

    def test_non_object_json_counts_as_failure_and_continues(self) -> None:
        for value in ([], None, "unexpected", 42, True):
            with self.subTest(value=value):
                self.assert_first_failed(
                    subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr="")
                )

    def test_invalid_json_keeps_the_existing_continue_behavior(self) -> None:
        self.assert_first_failed(subprocess.CompletedProcess([], 0, stdout="{", stderr=""))

    def test_timeout_keeps_the_existing_continue_behavior(self) -> None:
        self.assert_first_failed(subprocess.TimeoutExpired("fixture", 300))

    def test_nonzero_exit_keeps_the_existing_continue_behavior(self) -> None:
        self.assert_first_failed(
            subprocess.CompletedProcess([], 1, stdout="", stderr="fixture failed")
        )

    def test_two_successes_keep_metadata_and_summary(self) -> None:
        output, errors = self.run_batch(
            [subprocess.CompletedProcess([], 0, stdout="{}", stderr="") for _ in range(2)]
        )
        decoder = json.JSONDecoder()
        first, end = decoder.raw_decode(output)
        second = json.loads(output[end:])
        self.assertEqual([first["_session_id"], second["_session_id"]], ["first", "second"])
        self.assertEqual(first["_source_file"], str(self.sessions[0]))
        self.assertEqual(first["_steps"], 1)
        self.assertIn("Done: 2 analyzed, 0 skipped, 0 failed", errors)

    @unittest.skipUnless(os.name == "posix", "executable analyzer fixtures require POSIX")
    def test_real_cli_process_continues_after_non_object_output(self) -> None:
        analyzer = self.root / "analyzer.py"
        analyzer.write_text(
            f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
            "doc=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
            "print('[]' if doc['session_id']=='first' else '{\"accepted\":true}')\n",
            encoding="utf-8",
        )
        analyzer.chmod(0o700)
        result = self.run_cli(str(analyzer))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["_session_id"], "second")
        self.assertIn("Done: 1 analyzed, 0 skipped, 1 failed", result.stderr)
        self.assertFalse(list(self.root.glob("atif-*.json")))

    def test_real_cli_missing_binary_counts_each_file_without_traceback(self) -> None:
        result = self.run_cli(str(self.root / "missing-analyzer"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("Done: 0 analyzed, 0 skipped, 2 failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(list(self.root.glob("atif-*.json")))

    def run_cli(self, binary: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                batch_analyze.__file__,
                "--dir",
                str(self.root),
                "--dim",
                "perf",
                "--min-steps",
                "1",
                "--binary",
                binary,
            ],
            env={
                **os.environ,
                "TMPDIR": str(self.root),
                "TEMP": str(self.root),
                "TMP": str(self.root),
            },
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )


if __name__ == "__main__":
    unittest.main()
