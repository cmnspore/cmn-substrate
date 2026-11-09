import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "check_manifest", Path(__file__).resolve().parents[1] / "check_manifest.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "vectors").mkdir()
        self.write("manifest.json", {"version": checker.VERSION, "vectors": {"sample": "vectors/sample.json"}})
        self.write("vectors/sample.json", {"version": checker.VERSION, "cases": [{"id": "one"}]})

    def write(self, path, value):
        (self.root / path).write_text(json.dumps(value), encoding="utf-8")

    def test_independent_package(self):
        checker.check_manifest(self.root)

    def test_unlisted_vector(self):
        self.write("vectors/extra.json", {"version": checker.VERSION, "cases": [{"id": "extra"}]})
        with self.assertRaisesRegex(ValueError, "unlisted"):
            checker.check_manifest(self.root)

    def test_missing_vector(self):
        (self.root / "vectors/sample.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            checker.check_manifest(self.root)

    def test_duplicate_case_id(self):
        self.write("vectors/sample.json", {"version": checker.VERSION, "cases": [{"id": "one"}, {"id": "one"}]})
        with self.assertRaisesRegex(ValueError, "duplicate case id"):
            checker.check_manifest(self.root)

    def test_invalid_json(self):
        (self.root / "vectors/sample.json").write_text("{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            checker.check_manifest(self.root)

    def test_version_and_empty_cases(self):
        for document in [{"version": "wrong", "cases": [{"id": "one"}]}, {"version": checker.VERSION, "cases": []}]:
            with self.subTest(document=document):
                self.write("vectors/sample.json", document)
                with self.assertRaises(ValueError):
                    checker.check_manifest(self.root)

    def test_path_traversal(self):
        self.write("manifest.json", {"version": checker.VERSION, "vectors": {"sample": "../sample.json"}})
        with self.assertRaisesRegex(ValueError, "invalid vector path"):
            checker.check_manifest(self.root)
