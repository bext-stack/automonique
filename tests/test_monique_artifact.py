# SPDX-License-Identifier: Elastic-2.0
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('artifact', Path(__file__).parents[1] / 'tools/monique_artifact.py')
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)

class ArtifactPublishingTests(unittest.TestCase):
    def test_hidden_files_are_excluded_and_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'index.html').write_text('Report')
            (root / '.env').write_text('secret')
            self.assertEqual([m['path'] for _, m in artifact.bundle_files(root)], ['index.html'])
            (root / 'outside.txt').symlink_to('/etc/hostname')
            with self.assertRaises(ValueError):
                artifact.bundle_files(root)

    def test_template_does_not_overwrite_and_escapes_title(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'report/index.html'
            artifact.report_template(p, '<script>oops</script>')
            self.assertNotIn('<script>oops</script>', p.read_text())
            with self.assertRaises(ValueError):
                artifact.report_template(p, 'Other')

    def test_private_configuration_is_required(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'share/share.conf'; p.parent.mkdir()
            p.write_text('public_base=https://share.example.test\nsecret=' + 'x' * 48)
            p.chmod(0o600)
            self.assertEqual(artifact.ArtifactClient(d).base, 'https://share.example.test')
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                artifact.ArtifactClient(d)

if __name__ == '__main__':
    unittest.main()
