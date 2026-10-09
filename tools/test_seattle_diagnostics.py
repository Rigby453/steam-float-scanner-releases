import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('diag', Path(__file__).with_name('seattle-diagnostics.py'))
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class DiagnosticsTests(unittest.TestCase):
    def fixture(self):
        return dict(computer='SFSPR', account='Administrator', installedVersion='0.2.149',
                    scannerProcessCount=4, logExists=True, tailLines=500, validJsonLines=499,
                    capturedUtc='2026-10-09T09:07:17.2873909Z', logModifiedUtc=None,
                    observedCodeCounts={'PURCHASE_CONTRACT_MODULE_CHANGED': 2})

    def test_free_text_and_unknown_fields_are_dropped(self):
        value = self.fixture()
        value['secret'] = 'never expose'; value['scope'] = 'never expose'
        value['observedCodeCounts']['SECRET_PASSWORD'] = 'never expose'
        safe = diag.sanitize(value)
        self.assertNotIn('never expose', str(safe))
        self.assertEqual(safe['observedCodeCounts'], {'PURCHASE_CONTRACT_MODULE_CHANGED': 2})

    def test_wrong_identity_and_unbounded_counts_fail(self):
        for key, bad in [('computer', 'other'), ('account', 'other'), ('tailLines', 501),
                         ('scannerProcessCount', 'secret'), ('installedVersion', '0.2.149 password'),
                         ('capturedUtc', 'secret')]:
            value = self.fixture(); value[key] = bad
            with self.assertRaises(ValueError): diag.sanitize(value)

    def test_fixed_read_only_payload_and_connection_flags(self):
        args = diag.ssh_arguments('key', 'pin')
        for flag in ['StrictHostKeyChecking=yes', 'BatchMode=yes', 'ConnectTimeout=8',
                     'ConnectionAttempts=1', 'ClearAllForwardings=yes']:
            self.assertIn(flag, args)
        self.assertIn('Administrator@66.55.78.51', args)
        for forbidden in ['Set-Content', 'Start-Process', 'Stop-Process', 'Invoke-Expression',
                          'Set-Item', 'Remove-Item', 'Start-Service', 'Stop-Service']:
            self.assertNotIn(forbidden, diag.REMOTE_SCRIPT)
        self.assertIn('-Last 500', diag.REMOTE_SCRIPT)
        self.assertIn('New-Object byte[] 262144', diag.REMOTE_SCRIPT)


if __name__ == '__main__': unittest.main()
