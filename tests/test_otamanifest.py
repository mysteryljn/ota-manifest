import tempfile
import unittest
from pathlib import Path
from otamanifest import build_manifest,sign_manifest,verify_bundle

class OtaTests(unittest.TestCase):
    def test_sign_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"image.bin"; image.write_bytes(b"firmware")
            bundle=sign_manifest(build_manifest(image,"ecu-a","1.2.3"),"secret")
            self.assertTrue(verify_bundle(bundle,"secret")); self.assertFalse(verify_bundle(bundle,"wrong"))
if __name__=="__main__": unittest.main()
