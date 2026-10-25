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
            self.assertTrue(verify_bundle(bundle,"secret",image))
            image.write_bytes(b"tampered")
            self.assertFalse(verify_bundle(bundle,"secret",image))

    def test_payload_verification_rejects_missing_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"image.bin"; image.write_bytes(b"firmware")
            bundle=sign_manifest(build_manifest(image,"ecu-a","1.2.3"),"secret")
            self.assertFalse(verify_bundle(bundle,"secret",Path(tmp)/"missing.bin"))

    def test_malformed_bundle_is_rejected_without_exception(self):
        # A manifest read from disk is untrusted input.  Missing or malformed
        # signatures must produce a normal verification failure instead of a
        # KeyError/AttributeError that can take down an update verifier.
        self.assertFalse(verify_bundle({"algorithm": "HMAC-SHA256", "manifest": {}}, "secret"))
        self.assertFalse(verify_bundle([], "secret"))
if __name__=="__main__": unittest.main()
