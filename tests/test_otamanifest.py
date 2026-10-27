import tempfile
import unittest
from pathlib import Path
from otamanifest import build_manifest,main,sign_manifest,verify_bundle


class StreamingOnlyPath:
    """Path wrapper that fails if the implementation reads all bytes at once."""
    def __init__(self,path):
        self.path=path

    def open(self,*args,**kwargs):
        return self.path.open(*args,**kwargs)

    def read_bytes(self):
        raise AssertionError("OTA hashing must stream the image")

class OtaTests(unittest.TestCase):
    def test_sign_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"image.bin"; image.write_bytes(b"firmware")
            bundle=sign_manifest(build_manifest(image,"ecu-a","1.2.3"),"secret")
            self.assertTrue(verify_bundle(bundle,"secret")); self.assertFalse(verify_bundle(bundle,"wrong"))
            self.assertTrue(verify_bundle(bundle,"secret",image))
            image.write_bytes(b"tampered")
            self.assertFalse(verify_bundle(bundle,"secret",image))

    def test_empty_hmac_key_is_rejected(self):
        # HMAC accepts an empty key, but that makes the signature reproducible
        # by any attacker and therefore turns verification into no protection.
        with self.assertRaises(ValueError):
            sign_manifest({"payload": "test"}, "")

        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"image.bin"; image.write_bytes(b"firmware")
            bundle=sign_manifest(build_manifest(image,"ecu-a","1.2.3"),"secret")
            self.assertFalse(verify_bundle(bundle, ""))
            self.assertFalse(verify_bundle(bundle, None))

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

    def test_manifest_with_invalid_unicode_is_rejected_without_exception(self):
        # JSON allows escaped lone surrogates, while UTF-8 encoding the
        # canonical form does not.  Untrusted input must fail closed rather
        # than taking down the OTA verifier with UnicodeEncodeError.
        manifest = {
            "schema": "ota-manifest/v1",
            "ecu": "ecu-a",
            "version": "1.2.3",
            "size": 0,
            "sha256": "0" * 64,
            "rollback_allowed": False,
            "created_at": 0,
            "description": "\ud800",
        }
        bundle = {
            "algorithm": "HMAC-SHA256",
            "manifest": manifest,
            "signature": "",
        }
        self.assertFalse(verify_bundle(bundle, "secret"))

    def test_signed_manifest_requires_complete_metadata_without_image(self):
        # A valid HMAC does not make an incomplete manifest safe to consume.
        # Verification without an image still needs the fields used by an
        # updater to select and describe the payload.
        incomplete = {
            "schema": "ota-manifest/v1",
            "ecu": "ecu-a",
            "version": "1.2.3",
            "size": 8,
            "sha256": "0" * 64,
        }
        self.assertFalse(verify_bundle(sign_manifest(incomplete, "secret"), "secret"))

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "image.bin"
            image.write_bytes(b"firmware")
            malformed = build_manifest(image, "ecu-a", "1.2.3")
            malformed["size"] = -1
            self.assertFalse(verify_bundle(sign_manifest(malformed, "secret"), "secret"))

    def test_cli_rejects_unreadable_manifest_without_crashing(self):
        # A partially written or corrupted manifest must fail closed so an OTA
        # orchestrator can handle the failure and retry safely.
        with tempfile.TemporaryDirectory() as tmp:
            manifest=Path(tmp)/"manifest.json"
            manifest.write_text("{not-json", encoding="utf-8")
            self.assertEqual(main(["verify", str(manifest), "--key", "secret"]), 1)

            manifest.write_bytes(b"\xff\xfe\x00")
            self.assertEqual(main(["verify", str(manifest), "--key", "secret"]), 1)

            self.assertEqual(main(["verify", str(Path(tmp)/"missing.json"), "--key", "secret"]), 1)

    def test_cli_sign_reports_io_and_key_errors_without_traceback(self):
        # Signing is also an input/output boundary: a missing source image or
        # invalid destination must return a controlled failure to automation.
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.bin"
            output = Path(tmp) / "manifest.json"
            self.assertEqual(main([
                "sign", str(missing), str(output), "--version", "1.0", "--key", "secret"
            ]), 2)

            image = Path(tmp) / "image.bin"
            image.write_bytes(b"firmware")
            # The temporary directory itself is not a writable file target.
            self.assertEqual(main([
                "sign", str(image), tmp, "--version", "1.0", "--key", "secret"
            ]), 2)

            self.assertEqual(main([
                "sign", str(image), str(output), "--version", "1.0", "--key", ""
            ]), 2)

    def test_image_hashing_is_streamed(self):
        # Firmware can be hundreds of megabytes.  Both signing and payload
        # verification must hash it in bounded chunks instead of calling
        # Path.read_bytes(), which would allocate the complete image.
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"large-image.bin"
            image.write_bytes(b"A" * (2 * 1024 * 1024 + 17))
            streamed=StreamingOnlyPath(image)
            bundle=sign_manifest(build_manifest(streamed,"ecu-a","1.2.3"),"secret")
            self.assertTrue(verify_bundle(bundle,"secret",streamed))
if __name__=="__main__": unittest.main()
