#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path


_REQUIRED_MANIFEST_FIELDS = {
    "schema",
    "ecu",
    "version",
    "size",
    "sha256",
    "rollback_allowed",
    "created_at",
}

def canonical(manifest):
    return json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def _key_bytes(key):
    """Return key material only when a real shared secret was supplied.

    An empty HMAC key is accepted by the standard library, but it provides no
    authentication: anyone can reproduce a signature with ``--key ""``.
    Keep this check in one place so both signing and verification apply the
    same policy.
    """
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")
    try:
        return key.encode()
    except UnicodeEncodeError as exc:
        raise ValueError("key must be valid UTF-8 text") from exc

def build_manifest(image,ecu,version,rollback=False):
    data=image.read_bytes()
    return {"schema":"ota-manifest/v1","ecu":ecu,"version":version,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"rollback_allowed":bool(rollback),"created_at":int(time.time())}

def sign_manifest(manifest,key):
    signature=hmac.new(_key_bytes(key),canonical(manifest),hashlib.sha256).digest()
    return {"manifest":manifest,"algorithm":"HMAC-SHA256","signature":base64.b64encode(signature).decode()}


def _valid_manifest(manifest):
    """Return whether a manifest contains the complete v1 data model.

    A valid HMAC only proves that the signer approved the bytes it signed.  It
    does not make an incomplete manifest safe to consume.  Verifiers commonly
    run without an image path first, so validate all fields before accepting a
    signed manifest in that mode as well.
    """
    if manifest.get("schema") != "ota-manifest/v1":
        return False
    if not isinstance(manifest.get("ecu"), str) or not manifest["ecu"]:
        return False
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        return False

    size = manifest.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        return False

    digest = manifest.get("sha256")
    if (not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)):
        return False

    if not isinstance(manifest.get("rollback_allowed"), bool):
        return False
    created_at = manifest.get("created_at")
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
        return False
    return _REQUIRED_MANIFEST_FIELDS.issubset(manifest)

def verify_bundle(bundle,key,image=None):
    # Treat untrusted input as a verification failure rather than allowing a
    # malformed bundle to crash callers (for example, a missing signature
    # previously raised ``KeyError`` below).
    if (not isinstance(bundle, dict)
            or bundle.get("algorithm") != "HMAC-SHA256"
            or not isinstance(bundle.get("manifest"), dict)
            or not isinstance(bundle.get("signature"), str)):
        return False
    # JSON permits escaped lone surrogates (for example ``"\ud800"``), but
    # those values cannot be encoded as UTF-8 by ``canonical``.  A manifest
    # comes from an untrusted update channel, so treat this as a failed
    # verification instead of allowing UnicodeEncodeError to crash the
    # updater process.
    try:
        key_material = _key_bytes(key)
        expected=hmac.new(key_material,canonical(bundle["manifest"]),hashlib.sha256).digest()
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return False
    try: actual=base64.b64decode(bundle["signature"],validate=True)
    except Exception: return False
    if not hmac.compare_digest(actual,expected): return False
    manifest=bundle["manifest"]
    if not _valid_manifest(manifest):
        return False
    if image is None: return True
    try:
        data=image.read_bytes()
    except (OSError,TypeError):
        return False
    return (manifest.get("size") == len(data)
            and manifest.get("sha256") == hashlib.sha256(data).hexdigest())

def main(argv=None):
    parser=argparse.ArgumentParser(description="Create or verify an OTA manifest"); sub=parser.add_subparsers(dest="command")
    sign=sub.add_parser("sign"); sign.add_argument("image",type=Path); sign.add_argument("output",type=Path); sign.add_argument("--ecu",default="demo-ecu"); sign.add_argument("--version",required=True); sign.add_argument("--rollback",action="store_true"); sign.add_argument("--key",required=True)
    verify=sub.add_parser("verify"); verify.add_argument("manifest",type=Path); verify.add_argument("--image",type=Path); verify.add_argument("--key",required=True)
    args=parser.parse_args(argv)
    if not args.command: parser.error("a command is required: sign or verify")
    if args.command=="sign":
        bundle=sign_manifest(build_manifest(args.image,args.ecu,args.version,args.rollback),args.key); args.output.write_text(json.dumps(bundle,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); print(f"signed {args.output}"); return 0
    # Manifest files are untrusted input.  A truncated download, an invalid
    # encoding, or a missing file must be reported as a verification failure
    # instead of crashing the update orchestrator with a traceback.
    try:
        bundle=json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        print("INVALID")
        return 1
    ok=verify_bundle(bundle,args.key,args.image); print("OK" if ok else "INVALID"); return 0 if ok else 1

if __name__=="__main__": raise SystemExit(main())
