#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

def canonical(manifest):
    return json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def build_manifest(image,ecu,version,rollback=False):
    data=image.read_bytes()
    return {"schema":"ota-manifest/v1","ecu":ecu,"version":version,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"rollback_allowed":bool(rollback),"created_at":int(time.time())}

def sign_manifest(manifest,key):
    signature=hmac.new(key.encode(),canonical(manifest),hashlib.sha256).digest()
    return {"manifest":manifest,"algorithm":"HMAC-SHA256","signature":base64.b64encode(signature).decode()}

def verify_bundle(bundle,key,image=None):
    # Treat untrusted input as a verification failure rather than allowing a
    # malformed bundle to crash callers (for example, a missing signature
    # previously raised ``KeyError`` below).
    if (not isinstance(bundle, dict)
            or bundle.get("algorithm") != "HMAC-SHA256"
            or not isinstance(bundle.get("manifest"), dict)
            or not isinstance(bundle.get("signature"), str)):
        return False
    expected=hmac.new(key.encode(),canonical(bundle["manifest"]),hashlib.sha256).digest()
    try: actual=base64.b64decode(bundle["signature"],validate=True)
    except Exception: return False
    if not hmac.compare_digest(actual,expected): return False
    if image is None: return True
    try:
        data=image.read_bytes()
    except (OSError,TypeError):
        return False
    manifest=bundle["manifest"]
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
    bundle=json.loads(args.manifest.read_text(encoding="utf-8")); ok=verify_bundle(bundle,args.key,args.image); print("OK" if ok else "INVALID"); return 0 if ok else 1

if __name__=="__main__": raise SystemExit(main())
