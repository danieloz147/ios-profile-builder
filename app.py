#!/usr/bin/env python3
"""
ios-profile-builder
A local web UI for assembling Apple .mobileconfig configuration profiles.

Runs fully offline, binds to 127.0.0.1 by default, no telemetry,
no outbound network calls.

Python 3.8+ / Flask. No admin privileges required.
"""

import argparse
import base64
import os
import plistlib
import secrets
import shutil
import subprocess
import tempfile
import uuid

from flask import Flask, Response, render_template, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# --------------------------------------------------------------------------
# Limits / constants
# --------------------------------------------------------------------------

MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB cap on POST/upload size
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

PAYLOAD_VERSION = 1
MAX_PAYLOADS_PER_TYPE = 10


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    )
    return resp


# --------------------------------------------------------------------------
# Helpers
#
# SECURITY: every form field is treated strictly as untrusted DATA. Values
# only ever land in plist values via plistlib (which encodes/escapes them)
# and are never executed or interpreted as instructions.
# --------------------------------------------------------------------------

def new_uuid():
    return str(uuid.uuid4()).upper()


def _s(value, default=""):
    if value is None:
        return default
    return str(value).strip()


def _bool(value):
    return _s(value).lower() in ("1", "true", "on", "yes")


def base_payload(payload_type, display_name, identifier):
    return {
        "PayloadType": payload_type,
        "PayloadVersion": PAYLOAD_VERSION,
        "PayloadUUID": new_uuid(),
        "PayloadIdentifier": identifier,
        "PayloadDisplayName": display_name,
    }


# --------------------------------------------------------------------------
# Payload builders. Each returns a list of payload dicts (usually one).
# --------------------------------------------------------------------------

def build_webclip(form, root_id, idx):
    label = _s(form.get(f"webclip_label_{idx}"))
    url = _s(form.get(f"webclip_url_{idx}"))
    if not label and not url:
        return []
    p = base_payload(
        "com.apple.webClip.managed",
        label or "Web Clip",
        f"{root_id}.webclip.{idx}",
    )
    p["Label"] = label or "Web Clip"
    p["URL"] = url
    p["IsRemovable"] = _bool(form.get(f"webclip_removable_{idx}", "on"))
    p["FullScreen"] = _bool(form.get(f"webclip_fullscreen_{idx}"))
    icon = form.files.get(f"webclip_icon_{idx}")
    if icon is not None and getattr(icon, "filename", ""):
        data = icon.read()
        if data:
            p["Icon"] = data
    return [p]


def build_wifi(form, root_id, idx):
    ssid = _s(form.get(f"wifi_ssid_{idx}"))
    if not ssid:
        return []
    p = base_payload(
        "com.apple.wifi.managed",
        f"Wi-Fi ({ssid})",
        f"{root_id}.wifi.{idx}",
    )
    p["SSID_STR"] = ssid
    p["AutoJoin"] = _bool(form.get(f"wifi_autojoin_{idx}", "on"))
    p["HIDDEN_NETWORK"] = _bool(form.get(f"wifi_hidden_{idx}"))
    enc = _s(form.get(f"wifi_encryption_{idx}"), "WPA")
    p["EncryptionType"] = enc
    password = _s(form.get(f"wifi_password_{idx}"))
    if enc != "None" and password:
        p["Password"] = password
    return [p]


def build_vpn(form, root_id, idx):
    name = _s(form.get(f"vpn_name_{idx}"))
    server = _s(form.get(f"vpn_server_{idx}"))
    if not name and not server:
        return []
    p = base_payload(
        "com.apple.vpn.managed",
        name or "VPN",
        f"{root_id}.vpn.{idx}",
    )
    p["UserDefinedName"] = name or "VPN"
    vpn_type = _s(form.get(f"vpn_type_{idx}"), "IKEv2")
    p["VPNType"] = vpn_type
    p["VPN"] = {
        "RemoteAddress": server,
        "AuthenticationMethod": _s(form.get(f"vpn_auth_{idx}"), "SharedSecret"),
    }
    shared = _s(form.get(f"vpn_shared_secret_{idx}"))
    if shared:
        p["VPN"]["SharedSecret"] = shared
    if vpn_type == "IKEv2":
        p["IKEv2"] = {
            "RemoteAddress": server,
            "ServerCertificateIssuerCommonName": "",
        }
    return [p]


def _pem_or_der_to_der(raw_bytes):
    """Accept PEM or DER cert bytes, return DER bytes."""
    if b"-----BEGIN CERTIFICATE-----" in raw_bytes:
        body, capture = [], False
        for line in raw_bytes.splitlines():
            line = line.strip()
            if line.startswith(b"-----BEGIN"):
                capture = True
                continue
            if line.startswith(b"-----END"):
                break
            if capture:
                body.append(line)
        return base64.b64decode(b"".join(body))
    return raw_bytes


def build_root_ca(form, root_id, idx):
    cert_name = _s(form.get(f"ca_name_{idx}"), "Root CA")
    pem_paste = _s(form.get(f"ca_pem_{idx}"))
    raw = b""
    upload = form.files.get(f"ca_file_{idx}")
    if upload is not None and getattr(upload, "filename", ""):
        raw = upload.read()
    elif pem_paste:
        raw = pem_paste.encode("utf-8", "ignore")
    if not raw:
        return []
    try:
        der = _pem_or_der_to_der(raw)
    except Exception:
        raise ValueError(f"Root CA #{idx}: could not decode certificate (expected PEM or DER).")
    if not der:
        raise ValueError(f"Root CA #{idx}: empty certificate after decode.")
    p = base_payload("com.apple.security.root", cert_name, f"{root_id}.rootca.{idx}")
    p["PayloadCertificateFileName"] = _s(form.get(f"ca_filename_{idx}"), "rootca.cer")
    p["PayloadContent"] = der
    return [p]


def build_mdm(form, root_id, idx):
    server_url = _s(form.get(f"mdm_server_url_{idx}"))
    if not server_url:
        return []
    p = base_payload("com.apple.mdm", "MDM Enrollment", f"{root_id}.mdm.{idx}")
    p["ServerURL"] = server_url
    checkin = _s(form.get(f"mdm_checkin_url_{idx}"))
    if checkin:
        p["CheckInURL"] = checkin
    p["Topic"] = _s(form.get(f"mdm_topic_{idx}"))
    raw_rights = _s(form.get(f"mdm_access_rights_{idx}"), "8191")
    try:
        p["AccessRights"] = int(raw_rights or 8191)
    except ValueError:
        p["AccessRights"] = 8191
    p["CheckOutWhenRemoved"] = _bool(form.get(f"mdm_checkout_{idx}", "on"))
    p["SignMessage"] = _bool(form.get(f"mdm_signmessage_{idx}"))
    idc = _s(form.get(f"mdm_identity_uuid_{idx}"))
    if idc:
        p["IdentityCertificateUUID"] = idc
    return [p]


def build_custom(form, root_id, idx):
    raw = _s(form.get(f"custom_xml_{idx}"))
    if not raw:
        return []
    snippet = raw
    if "<plist" not in raw:
        snippet = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
            f'<plist version="1.0">{raw}</plist>'
        )
    try:
        parsed = plistlib.loads(snippet.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Custom payload #{idx}: invalid plist XML ({exc}).")
    if not isinstance(parsed, dict):
        raise ValueError(f"Custom payload #{idx}: top-level element must be a <dict>.")
    parsed.setdefault("PayloadType", _s(form.get(f"custom_type_{idx}"), "com.apple.custom"))
    parsed.setdefault("PayloadVersion", PAYLOAD_VERSION)
    parsed.setdefault("PayloadUUID", new_uuid())
    parsed.setdefault("PayloadIdentifier", f"{root_id}.custom.{idx}")
    parsed.setdefault("PayloadDisplayName", _s(form.get(f"custom_name_{idx}"), "Custom Payload"))
    return [parsed]


PAYLOAD_BUILDERS = {
    "webclip": build_webclip,
    "wifi": build_wifi,
    "vpn": build_vpn,
    "rootca": build_root_ca,
    "mdm": build_mdm,
    "custom": build_custom,
}


# --------------------------------------------------------------------------
# Form wrapper so builders reach request.files uniformly
# --------------------------------------------------------------------------

class _FormView:
    def __init__(self, req):
        self._form = req.form
        self.files = req.files

    def get(self, key, default=None):
        return self._form.get(key, default)


# --------------------------------------------------------------------------
# Profile assembly
# --------------------------------------------------------------------------

def assemble_profile(req):
    form = _FormView(req)
    display_name = _s(form.get("profile_display_name"), "Configuration Profile")
    identifier = _s(form.get("profile_identifier"), "com.example.profile")
    organization = _s(form.get("profile_organization"))
    description = _s(form.get("profile_description"))
    consent = _s(form.get("profile_consent"))

    payloads, errors = [], []
    for builder in PAYLOAD_BUILDERS.values():
        for idx in range(MAX_PAYLOADS_PER_TYPE):
            try:
                payloads.extend(builder(form, identifier, idx))
            except ValueError as exc:
                errors.append(str(exc))
    if errors:
        raise ValueError("; ".join(errors))

    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": PAYLOAD_VERSION,
        "PayloadUUID": new_uuid(),
        "PayloadIdentifier": identifier,
        "PayloadDisplayName": display_name,
        "PayloadContent": payloads,
    }
    if organization:
        profile["PayloadOrganization"] = organization
    if description:
        profile["PayloadDescription"] = description
    if consent:
        profile["ConsentText"] = {"default": consent}

    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


# --------------------------------------------------------------------------
# Optional openssl signing
# --------------------------------------------------------------------------

def _openssl_available():
    return shutil.which("openssl") is not None


def sign_profile(mc_bytes, p12_bytes, p12_password):
    """Sign with `openssl smime`. Returns (output_bytes, status_string). Never raises."""
    if not p12_bytes:
        return mc_bytes, "unsigned"
    if not _openssl_available():
        return mc_bytes, "unsigned (openssl not found on PATH)"

    tmpdir = tempfile.mkdtemp(prefix="iosprof_")
    p12_path = os.path.join(tmpdir, "cert.p12")
    key_path = os.path.join(tmpdir, "key.pem")
    crt_path = os.path.join(tmpdir, "crt.pem")
    in_path  = os.path.join(tmpdir, "profile.mobileconfig")
    out_path = os.path.join(tmpdir, "signed.mobileconfig")
    try:
        with open(p12_path, "wb") as fh:
            fh.write(p12_bytes)
        with open(in_path, "wb") as fh:
            fh.write(mc_bytes)
        pw = p12_password or ""
        subprocess.run(
            ["openssl", "pkcs12", "-in", p12_path, "-nocerts", "-nodes",
             "-out", key_path, "-passin", f"pass:{pw}"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkcs12", "-in", p12_path, "-clcerts", "-nokeys",
             "-out", crt_path, "-passin", f"pass:{pw}"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "smime", "-sign", "-in", in_path, "-out", out_path,
             "-signer", crt_path, "-inkey", key_path, "-certfile", crt_path,
             "-outform", "der", "-nodetach"],
            check=True, capture_output=True,
        )
        with open(out_path, "rb") as fh:
            signed = fh.read()
        return signed, "signed"
    except subprocess.CalledProcessError as exc:
        app.logger.warning("sign_profile: openssl error: %s",
                           (exc.stderr or b"").decode("utf-8", "ignore").strip())
        return mc_bytes, "unsigned (signing failed: check server logs)"
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("sign_profile: unexpected error: %s", exc)
        return mc_bytes, "unsigned (signing error: check server logs)"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    template = request.args.get("template", "")
    return render_template("index.html", template=template,
                           openssl=_openssl_available())


@app.route("/build", methods=["POST"])
def build():
    try:
        mc_bytes = assemble_profile(request)
    except ValueError as exc:
        return render_template("index.html", template="",
                               openssl=_openssl_available(),
                               error=str(exc)), 400

    status = "unsigned"
    p12 = request.files.get("signing_p12")
    if p12 is not None and getattr(p12, "filename", ""):
        p12_bytes = p12.read()
        p12_pw = _s(request.form.get("signing_password"))
        mc_bytes, status = sign_profile(mc_bytes, p12_bytes, p12_pw)

    fname = _s(request.form.get("profile_filename"), "profile")
    fname = os.path.basename(fname)
    fname = "".join(c for c in fname if c.isalnum() or c in "-_")
    fname = fname or "profile"
    fname += ".mobileconfig"

    resp = Response(mc_bytes, mimetype="application/x-apple-aspen-config")
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["X-Profile-Signing-Status"] = status
    return resp


@app.route("/analyze", methods=["POST"])
def analyze():
    f = request.files.get("profile_file")
    if f is None or not getattr(f, "filename", ""):
        return jsonify({"error": "No file uploaded"}), 400

    raw = f.read()
    try:
        profile = plistlib.loads(raw)
    except Exception as exc:
        return jsonify({"error": f"Could not parse plist: {exc}"}), 400

    if not isinstance(profile, dict):
        return jsonify({"error": "Not a valid .mobileconfig file"}), 400

    def safe(v):
        if isinstance(v, bytes):
            return f"<binary {len(v)}B>"
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v
        return str(v)

    result = {
        "display_name": _s(profile.get("PayloadDisplayName")),
        "identifier": _s(profile.get("PayloadIdentifier")),
        "organization": _s(profile.get("PayloadOrganization")),
        "description": _s(profile.get("PayloadDescription")),
        "payloads": [],
    }

    for p in profile.get("PayloadContent", []):
        if not isinstance(p, dict):
            continue
        ptype = _s(p.get("PayloadType"))
        info = {
            "type": ptype,
            "display_name": _s(p.get("PayloadDisplayName")),
            "fields": {},
        }
        if ptype == "com.apple.wifi.managed":
            info["fields"]["SSID"] = safe(p.get("SSID_STR", ""))
            info["fields"]["Encryption"] = safe(p.get("EncryptionType", ""))
            info["fields"]["AutoJoin"] = safe(p.get("AutoJoin", True))
        elif ptype == "com.apple.vpn.managed":
            info["fields"]["Name"] = safe(p.get("UserDefinedName", ""))
            info["fields"]["VPN Type"] = safe(p.get("VPNType", ""))
            vpn = p.get("VPN", {})
            if isinstance(vpn, dict):
                info["fields"]["Server"] = safe(vpn.get("RemoteAddress", ""))
        elif ptype == "com.apple.security.root":
            info["fields"]["Cert File"] = safe(p.get("PayloadCertificateFileName", ""))
            cert_data = p.get("PayloadContent")
            if cert_data:
                size = len(cert_data) if isinstance(cert_data, bytes) else "?"
                info["fields"]["Cert Size"] = f"{size}B"
        elif ptype == "com.apple.mdm":
            info["fields"]["Server URL"] = safe(p.get("ServerURL", ""))
            info["fields"]["CheckIn URL"] = safe(p.get("CheckInURL", ""))
            info["fields"]["Topic"] = safe(p.get("Topic", ""))
            info["fields"]["Access Rights"] = safe(p.get("AccessRights", ""))
        elif ptype in ("com.apple.mail.managed", "com.apple.eas.account"):
            info["fields"]["Email"] = safe(p.get("EmailAddress", ""))
            info["fields"]["Server"] = safe(
                p.get("IncomingMailServerHostName", p.get("PayloadHost", ""))
            )
        elif ptype == "com.apple.dnsSettings.managed":
            info["fields"]["Protocol"] = safe(p.get("DNSProtocol", ""))
            info["fields"]["Server URL"] = safe(p.get("ServerURL", p.get("ServerName", "")))
        elif ptype == "com.apple.proxy.http.global":
            info["fields"]["Proxy Server"] = safe(p.get("ProxyServer", ""))
            info["fields"]["Port"] = safe(p.get("ProxyServerPort", ""))
        elif ptype == "com.apple.webClip.managed":
            info["fields"]["URL"] = safe(p.get("URL", ""))
            info["fields"]["Full Screen"] = safe(p.get("FullScreen", False))
        elif ptype == "com.apple.applicationaccess":
            for k in ("allowCamera", "allowSafari", "allowAirDrop", "forceEncryptedBackup"):
                if k in p:
                    info["fields"][k] = safe(p[k])

        result["payloads"].append(info)

    return jsonify(result)


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "ok", "openssl": _openssl_available()}


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Local web UI for building Apple .mobileconfig profiles."
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1, local only).")
    parser.add_argument("--port", type=int, default=5000,
                        help="Bind port (default 5000).")
    parser.add_argument("--debug", action="store_true",
                        help="Enable Flask debug mode (development only).")
    args = parser.parse_args()
    print(f"[ios-profile-builder] http://{args.host}:{args.port}  "
          f"(openssl signing: {'available' if _openssl_available() else 'not found'})")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
