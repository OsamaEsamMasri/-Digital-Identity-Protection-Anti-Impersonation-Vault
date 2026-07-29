
import tkinter as tk
from tkinter import messagebox

import pkcs11
from pkcs11 import Attribute, Mechanism
from flask import Flask, request, jsonify

from config import (
    PKCS11_MODULE_PATH,
    TOKEN_LABEL,
    KEY_LABEL,
    AGENT_HOST,
    AGENT_PORT,
    ALLOWED_ORIGIN,
)

app = Flask(__name__)

_lib = pkcs11.lib(PKCS11_MODULE_PATH)
_token = _lib.get_token(token_label=TOKEN_LABEL)
_cached_pin = None


def get_pin():
    global _cached_pin
    if _cached_pin is None:
        _cached_pin = input("أدخل PIN الخاص بالـ Pico HSM لبدء جلسة الـ Agent: ").strip()
    return _cached_pin


def ask_user_confirmation(nonce_hex: str, origin: str) -> bool:
    root = tk.Tk()
    root.withdraw()
    message = (
        f"طلب تسجيل دخول جديد\n\n"
        f"الموقع: {origin}\n"
        f"رمز التحدي: {nonce_hex[:16]}...\n\n"
        f"هل توافق على توقيع هذا الطلب باستخدام الـ HSM؟"
    )
    result = messagebox.askyesno("تأكيد الدخول - Pico HSM Agent", message)
    root.destroy()
    return result


@app.before_request
def check_origin():
    origin = request.headers.get("Origin", "")
    if request.path == "/sign" and origin != ALLOWED_ORIGIN:
        return jsonify({"error": "origin not allowed"}), 403


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "token": TOKEN_LABEL})


@app.route("/sign", methods=["POST"])
def sign():
    data = request.get_json(force=True)
    nonce_hex = data.get("nonce")
    if not nonce_hex:
        return jsonify({"error": "missing nonce"}), 400

    origin = request.headers.get("Origin", "unknown")
    if not ask_user_confirmation(nonce_hex, origin):
        return jsonify({"error": "user rejected signing request"}), 403

    try:
        pin = get_pin()
        with _token.open(user_pin=pin) as session:
            private_key = session.get_key(
                label=KEY_LABEL, object_class=pkcs11.ObjectClass.PRIVATE_KEY
            )
            challenge_bytes = bytes.fromhex(nonce_hex)
            signature = private_key.sign(challenge_bytes, mechanism=Mechanism.ECDSA_SHA256)

            return jsonify({"signature": signature.hex()})
    except pkcs11.exceptions.PinIncorrect:
        global _cached_pin
        _cached_pin = None
        return jsonify({"error": "incorrect pin"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(f"[*] Local HSM Agent شغال على http://{AGENT_HOST}:{AGENT_PORT}")
    print(f"[*] accept request just from {ALLOWED_ORIGIN}")
    app.run(host=AGENT_HOST, port=AGENT_PORT, debug=False)
