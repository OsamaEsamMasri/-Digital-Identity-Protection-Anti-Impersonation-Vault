"""
app.py
======
"لوحة تحكم جامعة" وهمية لأغراض العرض والاختبار فقط.

نظام الدخول هون مبني بالكامل على Challenge-Response:
  1. المستخدم يطلب تسجيل دخول باسمه فقط (بدون كلمة سر!).
  2. السيرفر يولّد "تحدي" عشوائي (nonce) ويخزنه مؤقتاً.
  3. الـ Local Agent (اللي عند المستخدم) يوقع التحدي بمفتاحه الخاص
     المحفوظ جوا الـ Pico HSM.
  4. السيرفر يتحقق من التوقيع باستخدام المفتاح العام المسجل مسبقاً.
     إذا صح -> جلسة دخول صالحة. المفتاح الخاص ما انكشف ولا لحظة.

تشغيل:
    pip install flask ecdsa
    python app.py
"""

import json
import os
import secrets
import time

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.util import sigdecode_string

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

KEYS_FILE = os.path.join(os.path.dirname(__file__), "keys.json")

# صلاحية التحدي بالثواني - يمنع إعادة استخدام توقيع قديم (Replay Attack)
CHALLENGE_TTL = 60

# تخزين مؤقت للتحديات النشطة { username: (nonce_hex, expires_at) }
_active_challenges = {}


def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE) as f:
        return json.load(f)


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
    """
    تسجيل مستخدم جديد بمفتاحه العام (خطوة تتم مرة وحدة، من طرف الأدمن
    الفعلي بعد ما يشغل enroll.py على جهازه ويولد المفتاح جوا الـ HSM).
    """
    data = request.get_json(force=True)
    username = data.get("username")
    public_key_hex = data.get("public_key")

    if not username or not public_key_hex:
        return jsonify({"error": "username و public_key مطلوبين"}), 400

    keys = load_keys()
    keys[username] = public_key_hex
    save_keys(keys)

    return jsonify({"status": "registered", "username": username})


@app.route("/challenge", methods=["POST"])
def challenge():
    """الخطوة 1: المستخدم يطلب تحدي دخول."""
    data = request.get_json(force=True)
    username = data.get("username")

    keys = load_keys()
    if username not in keys:
        return jsonify({"error": "مستخدم غير مسجل"}), 404

    nonce = secrets.token_bytes(32)
    nonce_hex = nonce.hex()
    _active_challenges[username] = (nonce_hex, time.time() + CHALLENGE_TTL)

    return jsonify({"nonce": nonce_hex})


@app.route("/verify", methods=["POST"])
def verify():
    """الخطوة 2: التحقق من التوقيع الراجع من الـ Pico HSM."""
    data = request.get_json(force=True)
    username = data.get("username")
    signature_hex = data.get("signature")

    if username not in _active_challenges:
        return jsonify({"error": "لا يوجد تحدي نشط لهذا المستخدم"}), 400

    nonce_hex, expires_at = _active_challenges[username]

    if time.time() > expires_at:
        del _active_challenges[username]
        return jsonify({"error": "انتهت صلاحية التحدي، اطلب واحد جديد"}), 400

    keys = load_keys()
    public_key_hex = keys.get(username)
    if not public_key_hex:
        return jsonify({"error": "مستخدم غير مسجل"}), 404

    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        # المفتاح خزناه كنقطة غير مضغوطة 04||X||Y
        if pub_bytes[0] == 0x04:
            pub_bytes = pub_bytes[1:]

        vk = VerifyingKey.from_string(pub_bytes, curve=NIST256p)
        signature = bytes.fromhex(signature_hex)
        challenge_bytes = bytes.fromhex(nonce_hex)

        vk.verify(
            signature,
            challenge_bytes,
            hashfunc=__import__("hashlib").sha256,
            sigdecode=sigdecode_string,
        )

        # التوقيع صحيح -> نلغي التحدي (منع إعادة استخدامه) ونفتح جلسة
        del _active_challenges[username]
        session["user"] = username
        return jsonify({"status": "success"})

    except BadSignatureError:
        return jsonify({"error": "توقيع غير صحيح"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("index"))
    return render_template("dashboard.html", username=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
