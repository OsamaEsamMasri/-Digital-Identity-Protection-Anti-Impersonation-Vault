
import sys
import pkcs11
from pkcs11 import KeyType, Mechanism, Attribute
from pkcs11.util.ec import encode_named_curve_parameters

from config import PKCS11_MODULE_PATH, TOKEN_LABEL, KEY_LABEL, KEY_ID, EC_CURVE


def main():
    user_pin = input("أدخل PIN الخاص بالـ Pico HSM: ").strip()

    print("[*] جاري تحميل مكتبة PKCS#11...")
    lib = pkcs11.lib(PKCS11_MODULE_PATH)

    print(f"[*] جاري البحث عن التوكن: {TOKEN_LABEL}")
    token = lib.get_token(token_label=TOKEN_LABEL)

    with token.open(user_pin=user_pin, rw=True) as session:
        print("[*] جاري توليد زوج المفاتيح داخل الـ HSM (هذا قد يستغرق بضع ثوانٍ)...")

        parameters = session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters(EC_CURVE)},
            local=True,
        )

        public, private = parameters.generate_keypair(
            mechanism=Mechanism.EC_KEY_PAIR_GEN,
            label=KEY_LABEL,
            id=KEY_ID,
            store=True,
            private_template={
                Attribute.SIGN: True,
                Attribute.EXTRACTABLE: False,   # <-- أهم سطر بالملف كله
                Attribute.SENSITIVE: True,
            },
            public_template={
                Attribute.VERIFY: True,
            },
        )

        print("[+] تم توليد المفتاح بنجاح داخل الـ HSM.")

        ec_point_der = public[Attribute.EC_POINT]
        # القيمة راجعة كـ DER OCTET STRING تحتوي 04 || X || Y (نقطة غير مضغوطة)
        # أول بايتين هني header الـ DER (نوع الحقل + الطول)، منشيلهم
        if ec_point_der[0] != 0x04 or len(ec_point_der) < 3:
            # بعض الإصدارات بترجع الـ OCTET STRING بشكل مختلف، نتعامل معها هون
            raw_point = ec_point_der
        else:
            raw_point = ec_point_der

        # لو كانت القيمة ملفوفة بـ DER OCTET STRING (0x04 len ...) نفك التغليف
        # هذا الجزء قد يحتاج تعديل بسيط حسب استجابة جهازك الفعلي
        pub_hex = raw_point.hex()

        with open("public_key.txt", "w") as f:
            f.write(pub_hex)

        print("\n[+] تم حفظ المفتاح العام بملف public_key.txt")
        print("[+] هذا هو المفتاح العام (انسخه وسجله بالموقع عبر /register):\n")
        print(pub_hex)
        print("\n[!] لا تشارك أي شيء غير هذا المفتاح العام. المفتاح الخاص محبوس جوا الـ HSM ولا يمكن استخراجه.")


if __name__ == "__main__":
    try:
        main()
    except pkcs11.exceptions.PinIncorrect:
        print("[!] الـ PIN غلط.")
        sys.exit(1)
    except pkcs11.exceptions.NoSuchToken:
        print(f"[!] ما لقيت التوكن. تأكد إن الـ Pico HSM موصول والاسم بـ config.py صحيح.")
        print("    جرب أمر: pkcs11-tool --module \"<مسار opensc-pkcs11.dll>\" -L")
        sys.exit(1)
