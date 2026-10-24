#!/usr/bin/env python3
"""Build a password-gated card for GitHub Pages.

Usage:
    CARD_PASSWORD='secret' python3 tools/encrypt_card.py boo_102426

Reads   src/<name>/card.html and src/<name>/photos/*.jpg
Writes  <name>.html at the repo root: a lock screen + the whole card
        (photos inlined) encrypted with AES-256-GCM, key from PBKDF2.
Nothing readable ships without the password, so src/ stays gitignored.
"""
import base64, json, os, re, sys
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageOps
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 300_000
MAX_SIDE = 1100   # photos resized before inlining; keeps the page ~2-3 MB
QUALITY = 78

ROOT = Path(__file__).resolve().parent.parent


def photo_data_uri(path: Path) -> str:
    im = ImageOps.exif_transpose(Image.open(path)).convert("RGB")
    im.thumbnail((MAX_SIDE, MAX_SIDE))
    buf = BytesIO()
    im.save(buf, "JPEG", quality=QUALITY, optimize=True, progressive=True)
    return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()


def normalize(pw: str) -> str:
    # same rule as the gate page: trim + lowercase, so "Bubu " still opens it
    return pw.strip().lower()


def build(name: str, password: str) -> Path:
    src = ROOT / "src" / name
    html = (src / "card.html").read_text(encoding="utf-8")

    # each photo is embedded once in a map; <img data-photo> tags pick it up at runtime
    photos = {}

    def sub(m):
        name = m.group(1)
        if name not in photos:
            photos[name] = photo_data_uri(src / "photos" / name)
        return f'data-photo="{name}"'
    html, n = re.subn(r'src="photos/([^"]+)"', sub, html)
    loader = ("<script>const PHOTOS=" + json.dumps(photos) +
              ";document.querySelectorAll('img[data-photo]').forEach(i=>i.src=PHOTOS[i.dataset.photo]);</script>\n</body>")
    html = html.replace("</body>", loader, 1)
    print(f"inlined {len(photos)} photos for {n} refs")

    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(normalize(password).encode())
    ct = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)

    # self-check: decrypt what we just encrypted
    assert AESGCM(key).decrypt(iv, ct, None).decode("utf-8") == html

    gate = (ROOT / "tools" / "gate_template.html").read_text(encoding="utf-8")
    out = (gate.replace("{{SALT}}", base64.b64encode(salt).decode())
               .replace("{{IV}}", base64.b64encode(iv).decode())
               .replace("{{ITER}}", str(ITER))
               .replace("{{CT}}", base64.b64encode(ct).decode()))
    dest = ROOT / f"{name}.html"
    dest.write_text(out, encoding="utf-8")
    print(f"wrote {dest.relative_to(ROOT)}  ({dest.stat().st_size/1e6:.2f} MB)")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pw = os.environ.get("CARD_PASSWORD")
    if not pw:
        sys.exit("set CARD_PASSWORD env var")
    build(sys.argv[1], pw)
