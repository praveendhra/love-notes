# love-notes
## Cards

| Card | URL |
|------|-----|
| May 2026 | https://love-notes.praveendhra.com/boo_051926.html |
| Birthday, Oct 24 2026 | https://love-notes.praveendhra.com/boo_102426.html |

## Building an encrypted card (`boo_102426` style)

Source (card HTML + photos) lives in `src/<name>/` and is **gitignored** — the repo is public, so only the encrypted output is committed.

```bash
pip install cryptography pillow
CARD_PASSWORD='the-secret' python3 tools/encrypt_card.py boo_102426
git add boo_102426.html && git commit -m "card: rebuild" && git push
```

The output is a lock screen plus the whole card (photos inlined) encrypted with AES-256-GCM; the key is derived from the password with PBKDF2 (300k iterations). Passwords are trimmed + lowercased before use. Web Crypto needs https or localhost — a `file://` open will not decrypt.
