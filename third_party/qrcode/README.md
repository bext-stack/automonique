# qrcode (vendored browser bundle)

The operator dashboard mints a mobile pairing offer and has to show it as a QR
code. Nothing in this repository could encode one, and the dashboard's own
content-security policy forbids fetching a script from anywhere but this origin,
so the encoder is vendored here rather than loaded.

- **Upstream:** [`node-qrcode`](https://github.com/soldair/node-qrcode) 1.5.4, MIT (see `LICENSE`).
- **File:** `qrcode-core.js`, SHA-256 `7afd3ef30f03717cd1b64cb0a6f18af96ad6563efe01d2da46e69ca7641eb64f`.
- **Contents:** the pure encoder (`qrcode/lib/core/qrcode.js`) only. No
  renderer, no CLI, no Node built-ins, and none of upstream's `pngjs`,
  `yargs` or `dijkstrajs` runtime surface beyond what the encoder itself
  reaches. The dashboard draws the returned module matrix as inline SVG,
  because the policy's `img-src 'self'` rules out a `data:` image.
- **Global:** `moniqueQrCode.create(text, options)`, returning upstream's
  `{ modules, version }`.

## Regenerating

From a checkout of `bext-stack/automonique-mobile` at a commit whose
`package-lock.json` pins `qrcode@1.5.4`:

```sh
cat > .qr-entry.js <<'ENTRY'
const QRCode = require('qrcode/lib/core/qrcode');
module.exports = { create: QRCode.create };
ENTRY
esbuild .qr-entry.js --bundle --format=iife --global-name=moniqueQrCode \
  --platform=browser --target=es2020 --minify --legal-comments=none \
  --outfile=qrcode-core.js
rm .qr-entry.js
```

## Why this is trusted

The bundle was checked against upstream's own encoder on 400 payloads — 200
pairing offers of the exact shape the dashboard encodes and 200 pseudo-random
strings from 1 to 600 bytes — asserting the complete module matrix is identical
for every one at error-correction level M. A pairing offer encodes as a version
15 symbol, 77x77 modules.
