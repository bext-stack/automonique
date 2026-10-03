# Isolated asset viewers

The workspace sends verified file bytes to `artifact-viewer.html` in an opaque
sandbox (`allow-scripts`, without same-origin access). The frame cannot fetch
network resources or read dashboard credentials. SVGs are loaded as images;
Markdown passes through a strict element/attribute allowlist before insertion.

PDF.js runs in a blob worker. The parent fetches the local PDF engine only when
a PDF is opened; built-in fonts, CMaps and WASM decoders are bundled with it.
There are no CDN requests or external document viewers. PDF scripting and XFA
are not enabled. WASM compilation is permitted only in the isolated viewer.

Rebuild the committed assets from this directory:

```sh
npm ci --ignore-scripts
npm run build
```

`package-lock.json` pins dependencies and their integrity. The build writes the
viewer, PDF engine and third-party notices to the web entry's assets directory.
Deploy the same generated files to Share's `public/` directory and the shared
workspace script to `public/islands/artifacts.js`. Share uses
`viewerUrl: '/artifact-viewer.html'`; Monique uses `/artifact-viewer`.

PDFs support page navigation, thumbnails, bookmarks, selectable text, search,
zoom, rotation and password entry. Passwords remain in the frame. Scanned PDFs
without a text layer have no text search; OCR and annotation editing are not
included. Images support zoom, panning, rotation, backgrounds and bundle
navigation. CSV previews show at most 10,000 rows and 100 columns, with lazy row
display, filtering and sorting. Markdown has a reading view, JSON is formatted,
and text is searchable. Audio and video have speed, seek and loop controls.

Preview limits are 64 MiB for PDFs, 128 MiB for media and 32 MiB for other files;
text previews use at most 500,000 characters. Files beyond those limits and
unsupported formats remain downloadable. Each new selection stops the prior
frame and cancels further chunk reads. No document bytes are persisted by the
viewer. Viewing does not change a bundle's visibility or its versions.
