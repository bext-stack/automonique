# Versioned deliverables

Share is the durable bundle authority. Monique brokers authenticated requests;
the browser never receives the ingest credential. New bundles are private.
The library, run panel and conversation preview all read the same manifests.
Visibility is applied to the bundle, including historical versions and files.

Agents use `tools/monique_artifact.py`, with `AUTOMONIQUE_STATE_DIR` pointing to
the configured daemon state. The existing private `share/share.conf` configures
the HTTPS service and credential. The fleet worker supplies run, issue and agent
context for every provider. Interactive agents can pass `--run-id`, `--issue`,
`--conversation` and `--agent` explicitly.

```sh
monique-artifact template report/index.html --title 'Delivery report'
# Replace the scaffold with verified findings and add supporting files.
monique-artifact publish report --title 'Delivery report' --project 'Website'
monique-artifact publish report --artifact-id BUNDLE_ID --note 'Updated evidence'
monique-artifact visibility BUNDLE_ID public
monique-artifact visibility BUNDLE_ID private
```

Keep the emitted artifact ID in the completion response. `--public` is explicit;
an updated version inherits the existing bundle visibility. Uploading does not
mark a job complete or substitute for the GitHub completion receipt.

The Share API stages a manifest, accepts individually hashed 1 MiB chunks, then
atomically commits a complete immutable version. Revision checks reject stale
edits and publication across a concurrent privacy change. Limits are 400 files,
128 MiB per file, 512 MiB per version and 100 versions. Hidden files and symlinks
are excluded/refused by the publishing tool. Upload drafts expire after 24 hours;
failed uploads cannot be read through the public or private viewing API.

Previews use a sandboxed frame with no same-origin permission, no network,
no forms and no top-level navigation. Only bundled resources are supplied.
Office files and large media remain downloadable. HTML previews load at most
32 MiB of bundled resources, with an 8 MiB per dependency limit. Public access is
by link; the private library does not become a public directory. Public responses
do not include run, conversation, agent or ticket provenance.

Historical bundles can retain their existing public addresses. Share stores an
operator-only legacy directory mapping and atomically moves that directory out
of the public alias when privacy is enabled. A failed move stays visibly pending
and can be retried; it never reports successful revocation. Previously downloaded
or cached copies cannot be recalled. New bundles never use a public static alias.
