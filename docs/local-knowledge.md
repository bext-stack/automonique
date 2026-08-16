# Local entity knowledge

Automonique optionally reads `knowledge/catalog.json` beneath its state
directory when a natural-language question names a local entity. The file is
read again for every lookup, so a valid atomic replacement is visible to the
next question without restarting the daemon or interrupting active work.

The catalog must be a regular file owned by the daemon user, mode `0600`, no
larger than 128 KiB. It accepts at most 128 entities, with bounded aliases and
claims. Unknown fields, ambiguous aliases, malformed values, symlinks and
group/world permissions are refused.

```json
{
  "schema": "automonique.local-knowledge/v1",
  "entities": [
    {
      "id": "acme",
      "name": "Acme",
      "aliases": ["acme.example", "acme-stack"],
      "description": {
        "text": "A concise description supported by the named source.",
        "basis": "operator_asserted",
        "source": "approved internal catalog"
      },
      "facts": [
        {
          "text": "One bounded factual claim.",
          "basis": "local_observation",
          "source": "enabled service inventory"
        }
      ]
    }
  ]
}
```

`basis` is one of `operator_asserted`, `local_observation`, or
`primary_source`. Each claim needs its own provenance. Catalog data is treated
as untrusted read-only evidence, never as instructions or authorization.

Entity questions combine matching catalog entries with retrieved durable
memory, recent conversation, and any matching live typed projections such as
the enabled Prism inventory or configured model routes. Current typed facts win
when they conflict with older memory. Unrelated general conversation stays on
the fast conversation route.
