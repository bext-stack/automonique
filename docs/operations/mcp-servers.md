# MCP servers

Automonique can discover and call explicitly configured MCP 2026-07-28 servers from natural-language Telegram conversations. Tool choice is model-led, but authority is not: the model can select only an exact server/tool pair returned by live discovery, cannot select URLs or credentials, and cannot bypass an MCP `input_required` response.

Configuration is optional at `<state>/mcp/servers.json`. If the file is absent, no MCP client is composed. If present, it must be an owner-owned regular file with mode `0600`, use HTTPS (loopback HTTP is accepted for local testing), and match this shape:

```json
{
  "schema": "automonique.mcp-servers/v1",
  "servers": [
    {
      "name": "business",
      "url": "https://manage.inklura.fr/api/v1/agent/mcp",
      "token": "replace-with-a-short-lived-agent-token",
      "headers": {}
    },
    {
      "name": "support",
      "url": "https://support.inklura.fr/api/mcp",
      "token": "replace-with-the-support-service-token",
      "headers": {
        "MCP-All-Tenants": "true",
        "MCP-Actor-Name": "Automonique"
      }
    },
    {
      "name": "designer",
      "url": "https://designer.inklura.fr/api/mcp",
      "token": "replace-with-the-designer-service-token",
      "headers": {
        "MCP-Tenant-ID": "replace-with-tenant-id",
        "MCP-Designer-Site": "replace-with-pinned-site-slug",
        "MCP-Actor-Name": "Automonique"
      }
    }
  ]
}
```

Never commit this file. Tokens are retained only in the daemon process and redacted from debug output. Support and Designer service tokens must be provisioned in their corresponding site environments. For Business MCP, prefer the existing short-lived OAuth agent token rather than a static token.

When a tool returns `input_required`, Telegram receives a context preview with Approve and Deny buttons. Approval replays the exact staged server, tool, arguments, and input-request keys once. Denial performs no call. A restart intentionally invalidates pending MCP buttons, so a stale approval fails closed.
