# MCP Atlassian

![PyPI Version](https://img.shields.io/pypi/v/mcp-atlassian)
![PyPI - Downloads](https://img.shields.io/pypi/dm/mcp-atlassian)
![PePy - Total Downloads](https://static.pepy.tech/personalized-badge/mcp-atlassian?period=total&units=international_system&left_color=grey&right_color=blue&left_text=Total%20Downloads)
[![Run Tests](https://github.com/sooperset/mcp-atlassian/actions/workflows/tests.yml/badge.svg)](https://github.com/sooperset/mcp-atlassian/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/sooperset/mcp-atlassian)
[![Docs](https://img.shields.io/badge/docs-mintlify-blue)](https://personal-1d37018d.mintlify.app)

Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Supports both Cloud and Server/Data Center deployments.

https://github.com/user-attachments/assets/35303504-14c6-4ae4-913b-7c25ea511c3e

<details>
<summary>Confluence Demo</summary>

https://github.com/user-attachments/assets/7fe9c488-ad0c-4876-9b54-120b666bb785

</details>

## Quick Start

### 1. Get Your API Token

Go to https://id.atlassian.com/manage-profile/security/api-tokens and create a token.

> For Server/Data Center, use a Personal Access Token instead. See [Authentication](https://personal-1d37018d.mintlify.app/docs/authentication).

### 2. Configure Your IDE

Add to your Claude Desktop or Cursor MCP configuration:

```json
{
  "mcpServers": {
    "mcp-atlassian": {
      "command": "uvx",
      "args": ["mcp-atlassian"],
      "env": {
        "JIRA_URL": "https://your-company.atlassian.net",
        "JIRA_USERNAME": "your.email@company.com",
        "JIRA_API_TOKEN": "your_api_token",
        "CONFLUENCE_URL": "https://your-company.atlassian.net/wiki",
        "CONFLUENCE_USERNAME": "your.email@company.com",
        "CONFLUENCE_API_TOKEN": "your_api_token"
      }
    }
  }
}
```

> **Python 3.14 not yet supported.** Use `["--python=3.12", "mcp-atlassian"]` as args if needed.

> **Server/Data Center users**: Use `JIRA_PERSONAL_TOKEN` instead of `JIRA_USERNAME` + `JIRA_API_TOKEN`. See [Authentication](https://personal-1d37018d.mintlify.app/docs/authentication) for details.

### 3. Start Using

Ask your AI assistant to:
- **"Find issues assigned to me in PROJ project"**
- **"Search Confluence for onboarding docs"**
- **"Create a bug ticket for the login issue"**
- **"Update the status of PROJ-123 to Done"**

## Per-Request Credentials (Multi-User)

The server supports **per-request** Jira and Confluence credentials so you don’t have to keep any
tokens on the server.  
Send the following HTTP headers with each request:

| Header | Example | Description |
|--------|---------|-------------|
| `X-Jira-Authorization` | `Bearer <OAuthAccessToken>` &#124; `Token <PAT>` | Jira OAuth 2.0 bearer token **or** Personal Access Token |
| `X-Confluence-Authorization` | `Bearer <OAuthAccessToken>` &#124; `Token <PAT>` | Confluence OAuth 2.0 bearer token **or** Personal Access Token |
| `X-Jira-Cloud-Id` | `d9a871b3-proj-1234` | (Optional) Cloud ID for the Jira site |
| `X-Confluence-Cloud-Id` | `6f5c0c42-wiki-7890` | (Optional) Cloud ID for the Confluence site |

Backward-compatibility:

* If the product-specific auth headers are **omitted**, the legacy `Authorization` header is
  used for both Jira and Confluence.
* If the product-specific cloud-ID headers are **omitted**, the legacy
  `X-Atlassian-Cloud-Id` header is used.

### Example `curl`

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "X-Jira-Authorization: Bearer $JIRA_OAUTH_ACCESS_TOKEN" \
  -H "X-Confluence-Authorization: Token $CONFLUENCE_PAT" \
  -d '{"tool":"jira_search","arguments":{"jql":"assignee = currentUser()"}}'
```

## Documentation

Full documentation is available at **[personal-1d37018d.mintlify.app](https://personal-1d37018d.mintlify.app)**.

Documentation is also available in [llms.txt format](https://llmstxt.org/), which LLMs can consume easily:
- [`llms.txt`](https://personal-1d37018d.mintlify.app/llms.txt) — documentation sitemap
- [`llms-full.txt`](https://personal-1d37018d.mintlify.app/llms-full.txt) — complete documentation

| Topic | Description |
|-------|-------------|
| [Installation](https://personal-1d37018d.mintlify.app/docs/installation) | uvx, Docker, pip, from source |
| [Authentication](https://personal-1d37018d.mintlify.app/docs/authentication) | API tokens, PAT, OAuth 2.0 |
| [Configuration](https://personal-1d37018d.mintlify.app/docs/configuration) | IDE setup, environment variables |
| [HTTP Transport](https://personal-1d37018d.mintlify.app/docs/http-transport) | SSE, streamable-http, multi-user |
| [Central Server](./CENTRAL_SERVER.md) | Run centrally with per-request credentials |
| [Single-Service Examples](./CENTRAL_SERVER.md#7-single-service-docker-examples) | Jira-only and Confluence-only Docker recipes |
| [Tools Reference](https://personal-1d37018d.mintlify.app/docs/tools-reference) | All Jira & Confluence tools |
| [Troubleshooting](https://personal-1d37018d.mintlify.app/docs/troubleshooting) | Common issues & debugging |

## Compatibility

| Product | Deployment | Support |
|---------|------------|---------|
| Confluence | Cloud | Fully supported |
| Confluence | Server/Data Center | Supported (v6.0+) |
| Jira | Cloud | Fully supported |
| Jira | Server/Data Center | Supported (v8.14+) |

## Key Tools

| Jira | Confluence |
|------|------------|
| `jira_search` - Search with JQL | `confluence_search` - Search with CQL |
| `jira_get_issue` - Get issue details | `confluence_get_page` - Get page content |
| `jira_create_issue` - Create issues | `confluence_create_page` - Create pages |
| `jira_update_issue` - Update issues | `confluence_update_page` - Update pages |
| `jira_transition_issue` - Change status | `confluence_add_comment` - Add comments |

See [Tools Reference](https://personal-1d37018d.mintlify.app/docs/tools-reference) for the complete list.

## Security

Never share API tokens. Keep `.env` files secure. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

MIT - See [LICENSE](LICENSE). Not an official Atlassian product.
