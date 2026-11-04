# Connect agents

Claude Code, Codex, Cursor and Claude Desktop start a browser login when an MCP server answers `401`. Mandat issues tokens by **token exchange**, so these clients connect through **`mandat bridge`** instead.

The bridge is a local stdio MCP server. It:
- authenticates as a registered agent;
- exchanges the user's identity for 5-minute task tokens, and renews them before they expire;
- forwards every call to the protected server.

## 1. Register the agent

```bash
mandat agents add claude-code --tools "lookup_*,refund,read_inbox,send_email" --resources https://mcp.example.com/mcp
# → prints a client_secret once; this is MANDAT_AGENT_SECRET below
```

Lost the secret? Run `mandat agents rotate-secret claude-code --revoke-tokens`.

## 2. Add it to your client

The examples pin an exact version. Use the version you have reviewed: an unpinned `npx -y` runs whatever is published next, and `mandat scan-config` flags that.

`--user user:maria` uses the test login (dev IdP), which is fine for trying things out. For real people, sign in once with `mandat login` and use `--login` instead; see [Identity](identity.md).

**Claude Code**

```bash
claude mcp add acme -e MANDAT_AGENT_SECRET=<secret> -- \
  npx -y mandat@0.1.5 bridge --url https://mcp.example.com/mcp --mandat http://127.0.0.1:7400 --agent claude-code --login
```

On Windows, start the command with `cmd /c`: `… -- cmd /c npx -y mandat@0.1.5 bridge …`. If `mandat` is installed globally, `… -- cmd /c mandat bridge …` works too.

**`.mcp.json`** (Claude Code project config, Claude Desktop, Cursor). On Windows, use `"command": "cmd"` and put `"/c", "npx"` at the start of `args`.

```json
{ "mcpServers": { "acme": { "command": "npx",
  "args": ["-y", "mandat@0.1.5", "bridge", "--url", "https://mcp.example.com/mcp", "--mandat", "http://127.0.0.1:7400",
           "--agent", "claude-code", "--login"],
  "env": { "MANDAT_AGENT_SECRET": "<secret>" } } } }
```

**Codex** (`~/.codex/config.toml`; on Windows, use `command = "cmd"` and `args = ["/c", "npx", "-y", …]`)

```toml
[mcp_servers.acme]
command = "npx"
args = ["-y", "mandat@0.1.5", "bridge", "--url", "https://mcp.example.com/mcp", "--mandat", "http://127.0.0.1:7400",
        "--agent", "codex", "--login"]
env = { MANDAT_AGENT_SECRET = "<secret>" }

# Codex has its own approval gate for MCP tools that aren't read-only. Pass these tools through
# so that Mandat's policy decides (allow / deny / human approval):
[mcp_servers.acme.tools.refund]
approval_mode = "approve"
[mcp_servers.acme.tools.send_email]
approval_mode = "approve"
```

## Notes

- **Approvals.** A call that needs approval waits while a human approves in the console, in Slack, or with `mandat approvals approve <id>`. If nobody answers in time, the agent gets "approval required… retry the same call once it is approved", and the identical call then goes through once.
- **Narrower sessions.** Add `--tools a,b` to give a session less than everything the agent is registered for.
- **A raw IdP token instead of `mandat login`.** Put it in `MANDAT_SUBJECT_TOKEN`.
- **System proxies.** On Windows, a system proxy can intercept local requests from Python MCP clients. Set `NO_PROXY=127.0.0.1,localhost`.
- **Tested with** Claude Code 2.1.302 and codex-cli 0.166.0.
