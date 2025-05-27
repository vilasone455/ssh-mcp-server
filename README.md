# SSH MCP Server

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

---

## Features

* MCP-compliant server exposing SSH capabilities
* Execute shell commands on remote Linux and Windows systems
* Secure authentication via password or SSH key
* Read-only mode with built-in security checks
* Built with TypeScript and the official MCP SDK

### Available Tools

| Tool                        | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| `get_available_connections` | Lists machines available to connect via SSH              |
| `create_connection`         | Opens a new SSH session and tracks it by `connection_id` |
| `get_connections`           | Lists all active SSH sessions                            |
| `execute_command`           | Runs a shell command (unrestricted)                      |
| `secure_execute_command`    | Safer command execution; blocks destructive actions      |
| `close_connection`          | Closes an active SSH session                             |

---

## Quick Start

### 1. Clone the repository

```bash
$ git clone https://github.com/vilasone455/ssh-mcp-server.git
```

### 2. Create machine config

Create a `machines.json` file with the following structure:

```json
[
   {
    "machine_id": "todo-server-01",
    "label": "Todo server",
    "os": "ubuntu",
    "source": "digitalocean",
    "ssh": {
      "host": "192.168.1.11",
      "port": 22,
      "username": "user",
      "password": "your_password_here"
    }
  },
  {
    "machine_id": "build-agent-01",
    "label": "CI Build Agent (Key Auth)",
    "os": "ubuntu",
    "source": "aws",
    "ssh": {
      "host": "192.168.1.12",
      "port": 22,
      "username": "ubuntu",
      "keyPath": "/home/ubuntu/.ssh/id_rsa"
    }
  }

]
```

---

## Client Setup (Claude Desktop Example)

To integrate this MCP server into Claude Desktop, add both the server command and the required environment variable:

```jsonc
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "node",
      "args": [
        "/path/to/ssh-mcp-server/dist/index.js"
      ],
      "env": {
        "MACHINES_PATH": "/path/to/your/machines.json"
      }
    }
  }
}
```

Now you can interact with your server using natural language, e.g., "Run `uptime` on Todo VM."

---

## Disclaimer

Use at your own risk. This server grants shell-level access via MCP. Review commands carefully and run in a secure environment.

---

## Contributing

Star the repo, open issues, and submit pull requests! Feedback is welcome.

---
