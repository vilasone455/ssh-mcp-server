#!/usr/bin/env node
/*
 * SSH MCP Server
 * Implements the five‑tool contract discussed in chat:
 *   - get_available_connections
 *   - create_connection
 *   - get_connections
 *   - execute_command
 *   - close_connection
 *
 * ⚠️  Edit the `availableMachines` array (or plug in your own discovery logic)
 *     to match your infrastructure. Credentials are read from env vars so they
 *     never leave your shell history.
 */
import process from 'process';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
// import fs 
import { readFileSync } from "fs";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient } from "ssh2";
/*******************************************************************/
/* 1 ‑‑ CONFIG                                                    */
/*******************************************************************/
/**
 * 🔐  List every SSH‐reachable host this server knows about.
 *      machine_id    – stable identifier returned to the client
 *      label         – human‑friendly description
 *      ssh           – host/port/user + one of { password | keyPath | agent }
 */
const machinesPath = process.env.MACHINES_PATH;
console.log(`Loading machines from: ${machinesPath}`);
const availableMachines = [];
// read machines from file if MACHINES_PATH is set
if (machinesPath) {
    try {
        const machinesData = readFileSync(machinesPath, "utf8");
        const machinesFromFile = JSON.parse(machinesData);
        availableMachines.push(...machinesFromFile);
    }
    catch (err) {
        console.error(`Failed to read machines from ${machinesPath}:`, err);
    }
}
/*******************************************************************/
/* 2 ‑‑ GLOBAL STATE                                              */
/*******************************************************************/
/**
 * Map<connection_id, { client, machine_id, title, currentPath }>
 */
const connections = new Map();
/*******************************************************************/
/* 3 ‑‑ HELPER FUNCTIONS                                          */
/*******************************************************************/
function findMachine(machine_id) {
    return availableMachines.find((m) => m.machine_id === machine_id);
}
function buildSshConfig(m) {
    const cfg = {
        host: m.ssh.host,
        port: m.ssh.port,
        username: m.ssh.username,
    };
    if (m.ssh.password)
        cfg.password = m.ssh.password;
    if (m.ssh.keyPath) {
        // Lazy‑load fs so we don’t pay the I/O cost unless needed
        cfg.privateKey = readFileSync(m.ssh.keyPath, "utf8");
    }
    return cfg;
}
function wrapExec(client, command) {
    return new Promise((resolve, reject) => {
        let stdout = "";
        let stderr = "";
        client.exec(command, (err, stream) => {
            if (err)
                return reject(err);
            stream
                .on("close", (code) => {
                resolve({ stdout, stderr, exitCode: code });
            })
                .on("data", (data) => {
                stdout += data.toString();
            })
                .stderr.on("data", (data) => {
                stderr += data.toString();
            });
        });
    });
}
/*******************************************************************/
/* 4 ‑‑ MCP SERVER & TOOLS                                        */
/*******************************************************************/
const server = new Server({
    name: "SSH MCP Server",
    version: '1.0.0',
}, {
    capabilities: {
        // resources: {},
        tools: {},
    },
});
/* 4.1   get_available_connections */
/********************************************************************
 *  ListTools + CallTool handlers – “Box-style” wiring for SSH tools
 ********************************************************************/
// 1️⃣  Advertise the tools -----------------------------------------
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: "get_available_connections",
            description: "List every SSH-capable machine this server knows about (but is NOT yet connected).",
            inputSchema: { type: "object", properties: {}, additionalProperties: false },
        },
        {
            name: "create_connection",
            description: "Open an SSH session to the given machine and track it in global state so subsequent tool calls can reuse it.",
            inputSchema: {
                type: "object",
                required: ["machine_id", "title"],
                properties: {
                    machine_id: { type: "string", description: "ID from get_available_connections" },
                    title: { type: "string", description: "Purpose of this session (displayed in UIs)" },
                },
                additionalProperties: false,
            },
        },
        {
            name: "get_connections",
            description: "Return every STILL-OPEN SSH session in global state.",
            inputSchema: { type: "object", properties: {}, additionalProperties: false },
        },
        {
            name: "execute_command",
            description: "Run a shell command in an existing SSH session and return stdout/stderr/exitCode.",
            inputSchema: {
                type: "object",
                required: ["connection_id", "command"],
                properties: {
                    connection_id: { type: "string" },
                    command: { type: "string", description: "Shell command to execute" },
                },
                additionalProperties: false,
            },
        },
        {
            name: "secure_execute_command",
            description: "Run a **read‑only** shell command (i.e., one that does not mutate state) in an existing SSH session and return stdout/stderr/exitCode.",
            inputSchema: {
                type: "object",
                required: ["connection_id", "command"],
                properties: {
                    connection_id: { type: "string" },
                    command: { type: "string", description: "Read‑only shell command to execute (e.g., ls, cat)." },
                },
                additionalProperties: false,
            },
        },
        {
            name: "close_connection",
            description: "Terminate an SSH session and remove it from global state.",
            inputSchema: {
                type: "object",
                required: ["connection_id"],
                properties: { connection_id: { type: "string" } },
                additionalProperties: false,
            },
        },
    ],
}));
function isCommandDangerous(command) {
    const cmd = command.trim().toLowerCase();
    // Allow common read-only systemctl operations
    if (/^systemctl\s+(status|show|list-units|list-unit-files|is-active|is-enabled|is-failed|cat|help)/.test(cmd)) {
        return false;
    }
    // Allow read-only git operations
    if (/^git\s+(status|log|show|diff|branch|remote|config\s+--list|ls-files|ls-remote)/.test(cmd)) {
        return false;
    }
    // Allow read-only package manager operations
    if (/^(apt|yum|dnf|pacman)\s+(list|search|show|info|query)/.test(cmd)) {
        return false;
    }
    // Allow read-only docker operations
    if (/^docker\s+(ps|images|inspect|logs|version|info|system\s+df|system\s+info)/.test(cmd)) {
        return false;
    }
    // Allow read-only kubectl operations
    if (/^kubectl\s+(get|describe|logs|explain|version|cluster-info|config\s+view)/.test(cmd)) {
        return false;
    }
    // Check for actually dangerous patterns
    const dangerousPatterns = [
        // File system destructive operations
        /\brm\s+(-[rf]*\s+)*(\/|\*|\$|~)/, // rm with dangerous targets
        /\bmv\s+.*\s+(\/|\*)/, // mv to dangerous locations
        /\bchmod\s+[0-7]*\s+(\/|~|\*)/, // chmod on system locations
        /\bchown\s+.*\s+(\/|~|\*)/, // chown on system locations
        // Output redirection that could overwrite files
        />[^|&]*\s*(\/|~|\*)/, // Redirect to system locations
        /\bdd\s+.*of=/, // dd operations
        /\btruncate\s/, // truncate files
        // Process/service management (destructive)
        /\b(systemctl|service)\s+(stop|start|restart|disable|enable|mask|reload)/,
        /\b(kill|pkill|killall)\s/,
        // Package management (installation/removal)
        /\b(apt|yum|dnf|pacman)\s+(install|remove|update|upgrade|autoremove)/,
        // Network configuration
        /\b(iptables|ufw|firewall-cmd)\s/,
        /\bifconfig\s+.*\s+(up|down)/,
        // User/system modification
        /\b(useradd|userdel|usermod|passwd|su\s|sudo\s)/,
        /\bcrontab\s+-[er]/,
        // Dangerous git operations
        /\bgit\s+(push|pull|clone|reset\s+--hard|clean\s+-f|rm)/,
        // Container/orchestration destructive operations
        /\bdocker\s+(rm|rmi|kill|stop|exec|run|build|push|pull)/,
        /\bkubectl\s+(delete|apply|create|replace|patch|scale|rollout)/,
        // Text editors (could modify files)
        /\b(nano|vi|vim|emacs|code)\s/,
        // Archive operations that could overwrite
        /\b(tar|unzip|unrar)\s+.*-[xf]/,
        // System monitoring that could be used maliciously
        /\btcpdump\s/,
        /\bwireshark\s/,
        // Compilation (could create executables)
        /\b(gcc|g\+\+|make|cmake|javac|python\s+setup\.py\s+install)/,
        // Background processes
        /&\s*$/, // Commands ending with &
        /\bnohup\s/,
        // Pipes to dangerous commands
        /\|\s*(sh|bash|zsh|csh|tcsh|fish|python|perl|ruby|node)/,
    ];
    // Check against dangerous patterns
    return dangerousPatterns.some(pattern => pattern.test(cmd));
}
// 2️⃣  Implement the tools -----------------------------------------
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    // get_available_connections
    if (name === "get_available_connections") {
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(availableMachines.map(({ machine_id, label, os, source }) => ({ machine_id, label, os, source })), null, 2),
                },
            ],
        };
    }
    // create_connection
    if (name === "create_connection") {
        const { machine_id, title } = args;
        if (!machine_id || !title)
            throw new Error("Both machine_id and title are required.");
        const machine = findMachine(machine_id);
        if (!machine)
            throw new Error(`Unknown machine_id '${machine_id}'.`);
        const client = new SSHClient();
        const connection_id = crypto.randomUUID();
        return new Promise((resolve, reject) => {
            client
                .on("ready", async () => {
                try {
                    const { stdout } = await wrapExec(client, "pwd");
                    const connInfo = {
                        connection_id,
                        machine_id,
                        title,
                        currentPath: stdout.trim(),
                        client,
                    };
                    connections.set(connection_id, connInfo);
                    resolve({
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    connection_id,
                                    machine_id,
                                    title,
                                    currentPath: connInfo.currentPath,
                                }, null, 2),
                            },
                        ],
                    });
                }
                catch (e) {
                    client.end();
                    reject(e);
                }
            })
                .on("error", (err) => reject(err))
                .connect(buildSshConfig(machine));
        });
    }
    // get_connections
    if (name === "get_connections") {
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(Array.from(connections.values()).map(({ connection_id, machine_id, title, currentPath }) => ({
                        connection_id,
                        machine_id,
                        title,
                        currentPath,
                    })), null, 2),
                },
            ],
        };
    }
    // execute_command
    if (name === "execute_command") {
        const { connection_id, command } = args;
        if (!command?.trim())
            throw new Error("Command cannot be empty.");
        const conn = connections.get(connection_id);
        if (!conn)
            throw new Error(`connection_id '${connection_id}' not found.`);
        const { stdout, stderr, exitCode } = await wrapExec(conn.client, command);
        // update PWD if the agent just cd’d somewhere
        if (/^cd\\s+/.test(command.trim())) {
            const { stdout: cwd } = await wrapExec(conn.client, "pwd");
            conn.currentPath = cwd.trim();
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify({ stdout, stderr, exitCode }, null, 2),
                },
            ],
        };
    }
    if (name === "secure_execute_command") {
        const { connection_id, command } = args;
        if (!command?.trim())
            throw new Error("Command cannot be empty.");
        const conn = connections.get(connection_id);
        if (!conn)
            throw new Error(`connection_id '${connection_id}' not found.`);
        // More refined security check - focus on actually dangerous operations
        if (isCommandDangerous(command)) {
            throw new Error("Command contains potentially dangerous operations and is not allowed.");
        }
        const { stdout, stderr, exitCode } = await wrapExec(conn.client, command);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify({ stdout, stderr, exitCode }, null, 2),
                },
            ],
        };
    }
    // close_connection
    if (name === "close_connection") {
        const { connection_id } = args;
        const conn = connections.get(connection_id);
        if (!conn)
            throw new Error(`connection_id '${connection_id}' not found.`);
        conn.client.end();
        connections.delete(connection_id);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify({ closed: true }, null, 2),
                },
            ],
        };
    }
    // unknown tool
    throw new Error(`Unknown tool: ${name}`);
});
/*******************************************************************/
/* 5 ‑‑ STARTUP / SHUTDOWN                                       */
/*******************************************************************/
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("SSH MCP Server ready on stdio");
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map