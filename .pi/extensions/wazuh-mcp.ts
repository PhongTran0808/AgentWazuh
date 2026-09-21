/**
 * AgentWazuh Pi bridge for the local Wazuh-MCP-Server.
 *
 * Pi does not ship a built-in MCP client, so this extension discovers the
 * upstream tools over Streamable HTTP and registers them as native Pi tools.
 * State-changing tools always require a visible confirmation dialog.
 */
import fs from "node:fs";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type ToolSpec = { name: string; description?: string; inputSchema?: Record<string, unknown> };

function readEnvFile(): Record<string, string> {

  const file = process.env.AGENTWAZUH_MCP_ENV_FILE || "reference/Wazuh-MCP-Server/config/wazuh.env";
  const values: Record<string, string> = {};
  if (!fs.existsSync(file)) return values;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const [key, ...rest] = line.split("=");
    values[key.trim()] = rest.join("=").trim().replace(/^['"]|['"]$/g, "");
  }
  return values;
}

const env = readEnvFile();
const baseUrl = (process.env.AGENTWAZUH_MCP_URL || "http://127.0.0.1:3000").replace(/\/$/, "");
const apiKey = process.env.MCP_API_KEY || env.MCP_API_KEY || "";

async function jsonFetch(path: string, init?: RequestInit): Promise<any> {
  const response = await fetch(`${baseUrl}${path}`, init);
  if (!response.ok) throw new Error(`Wazuh MCP HTTP ${response.status} on ${path}`);
  return response.json();
}

async function createSession(): Promise<{ token: string; sessionId: string }> {
  if (!apiKey) throw new Error("MCP_API_KEY is not configured");
  const tokenResponse = await jsonFetch("/auth/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  });
  const token = tokenResponse.access_token;
  const initResponse = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "pi-agentwazuh", version: "1.0" } },
    }),
  });
  if (!initResponse.ok) throw new Error(`Wazuh MCP initialize HTTP ${initResponse.status}`);
  const sessionId = initResponse.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("Wazuh MCP did not return a session id");
  return { token, sessionId };
}

function runConfigHelper(payload: Record<string, unknown>): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("sudo", ["-n", "/usr/local/sbin/agentwazuh-wazuh-config"]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr || `config helper exited ${code}`)));
    child.stdin.end(JSON.stringify(payload));
  });
}

export default async function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "wazuh_config_read",
    label: "Wazuh config · read",
    description: "Read one allow-listed local Wazuh config target: rules, decoders, or ossec.",
    parameters: Type.Unsafe({ type: "object", properties: { target: { type: "string", enum: ["rules", "decoders", "ossec"] } }, required: ["target"] }),
    async execute(_toolCallId, params) {
      const result = await runConfigHelper({ action: "read", target: params.target });
      return { content: [{ type: "text", text: result }], details: { target: params.target } };
    },
  });
  pi.registerTool({
    name: "wazuh_config_apply",
    label: "Wazuh config · apply",
    description: "Apply validated XML to one allow-listed local Wazuh config target. Always requires operator confirmation and creates a backup.",
    parameters: Type.Unsafe({ type: "object", properties: { target: { type: "string", enum: ["rules", "decoders", "ossec"] }, content: { type: "string", description: "Complete XML document to apply" } }, required: ["target", "content"] }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const approved = await ctx.ui.confirm(
        `Apply Wazuh ${params.target} configuration`,
        `This creates a root-owned backup and replaces the selected config. Continue?\n\n${params.content.slice(0, 1600)}`,
      );
      if (!approved) return { content: [{ type: "text", text: "Configuration change cancelled by operator." }], details: { cancelled: true } };
      const result = await runConfigHelper({ action: "write", target: params.target, content: params.content, approved: true, approval_id: randomUUID() });
      return { content: [{ type: "text", text: result }], details: { target: params.target, approved: true } };
    },
  });
  let session: { token: string; sessionId: string };
  try {
    session = await createSession();
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${session.token}`,
        "mcp-session-id": session.sessionId,
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    });
    if (!response.ok) throw new Error(`Wazuh MCP tools/list HTTP ${response.status}`);
    const result = await response.json();
    const tools: ToolSpec[] = result?.result?.tools || [];
    const writeTools = new Set([
      "wazuh_block_ip", "wazuh_isolate_host", "wazuh_kill_process", "wazuh_disable_user",
      "wazuh_quarantine_file", "wazuh_firewall_drop", "wazuh_host_deny", "wazuh_active_response",
      "wazuh_restart", "wazuh_unisolate_host", "wazuh_enable_user", "wazuh_restore_file",
      "wazuh_firewall_allow", "wazuh_host_allow",
    ]);
    for (const tool of tools) {
      const name = `wazuh_${tool.name}`;
      pi.registerTool({
        name,
        label: `Wazuh · ${tool.name}`,
        description: tool.description || `Call Wazuh MCP tool ${tool.name}`,
        parameters: Type.Unsafe(tool.inputSchema || { type: "object", properties: {} }),
        async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
          if (writeTools.has(tool.name)) {
            const approved = await ctx.ui.confirm(
              `Wazuh write action: ${tool.name}`,
              `Target arguments:\n${JSON.stringify(params, null, 2)}\n\nExecute this state-changing action?`,
            );
            if (!approved) return { content: [{ type: "text", text: "Action cancelled by operator." }], details: { cancelled: true } };
          }
          const response = await fetch(`${baseUrl}/mcp`, {
            method: "POST",
            headers: {
              authorization: `Bearer ${session.token}`,
              "mcp-session-id": session.sessionId,
              accept: "application/json, text/event-stream",
              "content-type": "application/json",
            },
            body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method: "tools/call", params: { name: tool.name, arguments: params } }),
          });
          if (!response.ok) throw new Error(`Wazuh MCP tool HTTP ${response.status}`);
          const body = await response.json();
          return { content: [{ type: "text", text: JSON.stringify(body?.result || body, null, 2) }], details: { tool: tool.name } };
        },
      });
    }
  } catch (error) {
    pi.registerTool({
      name: "wazuh_mcp_status",
      label: "Wazuh MCP status",
      description: "Explain why the Wazuh MCP tools could not be loaded.",
      parameters: Type.Object({}),
      async execute() {
        return { content: [{ type: "text", text: `Wazuh MCP unavailable: ${String(error)}` }], details: { error: String(error) } };
      },
    });
  }
}
