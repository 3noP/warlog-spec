/**
 * stdio JSON-RPC proxy between an MCP client (Claude Desktop, Cursor, …)
 * and a backend MCP server (okta-mcp, falcon-mcp, …).
 *
 * The proxy is a transparent middleware : every message flows through
 * unchanged EXCEPT ``tools/call`` requests, which are intercepted to
 * emit a signed AuditRow on the local Warlog chain before being
 * forwarded to the backend.
 *
 * MCP wire format is newline-delimited JSON-RPC over stdio.
 */

import { ChildProcess, spawn } from "node:child_process";
import { createInterface } from "node:readline";

import type { Auditor } from "./auditor.js";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  error?: { code: number; message: string; data?: unknown };
  result?: unknown;
}

export interface ProxyOptions {
  /** Backend command + args, e.g. ``["uvx", "okta-mcp"]``. */
  backend: string[];
  /** Auditor instance ; receives intercepted tools/call requests. */
  auditor: Auditor;
  /** When true, refuse unmapped tools instead of forwarding them. */
  strict: boolean;
  /** Optional override for stdin / stdout / stderr (mainly for tests). */
  clientStdin?: NodeJS.ReadableStream;
  clientStdout?: NodeJS.WritableStream;
  clientStderr?: NodeJS.WritableStream;
}

/**
 * Run the proxy until either side closes its stream. Resolves with the
 * backend's exit code.
 */
export async function runProxy(opts: ProxyOptions): Promise<number> {
  const clientStdin = opts.clientStdin ?? process.stdin;
  const clientStdout = opts.clientStdout ?? process.stdout;
  const clientStderr = opts.clientStderr ?? process.stderr;

  if (opts.backend.length === 0) {
    throw new Error("Backend command is empty ; pass [cmd, ...args] in ProxyOptions.backend");
  }

  // Disable backend-side stdio buffering. Python MCP servers (and most
  // language runtimes) bufferize stdout when they detect they are not
  // attached to a TTY — which is exactly the case under this proxy.
  // The result is a deadlock : the backend holds a partial JSON-RPC
  // message in its internal buffer, our readline waits forever for a
  // newline, the MCP client (Claude Desktop, Cursor) freezes.
  //
  // PYTHONUNBUFFERED=1 covers the Python case (the most common MCP
  // backend implementation). Node backends respect process.stdout
  // line-buffering when piped already. Go backends typically buffer
  // on bufio.Writer — operators of Go MCP servers must add their own
  // flush after each message.
  const backendEnv: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
  };

  const child: ChildProcess = spawn(opts.backend[0]!, opts.backend.slice(1), {
    stdio: ["pipe", "pipe", "inherit"],
    env: backendEnv,
  });
  if (!child.stdin || !child.stdout) {
    throw new Error("Failed to spawn backend with piped stdio");
  }

  // Signal propagation : when the proxy receives SIGINT/SIGTERM (Ctrl-C
  // from the operator's console, MCP client process closing, parent
  // shutdown), kill the backend before we exit. Otherwise the backend
  // child is orphaned, holding file descriptors and possibly an active
  // vendor connection.
  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    clientStderr.write(`[warlog-mcp] received ${signal}, terminating backend\n`);
    try {
      child.kill(signal);
    } catch {
      // Backend already gone — fine.
    }
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // Surface backend stdout-pipe errors instead of silently dying.
  child.on("error", (err) => {
    clientStderr.write(`[warlog-mcp] backend spawn error : ${err.message}\n`);
  });
  // If the backend exits before the client closes stdin, surface the
  // exit code in stderr so the operator notices in their MCP client
  // logs. The client will see a closed pipe and report a transport
  // failure on its own.
  child.on("exit", (code, signal) => {
    if (code !== 0 && code !== null) {
      clientStderr.write(`[warlog-mcp] backend exited with code ${code}\n`);
    } else if (signal !== null) {
      clientStderr.write(`[warlog-mcp] backend killed by ${signal}\n`);
    }
  });

  // Client -> proxy -> backend
  const clientReader = createInterface({ input: clientStdin });
  clientReader.on("line", (line) => {
    handleClientMessage(line, child, clientStdout, opts.auditor, opts.strict, clientStderr);
  });
  // If the MCP client closes our stdin (typical when Claude Desktop
  // restarts a server connection), tear down the backend cleanly.
  clientReader.on("close", () => {
    if (!shuttingDown) {
      shuttingDown = true;
      try {
        child.kill("SIGTERM");
      } catch {
        // Best-effort.
      }
    }
  });

  // Backend -> proxy -> client (transparent forward).
  const backendReader = createInterface({ input: child.stdout });
  backendReader.on("line", (line) => {
    if (line.length === 0) return;
    clientStdout.write(line + "\n");
  });

  return new Promise<number>((resolve) => {
    child.on("close", (code) => {
      clientReader.close();
      backendReader.close();
      resolve(code ?? 0);
    });
  });
}

function handleClientMessage(
  line: string,
  child: ChildProcess,
  clientStdout: NodeJS.WritableStream,
  auditor: Auditor,
  strict: boolean,
  clientStderr: NodeJS.WritableStream,
): void {
  const trimmed = line.trim();
  if (!trimmed) return;

  let msg: JsonRpcRequest;
  try {
    msg = JSON.parse(trimmed) as JsonRpcRequest;
  } catch {
    // Forward malformed messages — the backend will surface the error.
    child.stdin?.write(line + "\n");
    return;
  }

  if (msg.method !== "tools/call") {
    // initialize, tools/list, notifications/*, anything-else : pass through.
    child.stdin?.write(line + "\n");
    return;
  }

  // Intercept the call : audit before forwarding.
  const params = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
  const toolName = params.name ?? "";
  const args = params.arguments ?? {};

  let decision;
  try {
    decision = auditor.audit(toolName, args, strict);
  } catch (err) {
    // Audit pipeline blew up — refuse the call rather than forward
    // unaudited. Operators must know audit is broken.
    clientStderr.write(`[warlog-mcp] audit pipeline failure for tool '${toolName}': ${err}\n`);
    sendError(clientStdout, msg.id, -32000, `Warlog audit failed: ${err}`);
    return;
  }

  if (decision.outcome === "refuse_unmapped") {
    sendError(clientStdout, msg.id, -32601, decision.reason ?? "tool not mapped");
    return;
  }
  if (decision.outcome === "approval_required") {
    sendError(clientStdout, msg.id, -32010, decision.reason ?? "approval required", {
      auditId: decision.auditId,
      requestId: decision.requestId,
    });
    return;
  }
  if (decision.outcome === "approval_denied") {
    sendError(clientStdout, msg.id, -32011, decision.reason ?? "approval denied", {
      auditId: decision.auditId,
    });
    return;
  }

  // Authorized — forward to backend.
  child.stdin?.write(line + "\n");
}

function sendError(
  out: NodeJS.WritableStream,
  id: number | string | null,
  code: number,
  message: string,
  data?: unknown,
): void {
  const response: JsonRpcResponse = {
    jsonrpc: "2.0",
    id,
    error: { code, message, data },
  };
  out.write(JSON.stringify(response) + "\n");
}

