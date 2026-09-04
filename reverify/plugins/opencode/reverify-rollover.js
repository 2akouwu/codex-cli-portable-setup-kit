// reverify rollover for OpenCode: hand off to files and open a fresh session instead of compacting.
//
// Installed by `reverify rollover install --harness opencode` into ~/.config/opencode/plugins/.
// The state machine lives in reverify (Python); this plugin only feeds it what OpenCode knows
// (tokens of the last assistant message, the user's verbatim first / latest messages) on every
// `session.idle`, and executes the answer through the SDK:
//   {"action":"prompt","text":...}     ask the model (in the same session) to write the hand-off
//   {"action":"rollover","opening":..} open a fresh session whose first message is the opening
//   {"action":"none"}                  nothing to do
// Subagent (child) sessions are never touched. Everything fails open.

const COMMAND = __REVERIFY_COMMAND__; // [python, rollover_harness.py] - filled in at install time

async function callGuard(payload) {
  try {
    const proc = Bun.spawn([...COMMAND, "hook", "opencode", "idle"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
      env: { ...process.env },
    });
    proc.stdin.write(JSON.stringify(payload));
    proc.stdin.end();
    const out = await new Response(proc.stdout).text();
    await proc.exited;
    const line = out.trim().split("\n").pop() || "{}";
    return JSON.parse(line);
  } catch (_err) {
    return { action: "none" };
  }
}

function collect(messages) {
  let tokens = null;
  let first = null;
  let last = null;
  for (const entry of messages || []) {
    const info = entry.info || entry;
    const parts = entry.parts || [];
    if (info.role === "assistant" && info.tokens) {
      const t = info.tokens;
      tokens = typeof t.total === "number" && t.total > 0
        ? t.total
        : (t.input || 0) + (t.output || 0) + ((t.cache && t.cache.read) || 0);
    } else if (info.role === "user") {
      const text = parts.filter((p) => p.type === "text" && typeof p.text === "string").map((p) => p.text).join("\n").trim();
      if (text && !text.startsWith("<")) {
        if (first === null) first = text;
        last = text;
      }
    }
  }
  return { tokens, first, last };
}

export const ReverifyRollover = async ({ client, directory }) => {
  const asked = new Set();          // sessions we already asked for a hand-off (stop_hook_active)
  const busy = new Set();
  let openingForNewSession = null;  // set while we wait for the TUI to create the successor

  async function sendOpening(sessionID, opening) {
    await client.session.prompt({ path: { id: sessionID }, body: { parts: [{ type: "text", text: opening }] } });
  }

  async function rollover(fromSessionID, opening) {
    openingForNewSession = opening;
    let switched = false;
    try {
      await client.tui.executeCommand({ body: { command: "session_new" } });
      switched = true;
    } catch (_err) {
      switched = false;
    }
    if (!switched) {
      // headless (opencode run / serve): create the successor ourselves
      const created = await client.session.create({ body: { title: "rollover continuation" } });
      const id = created && created.data && created.data.id;
      openingForNewSession = null;
      if (id) await sendOpening(id, opening);
    }
  }

  return {
    event: async ({ event }) => {
      try {
        if (event.type === "session.created" && openingForNewSession) {
          const info = event.properties && (event.properties.info || event.properties.session);
          const id = info && info.id;
          if (id && !info.parentID) {
            const opening = openingForNewSession;
            openingForNewSession = null;
            await sendOpening(id, opening);
          }
          return;
        }
        if (event.type !== "session.idle") return;
        const sessionID = event.properties && event.properties.sessionID;
        if (!sessionID || busy.has(sessionID)) return;
        busy.add(sessionID);
        try {
          const got = await client.session.get({ path: { id: sessionID } });
          const session = got && got.data;
          if (!session || session.parentID) return;
          const listed = await client.session.messages({ path: { id: sessionID } });
          const { tokens, first, last } = collect(listed && listed.data);
          const result = await callGuard({
            session_id: sessionID,
            cwd: session.directory || directory,
            tokens,
            first_user_message: first,
            last_user_message: last,
            stop_hook_active: asked.has(sessionID),
          });
          if (result.action === "prompt" && result.text) {
            asked.add(sessionID);
            await client.session.prompt({ path: { id: sessionID }, body: { parts: [{ type: "text", text: result.text }] } });
          } else if (result.action === "rollover" && result.opening) {
            asked.delete(sessionID);
            await rollover(sessionID, result.opening);
          } else {
            asked.delete(sessionID);
          }
        } finally {
          busy.delete(sessionID);
        }
      } catch (_err) {
        // fail open: never break the session
      }
    },
  };
};

export default ReverifyRollover;
