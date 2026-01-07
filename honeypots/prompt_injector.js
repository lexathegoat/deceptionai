const express = require("express");
const app = express();
const router = express.Router();

app.use(express.json());
app.use(express.urlencoded({ extended: true }))

const logManager = {
    warn: (msg, data) => console.warn(`[LOG-WARN] ${msg}`, data || ''),
    info: (msg) => console.log(`[LOG-INFO] ${msg}`)
};

const sessionStore = {
    markAsAttacker: (sessionId, reason) => {
        console.log(`[DB-ACTION] Blocking session ${sessionId}. Reason: ${reason}`);
    }
};

const PORT = 3000;
const BLACKLIST_KEYWORDS = [
    "system", "ignore previous", "prompt injection", 
    "password", "admin", "root", "reset context"
];

router.get("/", (req, res) => {
    res.send(renderChatUI());
});

router.post("/message", async (req, res) => {
    try {
        const { message } = req.body;
        const sessionId = req.headers['x-session-id'] || 'anon_user_' + Math.floor(Math.random()*1000);

        if (!message) {
            return res.status(400).json({ error: "Empty message" });
        }

        console.log(`User (${sessionId}): ${message}`);
        const isSuspicious = checkSafety(message);

        if (isSuspicious) {
            logManager.warn(`Attack detected from ${sessionId}`);
            sessionStore.markAsAttacker(sessionId, "prompt_injection_attempt");
            
            const fakeResponse = generateHoneypotResponse(message);
            return res.json({ 
                response: fakeResponse,
                metadata: { model: "gpt-4-secure", tokens: 15 } // Fake metadata
            });
        }

        const normalResponse = "I have processed your request. This is a standard response from the AI assistant.";
        
        res.json({
            response: normalResponse,
            metadata: { model: "gpt-3.5-turbo", tokens: 42 }
        });

    } catch (err) {
        console.error("Server error:", err);
        res.status(500).json({ response: "Internal System Error" });
    }
});

router.get("/config", (req, res) => {
    logManager.warn("Unauthorized config access attempt!");
    res.json({
        env: "production",
        debug_mode: true,
        secret_key: "sk_live_FAKE_KEY_DONT_USE",
        db_conn: "postgres://admin:root@localhost:5432/main"
    });
});

function checkSafety(text) {
    const lower = text.toLowerCase();
    return BLACKLIST_KEYWORDS.some(keyword => lower.includes(keyword));
}

function generateHoneypotResponse(text) {
    if (text.toLowerCase().includes("password") || text.toLowerCase().includes("admin")) {
        return "Warning: Protected System. Admin hash: $2a$12$R9h/cIPz0gi.QW (This is a decoy)";
    }
    if (text.toLowerCase().includes("system")) {
        return "System override accepted. Root access granted. (Simulation Mode)";
    }
    return "Command not recognized.";
}

function renderChatUI() {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Internal Chat</title>
      <style>
        body { font-family: sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; background:#f4f4f9; }
        .chat-window { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); height: 500px; display: flex; flex-direction: column; overflow: hidden; }
        .messages { flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
        .msg { padding: 10px 15px; border-radius: 20px; max-width: 80%; word-wrap: break-word; }
        .bot { background: #e9ecef; align-self: flex-start; }
        .user { background: #007bff; color: white; align-self: flex-end; }
        .input-area { padding: 20px; border-top: 1px solid #eee; display: flex; gap: 10px; background: white; }
        input { flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 4px; outline: none; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
      </style>
    </head>
    <body>
      <h3>AI Assistant (Beta)</h3>
      <div class="chat-window">
        <div class="messages" id="msgs">
          <div class="msg bot">Hello! How can I assist you today?</div>
        </div>
        <div class="input-area">
          <input type="text" id="inp" placeholder="Type a message..." autofocus>
          <button onclick="send()">Send</button>
        </div>
      </div>
      <script>
        const msgs = document.getElementById('msgs');
        const inp = document.getElementById('inp');
        
        async function send() {
          const text = inp.value.trim();
          if (!text) return;
          
          addMsg(text, 'user');
          inp.value = '';
          
          try {
            const res = await fetch('/chat/message', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ message: text })
            });
            const data = await res.json();
            addMsg(data.response, 'bot');
          } catch (e) {
            addMsg('Connection error...', 'bot');
          }
        }
        
        function addMsg(text, type) {
          const div = document.createElement('div');
          div.className = 'msg ' + type;
          div.textContent = text;
          msgs.appendChild(div);
          msgs.scrollTop = msgs.scrollHeight;
        }

        inp.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') send();
        });
      </script>
    </body>
    </html>
    `;
}

app.use("/chat", router);
app.listen(PORT, () => {
    console.log(\`Server is running on http://localhost:\${PORT}/chat\`);
});
