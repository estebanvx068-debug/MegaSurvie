const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const crypto = require("crypto");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const app = express();
const DATA_DIR = "./data";
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = `${DATA_DIR}/users.json`;
const SESSIONS_FILE = `${DATA_DIR}/sessions.json`;
const ONLINE_FILE = `${DATA_DIR}/online.json`;

app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));

function readJSON(path) {
  try { return JSON.parse(fs.readFileSync(path)); } catch (e) { return {}; }
}
function writeJSON(path, obj) {
  fs.writeFileSync(path, JSON.stringify(obj, null, 2));
}
function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}
function loadOrCreateFiles() {
  if (!fs.existsSync(USERS_FILE)) writeJSON(USERS_FILE, {});
  if (!fs.existsSync(SESSIONS_FILE)) writeJSON(SESSIONS_FILE, {});
  if (!fs.existsSync(ONLINE_FILE)) writeJSON(ONLINE_FILE, { online: [] });
}
loadOrCreateFiles();

app.post("/api/login", (req, res) => {
  const { username, secret } = req.body || {};
  if (!username || !secret) return res.status(400).json({ ok:false, msg:"username and secret required" });

  const users = readJSON(USERS_FILE);
  const expectedHash = users[username];
  if (!expectedHash) return res.status(403).json({ ok:false, msg:"Utilisateur inconnu" });
  if (sha256(secret) !== expectedHash) return res.status(403).json({ ok:false, msg:"Secret incorrect" });

  const sessions = readJSON(SESSIONS_FILE);
  const token = uuidv4();
  const expiresAt = Date.now() + 1000 * 60 * 60;
  sessions[token] = { username, expiresAt };
  writeJSON(SESSIONS_FILE, sessions);

  const online = readJSON(ONLINE_FILE);
  if (!online.online.includes(username)) online.online.push(username);
  writeJSON(ONLINE_FILE, online);

  return res.json({ ok:true, token, username, expiresAt });
});

app.post("/api/logout", (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, msg:"token required" });
  const sessions = readJSON(SESSIONS_FILE);
  if (!sessions[token]) return res.status(403).json({ ok:false, msg:"session invalide" });

  const username = sessions[token].username;
  delete sessions[token];
  writeJSON(SESSIONS_FILE, sessions);

  const online = readJSON(ONLINE_FILE);
  online.online = online.online.filter(u => u !== username);
  writeJSON(ONLINE_FILE, online);

  return res.json({ ok:true });
});

app.get("/api/status", (req, res) => {
  const online = readJSON(ONLINE_FILE);
  return res.json({ ok:true, online: online.online || [] });
});

function cleanupSessions() {
  const sessions = readJSON(SESSIONS_FILE);
  const online = readJSON(ONLINE_FILE);
  const now = Date.now();
  let changed = false;
  for (const t of Object.keys(sessions)) {
    if (sessions[t].expiresAt < now) {
      const uname = sessions[t].username;
      delete sessions[t];
      online.online = (online.online || []).filter(u => u !== uname);
      changed = true;
    }
  }
  if (changed) {
    writeJSON(SESSIONS_FILE, sessions);
    writeJSON(ONLINE_FILE, online);
  }
}
setInterval(cleanupSessions, 60000);

app.get("/admin/users", (req,res) => {
  const users = readJSON(USERS_FILE);
  return res.json({ ok:true, users });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
