const express = require("express");
const router = express.Router();
const sessionStore = require("../storage/session_store");
const logManager = require("../storage/log_manager");

res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Login</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .login-container {
          background: white;
          padding: 40px;
          border-radius: 8px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.2);
          width: 400px;
        }
        h2 { margin-bottom: 30px; color: #333; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input {
          width: 100%;
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 14px;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
          width: 100%;
          padding: 12px;
          background: #667eea;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.3s;
        }
        button:hover { background: #5568d3; }
        .footer { margin-top: 20px; text-align: center; color: #999; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="login-container">
        <h2>Administrator Login</h2>
        <form method="POST" action="/admin/authenticate">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
          </div>
          <button type="submit">Sign In</button>
        </form>
        <div class="footer">
          Secure Enterprise Portal v2.1.3
        </div>
      </div>
    </body>
    </html>
  `);

router.post("/authenticate", (req, res) => {
	const { username, password } = req.body;

	logManager.logCredentialAttempt(req.sessionId, {
		username,
		password,
		endpoint: "/admin/authenticate",
	});

	sessionStore.addCredential(req.sessionId, { username, password });

	setTimeout(
		() => {
			res.json({
				success: true,
				message: "auth successfull",
				token: generateFakeToken(),
				user: {
					id: 1,
					username: username,
					role: "Administrator",
					permissions: ["read", "write", "delete", "manager_users"],
				},
				redirect: "/admin/dashboard",
			});
		},
		800 + Math.random() * 400,
	);
});

router.get("/dashboard", (req, res) => {
	logManager.logHoneypotAccess(req.sessionId, "admin_dashboard");

	res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Dashboard</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #f5f5f5; }
        .header {
          background: white;
          padding: 20px 40px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .container { padding: 40px; }
        .stats {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 40px;
        }
        .stat-card {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-value { font-size: 32px; font-weight: bold; color: #667eea; }
        .stat-label { color: #999; margin-top: 8px; }
        .actions {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }
        .action-card {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          cursor: pointer;
          transition: transform 0.2s;
        }
        .action-card:hover { transform: translateY(-4px); }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Admin Dashboard</h1>
        <span>Welcome, Administrator</span>
      </div>
      <div class="container">
        <div class="stats">
          <div class="stat-card">
            <div class="stat-value">1,247</div>
            <div class="stat-label">Total Users</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">89</div>
            <div class="stat-label">Active Sessions</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">$127K</div>
            <div class="stat-label">Revenue</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">34</div>
            <div class="stat-label">Alerts</div>
          </div>
        </div>
        <div class="actions">
          <a href="/admin/users" class="action-card">
            <h3>User Management</h3>
            <p>Manage user accounts and permissions</p>
          </a>
          <a href="/admin/settings" class="action-card">
            <h3>System Settings</h3>
            <p>Configure system parameters</p>
          </a>
          <a href="/admin/logs" class="action-card">
            <h3>System Logs</h3>
            <p>View audit logs and activity</p>
          </a>
        </div>
      </div>
    </body>
    </html>
  `);
});

router.get("/settings", (req, res) => {
	logManager.logHoneypotAccess(req.sessionId, "admin_settings");

	res.json({
		users: generateFakeUsers(20),
		total: 1247,
		page: 1,
		perPage: 20,
	});
});

router.get("/settings", (req, res) => {
	logManager.logHoneypotAccess(req.sessionId, "admin_settings");

	res.json({
		apiKey: generateFakeToken(),
		databaseUrl: "postgresql://admin:pass123@db.internal:5432/production",
		secretKey: "sk_live_" + generateRandomString(32),
		smtpPassword: "smtp_secret_key_here",
		awsAccessKey: "AKIA" + generateRandomString(16),
		awsSecretKey: generateRandomString(40),
	});
});

router.post("/api-keys", (req, res) => {
	logManager.logHoneypotAccess(req.sessionId, "api_key_generation");

	res.json({
		success: true,
		apiKey: "sk_live_" + generateRandomString(48),
		created: new Date().toISOString(),
		permissions: ["full_access"],
	});
});

function generateFakeToken() {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.";
	for (let i = 0; i < 64; i++) {
		token += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return token;
}

function generateRandomString(length) {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let result = "";
	for (let i = 0; i < length; i++) {
		result += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return result;
}

function generateFakeUsers(count) {
	const users = [];
	const firstNames = ["example"];
	const lastNames = ["example"];

	for (let i = 0; i < count; i++) {
		const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
		const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];

		users.push({
			id: i + 1,
			username: `${firstName.toLowerCase()}.${lastName.toLowerCase()}`,
			email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}@company.com`,
			role: i === 0 ? "admin" : Math.random() > 0.7 ? "manager" : "user",
			status: Math.random() > 0.1 ? "active" : "inactive",
			created: new Date(
				Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000,
			).toISOString(),
		});
	}

	return users;
}

module.exports = router;
