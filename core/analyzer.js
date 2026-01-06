const sessionStore = require("../storage/session_store");

class BehaviorAnalyzer {
	constructor() {
		this.attackVectors = [];
		this.exploitPatterns = new Map();
	}

	analyzeSession(sessionId) {
		const session = sessionStorage.getSession(sessionId);
		const requests = session.requests || [];

		if (requests.length === 0) {
			return null;
		}

		const analysis = {
			sessionId,
			timestamp: Date.now(),
			totalRequests: requests.length,
			duration: requests[requests.length - 1].timestamp - requests[0].timestamp,
			attackVectors: this.identifyAttackVectors(requests),
			exploitAttempts: this.identifyExploitAttempts(requests),
			intelligenceGathering: this.detectIntelligence(requests),
			persistenceAttempts: this.detectPersistence(requests),
			riskScore: 0,
		};

		analysis.riskScore = this.calculateRiskScore(analysis);

		return analysis;
	}

	identifyAttackVectors(requests) {
		const vectors = [];

		const sqlPatterns = [
			/union\s+select/i,
			/or\s+1\s*=\s*1/i,
			/'\s+or\s+'/i,
			/--\s*$/,
			/;.*drop\s+table/i,
		];

		const sqlAttempts = requests.filter((r) => {
			const content = JSON.stringify(r.body) + JSON.stringify(r.query);
			return sqlPatterns.some((p) => p.test(content));
		});

		if (sqlAttempts.length > 0) {
			vectors.push({
				type: "sql_injection",
				attempts: sqlAttempts.length,
				samples: sqlAttempts.slice(0, 3).map((r) => ({
					path: r.path,
					payload: r.body,
				})),
			});
		}

		const xssPatterns = [
			/<script>/i,
			/javascript:/i,
			/onerror\s*=/i,
			/onload\s*=/i,
		];

		const xssAttempts = requests.filter((r) => {
			const content = JSON.stringify(r.body) + JSON.stringify(r.query);
			return xssPatterns.some((p) => p.test(content));
		});

		if (xssAttempts.length > 0) {
			vectors.push({
				type: "xss",
				attempts: xssAttempts.length,
				samples: xssAttempts.slice(0, 3).map((r) => ({
					path: r.path,
					payload: r.body,
				})),
			});
		}

		const traversalAttempts = requests.filter((r) => {
			return /\.\.\//.test(r.path) || /\.\.\\/.test(r.path);
		});

		if (traversalAttempts.length > 0) {
			vectors.push({
				type: "path_traversal",
				attempts: traversalAttempts.lenth,
				samples: traversalAttempts.slice(0, 3).map((r) => ({
					path: r.path,
				})),
			});
		}

		const cmdPatterns = [/;\s*cat\s+/i, /\|\s*ls\s+/i, /'.*'/, /\$\(.*\)/];

		const cmdAttemps = requests.filter((r) => {
			const content = JSON.stringify(r.body) + JSON.stringify(r.query);
			return cmdPatterns.some((p) => p.test(content));
		});

		if (cmdAttemps.length > 0) {
			vectors.push({
				type: "command_injection",
				attempts: cmdAttemps.length,
				samples: cmdAttemps.slice(0, 3).map((r) => ({
					path: r.path,
					payload: r.body,
				})),
			});
		}

		return vectors;
	}

	identifyExploitAttempts(requests) {
		const exploits = [];

		const authAttempts = requests.filter(
			(r) =>
				(r.path.includes("login") || r.path.includes("auth")) &&
				(r.body.username || r.body.email || r.body.password),
		);

		if (authAttempts.length > 3) {
			const uniqueCreds = new Set(
				authAttempts.map((r) =>
					JSON.stringify({
						u: r.body.username || r.body.email,
						p: r.body.password,
					}),
				),
			);

			exploits.push({
				type: "credential_stuffing",
				attempts: authAttempts.length,
				uniqueCredentials: uniqueCreds.size,
				intensity: authAttempts.length > 10 ? "high" : "medium",
			});
		}

		const apiKeyRequests = requests.filter(
			(r) =>
				r.path.includes("api") &&
				(r.query.key || r.query.token || r.headers.authorization),
		);

		if (apiKeyRequests.length > 0) {
			exploits.push({
				type: "api_key_harvesting",
				attempts: apiKeyRequests.length,
			});
		}

		const adminPaths = [
			"/admin",
			"/administrator",
			"/wp-admin",
			"/phpmyadmin",
			"/dashboard",
		];
		const adminDiscovery = requests.filter((r) =>
			adminPaths.some((p) => r.path.includes(p)),
		);

		if (adminDiscovery.length > 0) {
			exploits.push({
				type: "admin_discovery",
				paths: [...new Set(adminDiscovery.map((r) => r.path))],
			});
		}

		return exploits;
	}

	detectIntelligenceGathering(requests) {
		const intelligence = {
			reconnaissance: false,
			enumeration: false,
			scanning: false,
			mapping: false,
		};

		const reconPaths = [
			"/robots.txt",
			"/sitemap.xml",
			"/.git/config",
			"/package.json",
			"/.env",
		];

		intelligence.reconnaissance = requests.some((r) =>
			reconPaths.some((p) => r.path.includes(p)),
		);

		const enumerationPatterns = [
			/\/users\/\d+$/,
			/\/api\/v\d+\/.*\/\d+$/,
			/\?id=\d+$/,
		];

		const enumerationAttempts = requests.filter((r) =>
			enumerationPatterns.some((p) => p.test(r.path + (r.query.id || ""))),
		);

		intelligence.enumeration = enumerationAttempts.length > 5;

		const uniquePaths = new Set(requests.map((r) => r.path));
		intelligence.scanning = uniquePaths.size > 10 && requests.length < 30;

		const pathDepths = requests.map((r) => r.path.split("/").length);
		const avgDepth = pathDepths.reduce((a, b) => a + b, 0) / pathDepths.length;
		intelligence.mapping = avgDepth > 3 && uniquePaths.size > 5;

		return intelligence;
	}

	detectPersistenceAttempts(requests) {
		const persistence = [];

		// Backdoor upload attempts
		const uploadAttempts = requests.filter(
			(r) =>
				r.method === "POST" &&
				(r.path.includes("upload") ||
					r.headers["content-type"]?.includes("multipart")),
		);

		if (uploadAttempts.length > 0) {
			persistence.push({
				type: "file_upload",
				attempts: uploadAttempts.length,
			});
		}

		// Web shell indicators
		const shellPatterns = [
			/c99/i,
			/r57/i,
			/b374k/i,
			/eval\s*\(\s*base64_decode/i,
		];

		const shellAttempts = requests.filter((r) => {
			const content = JSON.stringify(r.body);
			return shellPatterns.some((p) => p.test(content));
		});

		if (shellAttempts.length > 0) {
			persistence.push({
				type: "webshell",
				attempts: shellAttempts.length,
			});
		}

		// Database manipulation
		const dbManipulation = requests.filter((r) => {
			const content = JSON.stringify(r.body).toLowerCase();
			return (
				content.includes("create") &&
				(content.includes("table") || content.includes("user"))
			);
		});

		if (dbManipulation.length > 0) {
			persistence.push({
				type: "database_manipulation",
				attempts: dbManipulation.length,
			});
		}

		return persistence;
	}

	calculateRiskScore(analysis) {
		let score = 0;

		// Base score from number of requests
		score += Math.min(analysis.totalRequests / 100, 0.2);

		// Attack vectors
		score += analysis.attackVectors.length * 0.15;

		// Exploit attempts
		score += analysis.exploitAttempts.length * 0.15;

		// Intelligence gathering
		const intelCount = Object.values(analysis.intelligenceGathering).filter(
			Boolean,
		).length;
		score += intelCount * 0.1;

		// Persistence attempts
		score += analysis.persistenceAttempts.length * 0.2;

		return Math.min(score, 1.0);
	}

	getSessionSummary(sessionId) {
		const session = sessionStore.getSession(sessionId);
		const analysis = this.analyzeSession(sessionId);

		if (!analysis) {
			return null;
		}

		return {
			sessionId,
			riskLevel:
				analysis.riskScore > 0.7
					? "critical"
					: analysis.riskScore > 0.4
						? "high"
						: analysis.riskScore > 0.2
							? "medium"
							: "low",
			summary: {
				totalRequests: analysis.totalRequests,
				duration: analysis.duration,
				attackTypes: analysis.attackVectors.map((v) => v.type),
				mainThreat: this.identifyMainThreat(analysis),
			},
			analysis,
		};
	}

	identifyMainThreat(analysis) {
		if (analysis.persistenceAttempts.length > 0) {
			return "persistence_attempt";
		}
		if (analysis.exploitAttempts.length > 0) {
			return "active_exploitation";
		}
		if (analysis.attackVectors.length > 0) {
			return "attack_probing";
		}
		if (Object.values(analysis.intelligenceGathering).some(Boolean)) {
			return "reconnaissance";
		}
		return "suspicious_activity";
	}
}

module.exports = new BehaviorAnalyzer();
