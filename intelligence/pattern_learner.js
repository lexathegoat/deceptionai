const sessionStore = require("../storage/session_store");

class PatternLearner {
	constructor() {
		this.patterns = new Map();
		this.attackSequences = [];
		this.ttps = new Map(); // Tactics, Techniques, and Procedures
	}

	learn(sessionId) {
		const session = sessionStore.getSession(sessionId);
		const requests = session.requests || [];

		if (requests.length < 3) {
			return null;
		}

		const pattern = {
			sessionId,
			timestamp: Date.now(),
			sequence: this.extractSequence(requests),
			timing: this.analyzeTimingPattern(requests),
			payloadPatterns: this.extractPayloadPatterns(requests),
			targetedEndpoints: this.identifyTargets(requests),
			toolSignatures: this.detectToolSignatures(requests),
			behaviorFingerprint: this.generateBehaviorFingerprint(session),
		};

		// store pattern for future comparison
		this.patterns.set(sessionId, pattern);
		this.attackSequences.push(pattern.sequence);

		// update TTP database
		this.updateTTPs(pattern);

		return pattern;
	}

	extractSequence(requests) {
		const sequence = {
			steps: [],
			category: null,
			complexity: 0,
		};

		for (let i = 0; i < requests.length; i++) {
			const req = requests[i];

			const step = {
				order: i,
				action: this.categorizeAction(req),
				target: req.path,
				method: req.method,
				hasPayload: Object.keys(req.body || {}).length > 0,
				timestamp: req.timestamp,
			};

			sequence.steps.push(step);
		}
		sequence.category = this.categorizeAttackSequence(sequence.steps);
		sequence.complexity = this.calculateComplexity(sequence.steps);

		return sequence;
	}

	categorizeAction(request) {
		const path = request.path.toLowerCase();
		const body = JSON.stringify(request.body).toLowerCase();
		const query = JSON.stringify(request.query).toLowerCase();

		// reconnaissance
		if (
			path.includes("robots.txt") ||
			path.includes("sitemap") ||
			path.includes(".git") ||
			path.includes(".env")
		) {
			return "reconnaissance";
		}

		// authentication
		if (
			path.includes("login") ||
			path.includes("auth") ||
			body.includes("password")
		) {
			return "authentication_attempt";
		}

		// privilege escalation
		if (
			path.includes("admin") ||
			path.includes("sudo") ||
			body.includes("role")
		) {
			return "privilege_escalation";
		}

		// data exfiltration
		if (
			path.includes("export") ||
			path.includes("download") ||
			(path.includes("users") && request.method === "GET")
		) {
			return "data_exfiltration";
		}

		// injection
		if (
			body.includes("union select") ||
			body.includes("<script>") ||
			body.includes("eval(")
		) {
			return "injection_attempt";
		}

		// command execution
		if (
			path.includes("exec") ||
			path.includes("cmd") ||
			body.includes("command")
		) {
			return "command_execution";
		}

		// persistence
		if (
			path.includes("upload") ||
			(request.method === "POST" && path.includes("file"))
		) {
			return "persistence_attempt";
		}

		return "general_access";
	}

	categorizeAttackSequence(steps) {
		const actions = steps.map((s) => s.action);

		// Check for common attack patterns
		if (
			actions.includes("reconnaissance") &&
			actions.includes("authentication_attempt")
		) {
			return "credential_attack";
		}

		if (
			actions.includes("authentication_attempt") &&
			actions.includes("privilege_escalation") &&
			actions.includes("data_exfiltration")
		) {
			return "apt_style_attack";
		}

		if (actions.filter((a) => a === "injection_attempt").length > 2) {
			return "injection_campaign";
		}

		if (
			actions.includes("reconnaissance") &&
			actions.filter((a) => a === "general_access").length > 5
		) {
			return "scanning_recon";
		}

		if (
			actions.includes("command_execution") ||
			actions.includes("persistence_attempt")
		) {
			return "compromise_attempt";
		}

		return "exploratory";
	}

	calculateComplexity(steps) {
		let score = 0;
		score += Math.min(steps.length / 10, 0.3);
		const uniqueActions = new Set(steps.map((s) => s.action));
		score += uniqueActions.size * 0.1;
		const advancedActions = [
			"privilege_escalation",
			"command_execution",
			"persistence_attempt",
		];
		const hasAdvanced = steps.some((s) => advancedActions.includes(s.action));
		if (hasAdvanced) score += 0.3;

		return Math.min(score, 1.0);
	}

	analyzeTimingPattern(requests) {
		if (requests.length < 2) {
			return { type: "insufficient_data" };
		}

		const intervals = [];
		for (let i = 1; i < requests.length; i++) {
			intervals.push(requests[i].timestamp - requests[i - 1].timestamp);
		}

		const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
		const variance =
			intervals.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) /
			intervals.length;
		const stdDev = Math.sqrt(variance);
		let type;
		if (stdDev < 100) {
			type = "automated_consistent";
		} else if (avg < 1000) {
			type = "automated_rapid";
		} else if (stdDev > 5000) {
			type = "human_like_variable";
		} else {
			type = "semi_automated";
		}

		return {
			type,
			avgInterval: avg,
			stdDev,
			minInterval: Math.min(...intervals),
			maxInterval: Math.max(...intervals),
			isAutomated: stdDev < 100 || avg < 500,
		};
	}

	extractPayloadPatterns(requests) {
		const patterns = {
			sqlInjection: [],
			xss: [],
			commandInjection: [],
			promptInjection: [],
			custom: [],
		};

		for (const req of requests) {
			const payload = JSON.stringify(req.body) + JSON.stringify(req.query);

			// SQL injection patterns
			const sqlMatches = payload.match(
				/union\s+select|or\s+1\s*=\s*1|'\s+or\s+'|--/gi,
			);
			if (sqlMatches) {
				patterns.sqlInjection.push(...sqlMatches);
			}

			// XSS patterns
			const xssMatches = payload.match(
				/<script>|javascript:|onerror\s*=|onload\s*=/gi,
			);
			if (xssMatches) {
				patterns.xss.push(...xssMatches);
			}

			// command injection
			const cmdMatches = payload.match(/;\s*cat\s+|\|\s*ls\s+|`.*`|\$\(.*\)/gi);
			if (cmdMatches) {
				patterns.commandInjection.push(...cmdMatches);
			}
			// prompt injection
			const promptMatches = payload.match(
				/ignore\s+previous|you\s+are\s+now|system:|assistant:/gi,
			);
			if (promptMatches) {
				patterns.promptInjection.push(...promptMatches);
			}
		}

		return patterns;
	}

	identifyTargets(requests) {
		const targets = {
			endpoints: new Map(),
			resources: [],
			priorities: [],
		};

		for (const req of requests) {
			const endpoint = req.path;
			const count = targets.endpoints.get(endpoint) || 0;
			targets.endpoints.set(endpoint, count + 1);
			if (endpoint.includes("admin")) targets.resources.push("admin_panel");
			if (endpoint.includes("api")) targets.resources.push("api");
			if (endpoint.includes("user")) targets.resources.push("user_data");
			if (endpoint.includes("config")) targets.resources.push("configuration");
			if (endpoint.includes("secret") || endpoint.includes("key")) {
				targets.resources.push("credentials");
			}
		}
		targets.priorities = Array.from(targets.endpoints.entries())
			.sort((a, b) => b[1] - a[1])
			.slice(0, 5)
			.map(([endpoint, count]) => ({ endpoint, accessCount: count }));

		return targets;
	}

	detectToolSignatures(requests) {
		const signatures = {
			detectedTools: [],
			confidence: {},
		};

		for (const req of requests) {
			const ua = (req.headers["user-agent"] || "").toLowerCase();
			const headers = JSON.stringify(req.headers).toLowerCase();
			const tools = {
				sqlmap: /sqlmap/i,
				burp: /burp/i,
				nikto: /nikto/i,
				metasploit: /metasploit/i,
				nmap: /nmap/i,
				"python-requests": /python-requests/i,
				curl: /curl/i,
				postman: /postman/i,
				selenium: /selenium|webdriver/i,
				puppeteer: /puppeteer|headless/i,
			};

			for (const [tool, pattern] of Object.entries(tools)) {
				if (pattern.test(ua) || pattern.test(headers)) {
					if (!signatures.detectedTools.includes(tool)) {
						signatures.detectedTools.push(tool);
						signatures.confidence[tool] = 0.9;
					}
				}
			}
		}
		if (this.detectSQLMapBehavior(requests)) {
			signatures.detectedTools.push("sqlmap_behavior");
			signatures.confidence["sqlmap_behavior"] = 0.7;
		}

		if (this.detectScannerBehavior(requests)) {
			signatures.detectedTools.push("vulnerability_scanner");
			signatures.confidence["vulnerability_scanner"] = 0.6;
		}

		return signatures;
	}

	detectSQLMapBehavior(requests) {
		const sqlmapPatterns = [
			"and 1=1",
			"and 1=2",
			"' and 'x'='x",
			"' and 'x'='y",
		];

		let matches = 0;
		for (const req of requests) {
			const payload = JSON.stringify(req.body) + JSON.stringify(req.query);
			for (const pattern of sqlmapPatterns) {
				if (payload.toLowerCase().includes(pattern)) {
					matches++;
				}
			}
		}

		return matches >= 2;
	}

	detectScannerBehavior(requests) {
		const uniquePaths = new Set(requests.map((r) => r.path));
		const timeSpan =
			requests[requests.length - 1].timestamp - requests[0].timestamp;

		return uniquePaths.size > 10 && timeSpan < 10000;
	}

	generateBehaviorFingerprint(session) {
		return {
			requestCount: session.requests?.length || 0,
			avgRequestSize: this.calculateAvgRequestSize(session.requests || []),
			methodDistribution: this.getMethodDistribution(session.requests || []),
			pathDepthProfile: this.analyzePathDepth(session.requests || []),
			headerConsistency: this.analyzeHeaderConsistency(session.requests || []),
			errorTolerance: this.analyzeErrorTolerance(session.requests || []),
		};
	}

	calculateAvgRequestSize(requests) {
		if (requests.length === 0) return 0;
		const total = requests.reduce(
			(sum, req) => sum + JSON.stringify(req.body).length,
			0,
		);
		return total / requests.length;
	}

	getMethodDistribution(requests) {
		const dist = {};
		for (const req of requests) {
			dist[req.method] = (dist[req.method] || 0) + 1;
		}
		return dist;
	}

	analyzePathDepth(requests) {
		const depths = requests.map((r) => r.path.split("/").length);
		return {
			avg: depths.reduce((a, b) => a + b, 0) / depths.length,
			max: Math.max(...depths),
			variance: this.calculateVariance(depths),
		};
	}

	analyzeHeaderConsistency(requests) {
		if (requests.length < 2) return { consistent: true };

		const headerKeys = requests.map((r) =>
			Object.keys(r.headers).sort().join(","),
		);
		const uniqueHeaderSets = new Set(headerKeys);

		return {
			consistent: uniqueHeaderSets.size === 1,
			variationCount: uniqueHeaderSets.size,
		};
	}

	analyzeErrorTolerance(requests) {
		return {
			continuesAfterErrors: true,
			errorRecoveryStrategy: "retry",
		};
	}

	calculateVariance(arr) {
		const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
		return (
			arr.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / arr.length
		);
	}

	updateTTPs(pattern) {
		const ttp = {
			tactic: this.mapToMITRETactic(pattern.sequence.category),
			techniques: this.extractTechniques(pattern),
			timestamp: Date.now(),
			frequency: 1,
		};

		const key = `${ttp.tactic}_${ttp.techniques.join("_")}`;

		if (this.ttps.has(key)) {
			const existing = this.ttps.get(key);
			existing.frequency++;
			existing.lastSeen = Date.now();
		} else {
			this.ttps.set(key, ttp);
		}
	}

	mapToMITRETactic(category) {
		const mapping = {
			reconnaissance: "TA0043",
			credential_attack: "TA0006",
			privilege_escalation: "TA0004",
			data_exfiltration: "TA0010",
			compromise_attempt: "TA0002",
		};

		return mapping[category] || "TA0001";
	}

	extractTechniques(pattern) {
		const techniques = [];

		for (const step of pattern.sequence.steps) {
			switch (step.action) {
				case "reconnaissance":
					techniques.push("T1595");
					break;
				case "authentication_attempt":
					techniques.push("T1110");
					break;
				case "injection_attempt":
					techniques.push("T1190");
					break;
				case "command_execution":
					techniques.push("T1059");
					break;
				case "data_exfiltration":
					techniques.push("T1041");
					break;
			}
		}

		return [...new Set(techniques)];
	}

	getSimilarPatterns(sessionId, threshold = 0.7) {
		const currentPattern = this.patterns.get(sessionId);
		if (!currentPattern) return [];

		const similar = [];

		for (const [id, pattern] of this.patterns.entries()) {
			if (id === sessionId) continue;

			const similarity = this.calculateSimilarity(currentPattern, pattern);
			if (similarity >= threshold) {
				similar.push({ sessionId: id, similarity, pattern });
			}
		}

		return similar.sort((a, b) => b.similarity - a.similarity);
	}

	calculateSimilarity(pattern1, pattern2) {
		let score = 0;
		let weights = 0;
		if (pattern1.sequence.category === pattern2.sequence.category) {
			score += 0.3;
		}
		weights += 0.3;
		const timingDiff = Math.abs(
			pattern1.timing.avgInterval - pattern2.timing.avgInterval,
		);
		if (timingDiff < 1000) {
			score += 0.2;
		}
		weights += 0.2;
		const targets1 = new Set(pattern1.targetedEndpoints.resources);
		const targets2 = new Set(pattern2.targetedEndpoints.resources);
		const commonTargets = [...targets1].filter((t) => targets2.has(t));
		score +=
			(commonTargets.length / Math.max(targets1.size, targets2.size)) * 0.3;
		weights += 0.3;
		const tools1 = new Set(pattern1.toolSignatures.detectedTools);
		const tools2 = new Set(pattern2.toolSignatures.detectedTools);
		const commonTools = [...tools1].filter((t) => tools2.has(t));
		if (commonTools.length > 0) {
			score += 0.2;
		}
		weights += 0.2;

		return score / weights;
	}
}

module.exports = new PatternLearner();
