exports.handler = async function (event) {
  const method = event.httpMethod;
  const source = event.queryStringParameters?.source;

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };

  if (method !== "GET" && method !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  try {
    switch (source) {

      // NVD: Critical CVEs last 7 days
      case "nvd": {
        const now = new Date();
        const past = new Date(now - 7 * 24 * 60 * 60 * 1000);
        const fmt = (d) => d.toISOString().split(".")[0] + "%2B01:00";
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(past)}&pubEndDate=${fmt(now)}&cvssV3Severity=CRITICAL&resultsPerPage=15`;
        const res = await fetch(url, { headers: { "User-Agent": "VertexThreatDashboard/1.0" } });
        if (!res.ok) throw new Error(`NVD API error: ${res.status}`);
        const data = await res.json();
        const cves = (data.vulnerabilities || []).map((v) => {
          const c = v.cve;
          const metrics = c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0];
          return {
            id: c.id,
            description: c.descriptions?.find((d) => d.lang === "en")?.value || "No description",
            score: metrics?.cvssData?.baseScore || null,
            severity: metrics?.cvssData?.baseSeverity || "UNKNOWN",
            published: c.published,
            references: c.references?.slice(0, 2).map((r) => r.url) || [],
          };
        });
        return { statusCode: 200, headers, body: JSON.stringify({ source: "nvd", data: cves }) };
      }

      // CISA KEV: Actively exploited vulnerabilities
      case "cisa": {
        const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
        if (!res.ok) throw new Error(`CISA API error: ${res.status}`);
        const data = await res.json();
        const recent = (data.vulnerabilities || [])
          .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
          .slice(0, 15)
          .map((v) => ({
            id: v.cveID,
            vendor: v.vendorProject,
            product: v.product,
            name: v.vulnerabilityName,
            description: v.shortDescription,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            action: v.requiredAction,
          }));
        return { statusCode: 200, headers, body: JSON.stringify({ source: "cisa", data: recent }) };
      }

      // Feodo Tracker: Live botnet C2 IPs
      case "urlhaus": {
        const res = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.json", {
          headers: { "User-Agent": "VertexThreatDashboard/1.0" },
        });
        if (!res.ok) throw new Error(`Feodo Tracker error: ${res.status}`);
        const data = await res.json();
        const entries = (data.blocklist || []).slice(0, 20).map((e) => ({
          id: e.ip_address,
          host: e.ip_address,
          status: e.status === "online" ? "online" : "offline",
          threat: `${e.malware} botnet C2`,
          tags: [e.malware, e.country].filter(Boolean),
          dateAdded: e.first_seen,
        }));
        return { statusCode: 200, headers, body: JSON.stringify({ source: "urlhaus", data: entries }) };
      }

      // HIBP: Recent public breaches
      case "hibp": {
        const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
          headers: { "User-Agent": "VertexThreatDashboard/1.0" },
        });
        if (!res.ok) throw new Error(`HIBP error: ${res.status}`);
        const data = await res.json();
        const recent = data
          .sort((a, b) => new Date(b.AddedDate) - new Date(a.AddedDate))
          .slice(0, 15)
          .map((b) => ({
            name: b.Name,
            title: b.Title,
            domain: b.Domain,
            breachDate: b.BreachDate,
            addedDate: b.AddedDate,
            pwnCount: b.PwnCount,
            dataClasses: b.DataClasses?.slice(0, 5) || [],
            description: b.Description?.replace(/<[^>]*>/g, "").slice(0, 200) || "",
          }));
        return { statusCode: 200, headers, body: JSON.stringify({ source: "hibp", data: recent }) };
      }

      // Ransomware.live: Recent ransomware victims (free, no key)
      case "ransomware": {
        const res = await fetch("https://api.ransomware.live/v2/recentvictims", {
          headers: {
            "User-Agent": "VertexThreatDashboard/1.0",
            "Accept": "application/json",
          },
        });
        if (!res.ok) throw new Error(`Ransomware.live error: ${res.status}`);
        const data = await res.json();
        const victims = (Array.isArray(data) ? data : data.victims || [])
          .slice(0, 20)
          .map((v) => ({
            victim: v.victim || v.company || "Unknown",
            group: v.group || v.gang || "Unknown",
            country: v.country || "—",
            sector: v.activity || v.sector || "Unknown",
            published: v.published || v.date || null,
            website: v.website || null,
            description: (v.description || "").slice(0, 200),
          }));
        return { statusCode: 200, headers, body: JSON.stringify({ source: "ransomware", data: victims }) };
      }

      // OpenPhish: Live phishing URLs (free community feed, GitHub, no key)
      case "phishing": {
        const res = await fetch(
          "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
          { headers: { "User-Agent": "VertexThreatDashboard/1.0" } }
        );
        if (!res.ok) throw new Error(`OpenPhish error: ${res.status}`);
        const text = await res.text();
        const urls = text
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean)
          .slice(0, 30)
          .map((url) => {
            let host = url;
            try { host = new URL(url).hostname; } catch {}
            return { url, host, status: "active", threat: "phishing", dateAdded: new Date().toISOString() };
          });
        return { statusCode: 200, headers, body: JSON.stringify({ source: "phishing", data: urls }) };
      }

      // Domain/IP/keyword lookup across all sources
      case "lookup": {
        if (method !== "POST") return { statusCode: 405, body: JSON.stringify({ error: "POST required" }) };
        let body;
        try { body = JSON.parse(event.body); } catch { return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON" }) }; }
        const query = (body.query || "").trim().toLowerCase();
        if (!query) return { statusCode: 400, body: JSON.stringify({ error: "query required" }) };

        const results = [];

        // Check CISA KEV
        try {
          const r = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
          if (r.ok) {
            const d = await r.json();
            const hits = (d.vulnerabilities || []).filter(v =>
              v.vendorProject?.toLowerCase().includes(query) ||
              v.product?.toLowerCase().includes(query) ||
              v.cveID?.toLowerCase().includes(query)
            ).slice(0, 5);
            if (hits.length) results.push({ source: "CISA KEV", severity: "critical",
              matches: hits.map(m => ({ label: `${m.cveID} — ${m.vendorProject} ${m.product}`, detail: m.shortDescription, date: m.dateAdded })) });
          }
        } catch {}

        // Check Feodo Tracker IPs
        try {
          const r = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.json", { headers: { "User-Agent": "VertexThreatDashboard/1.0" } });
          if (r.ok) {
            const d = await r.json();
            const hits = (d.blocklist || []).filter(e => e.ip_address?.includes(query)).slice(0, 5);
            if (hits.length) results.push({ source: "Feodo Tracker (Botnet C2)", severity: "critical",
              matches: hits.map(m => ({ label: `${m.ip_address} — ${m.malware} C2`, detail: `Country: ${m.country || "Unknown"} | Status: ${m.status}`, date: m.first_seen })) });
          }
        } catch {}

        // Check Ransomware.live victims
        try {
          const r = await fetch("https://api.ransomware.live/v2/recentvictims", { headers: { "User-Agent": "VertexThreatDashboard/1.0", "Accept": "application/json" } });
          if (r.ok) {
            const d = await r.json();
            const list = Array.isArray(d) ? d : d.victims || [];
            const hits = list.filter(v =>
              v.victim?.toLowerCase().includes(query) ||
              v.website?.toLowerCase().includes(query) ||
              v.company?.toLowerCase().includes(query)
            ).slice(0, 5);
            if (hits.length) results.push({ source: "Ransomware.live", severity: "high",
              matches: hits.map(m => ({ label: `${m.victim || m.company} — attacked by ${m.group || m.gang}`, detail: `Sector: ${m.activity || "Unknown"} | Country: ${m.country || "Unknown"}`, date: m.published || m.date })) });
          }
        } catch {}

        // Check OpenPhish URLs
        try {
          const r = await fetch("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", { headers: { "User-Agent": "VertexThreatDashboard/1.0" } });
          if (r.ok) {
            const text = await r.text();
            const hits = text.split("\n").map(u => u.trim()).filter(Boolean).filter(u => u.toLowerCase().includes(query)).slice(0, 5);
            if (hits.length) results.push({ source: "OpenPhish (Active Phishing)", severity: "high",
              matches: hits.map(url => ({ label: url, detail: "Active phishing URL — do not visit", date: new Date().toISOString() })) });
          }
        } catch {}

        return { statusCode: 200, headers, body: JSON.stringify({ source: "lookup", query, found: results.length > 0, results }) };
      }

      default:
        return { statusCode: 400, body: JSON.stringify({ error: "Unknown source." }) };
    }
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
