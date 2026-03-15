export default async function handler(req, res) {
  const method = req.method;
  const source = req.query?.source;

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Content-Type", "application/json");

  if (method !== "GET" && method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  try {
    switch (source) {

      // NVD: Critical CVEs last 7 days
      case "nvd": {
        const now = new Date();
        const past = new Date(now - 7 * 24 * 60 * 60 * 1000);
        const fmt = (d) => d.toISOString().split(".")[0] + "%2B01:00";
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(past)}&pubEndDate=${fmt(now)}&cvssV3Severity=CRITICAL&resultsPerPage=15`;
        const r = await fetch(url, { headers: { "User-Agent": "VertexV2Dashboard/1.0" } });
        if (!r.ok) throw new Error(`NVD error: ${r.status}`);
        const data = await r.json();
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
        return res.status(200).json({ source: "nvd", data: cves });
      }

      // CISA KEV
      case "cisa": {
        const r = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
        if (!r.ok) throw new Error(`CISA error: ${r.status}`);
        const data = await r.json();
        const recent = (data.vulnerabilities || [])
          .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
          .slice(0, 15)
          .map((v) => ({
            id: v.cveID, vendor: v.vendorProject, product: v.product,
            name: v.vulnerabilityName, description: v.shortDescription,
            dateAdded: v.dateAdded, dueDate: v.dueDate, action: v.requiredAction,
          }));
        return res.status(200).json({ source: "cisa", data: recent });
      }

      // C2IntelFeeds: Live C2 IPs (GitHub, free, no key)
      case "urlhaus": {
        const r = await fetch(
          "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
          { headers: { "User-Agent": "VertexV2Dashboard/1.0" } }
        );
        if (!r.ok) throw new Error(`C2IntelFeeds error: ${r.status}`);
        const text = await r.text();
        const lines = text.split("\n").filter(l => l.trim() && !l.startsWith("#") && !l.startsWith("ip"));
        const entries = lines.slice(0, 25).map((line) => {
          const parts = line.split(",");
          const ip = (parts[0] || "").trim().replace(/"/g, "");
          const ioc = (parts[1] || "C2 server").trim().replace(/"/g, "");
          return { id: ip, host: ip, status: "online", threat: ioc || "Command & Control server", tags: ["C2", "malware"], dateAdded: new Date().toISOString() };
        }).filter(e => e.host);
        return res.status(200).json({ source: "urlhaus", data: entries });
      }

      // HIBP: Recent breaches
      case "hibp": {
        const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
          headers: { "User-Agent": "VertexV2Dashboard/1.0" },
        });
        if (!r.ok) throw new Error(`HIBP error: ${r.status}`);
        const data = await r.json();
        const recent = data
          .sort((a, b) => new Date(b.AddedDate) - new Date(a.AddedDate))
          .slice(0, 15)
          .map((b) => ({
            name: b.Name, title: b.Title, domain: b.Domain,
            breachDate: b.BreachDate, addedDate: b.AddedDate,
            pwnCount: b.PwnCount, dataClasses: b.DataClasses?.slice(0, 5) || [],
            description: b.Description?.replace(/<[^>]*>/g, "").slice(0, 200) || "",
          }));
        return res.status(200).json({ source: "hibp", data: recent });
      }

      // Ransomware.live
      case "ransomware": {
        const r = await fetch("https://api.ransomware.live/v2/recentvictims", {
          headers: { "User-Agent": "VertexV2Dashboard/1.0", "Accept": "application/json" },
        });
        if (!r.ok) throw new Error(`Ransomware.live error: ${r.status}`);
        const data = await r.json();
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
        return res.status(200).json({ source: "ransomware", data: victims });
      }

      // OpenPhish
      case "phishing": {
        const r = await fetch(
          "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
          { headers: { "User-Agent": "VertexV2Dashboard/1.0" } }
        );
        if (!r.ok) throw new Error(`OpenPhish error: ${r.status}`);
        const text = await r.text();
        const urls = text.split("\n").map(u => u.trim()).filter(Boolean).slice(0, 30).map((url) => {
          let host = url;
          try { host = new URL(url).hostname; } catch {}
          return { url, host, status: "active", threat: "phishing", dateAdded: new Date().toISOString() };
        });
        return res.status(200).json({ source: "phishing", data: urls });
      }

      // Business Tools CVE Monitor
      case "biztools": {
        const TOOLS = [
          { name: "Microsoft 365",    keyword: "microsoft 365",  category: "Productivity", icon: "🪟", url: "https://microsoft.com/microsoft-365" },
          { name: "WordPress",        keyword: "wordpress",      category: "Website",      icon: "🌐", url: "https://wordpress.org" },
          { name: "QuickBooks",       keyword: "quickbooks",     category: "Accounting",   icon: "💰", url: "https://quickbooks.intuit.com" },
          { name: "Slack",            keyword: "slack",          category: "Comms",        icon: "💬", url: "https://slack.com" },
          { name: "Zoom",             keyword: "zoom",           category: "Video",        icon: "📹", url: "https://zoom.us" },
          { name: "Google Workspace", keyword: "google chrome",  category: "Productivity", icon: "🔵", url: "https://workspace.google.com" },
          { name: "Shopify",          keyword: "shopify",        category: "E-commerce",   icon: "🛍", url: "https://shopify.com" },
          { name: "HubSpot",          keyword: "hubspot",        category: "CRM",          icon: "🧡", url: "https://hubspot.com" },
          { name: "Dropbox",          keyword: "dropbox",        category: "Storage",      icon: "📦", url: "https://dropbox.com" },
          { name: "Adobe Acrobat",    keyword: "adobe acrobat",  category: "Documents",    icon: "📄", url: "https://adobe.com/acrobat" },
          { name: "Mailchimp",        keyword: "mailchimp",      category: "Marketing",    icon: "📧", url: "https://mailchimp.com" },
          { name: "Xero",             keyword: "xero",           category: "Accounting",   icon: "📊", url: "https://xero.com" },
        ];

        const now = new Date();
        const past90 = new Date(now - 90 * 24 * 60 * 60 * 1000);
        const fmt = (d) => d.toISOString().split(".")[0] + "%2B01:00";

        let cisaVulns = [];
        try {
          const cr = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
          if (cr.ok) { const cd = await cr.json(); cisaVulns = cd.vulnerabilities || []; }
        } catch {}

        const results = [];
        for (const tool of TOOLS) {
          try {
            await new Promise(r => setTimeout(r, 200));
            const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(tool.keyword)}&pubStartDate=${fmt(past90)}&pubEndDate=${fmt(now)}&resultsPerPage=5`;
            const r = await fetch(url, { headers: { "User-Agent": "VertexV2Dashboard/1.0" } });
            if (!r.ok) { results.push({ ...tool, cves: [], status: "unknown", error: `NVD ${r.status}` }); continue; }
            const data = await r.json();
            const cves = (data.vulnerabilities || []).map((v) => {
              const c = v.cve;
              const metrics = c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0];
              const score = metrics?.cvssData?.baseScore || null;
              const severity = metrics?.cvssData?.baseSeverity || "UNKNOWN";
              return {
                id: c.id,
                description: c.descriptions?.find((d) => d.lang === "en")?.value?.slice(0, 220) || "No description",
                score, severity, published: c.published,
                activelyExploited: cisaVulns.some(kv => kv.cveID === c.id),
                reference: c.references?.[0]?.url || null,
              };
            });
            const topScore = cves.reduce((max, c) => (c.score || 0) > max ? (c.score || 0) : max, 0);
            const status = topScore >= 9 ? "critical" : topScore >= 7 ? "high" : topScore >= 4 ? "medium" : cves.length > 0 ? "low" : "clear";
            results.push({ ...tool, cves, status, topScore, total: data.totalResults || 0 });
          } catch (e) {
            results.push({ ...tool, cves: [], status: "unknown", error: e.message });
          }
        }
        return res.status(200).json({ source: "biztools", data: results });
      }

      // Domain / IP / keyword lookup
      case "lookup": {
        if (method !== "POST") return res.status(405).json({ error: "POST required" });
        const { query } = req.body;
        if (!query) return res.status(400).json({ error: "query required" });
        const q = query.trim().toLowerCase();
        const results = [];

        try {
          const r = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
          if (r.ok) {
            const d = await r.json();
            const hits = (d.vulnerabilities || []).filter(v =>
              v.vendorProject?.toLowerCase().includes(q) || v.product?.toLowerCase().includes(q) || v.cveID?.toLowerCase().includes(q)
            ).slice(0, 5);
            if (hits.length) results.push({ source: "CISA KEV", severity: "critical",
              matches: hits.map(m => ({ label: `${m.cveID} — ${m.vendorProject} ${m.product}`, detail: m.shortDescription, date: m.dateAdded })) });
          }
        } catch {}

        try {
          const r = await fetch("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
            { headers: { "User-Agent": "VertexV2Dashboard/1.0" } });
          if (r.ok) {
            const text = await r.text();
            const hits = text.split("\n").filter(l => l.includes(q)).slice(0, 5);
            if (hits.length) results.push({ source: "C2IntelFeeds", severity: "critical",
              matches: hits.map(l => { const p = l.split(","); return { label: p[0]?.trim() || l, detail: p[1]?.trim() || "C2 server", date: null }; }) });
          }
        } catch {}

        try {
          const r = await fetch("https://api.ransomware.live/v2/recentvictims",
            { headers: { "User-Agent": "VertexV2Dashboard/1.0", "Accept": "application/json" } });
          if (r.ok) {
            const d = await r.json();
            const list = Array.isArray(d) ? d : d.victims || [];
            const hits = list.filter(v => v.victim?.toLowerCase().includes(q) || v.website?.toLowerCase().includes(q)).slice(0, 5);
            if (hits.length) results.push({ source: "Ransomware.live", severity: "high",
              matches: hits.map(m => ({ label: `${m.victim || m.company} — ${m.group || m.gang}`, detail: `${m.activity || "Unknown"} | ${m.country || "Unknown"}`, date: m.published })) });
          }
        } catch {}

        try {
          const r = await fetch("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            { headers: { "User-Agent": "VertexV2Dashboard/1.0" } });
          if (r.ok) {
            const text = await r.text();
            const hits = text.split("\n").map(u => u.trim()).filter(Boolean).filter(u => u.toLowerCase().includes(q)).slice(0, 5);
            if (hits.length) results.push({ source: "OpenPhish", severity: "high",
              matches: hits.map(url => ({ label: url, detail: "Active phishing URL — do not visit", date: new Date().toISOString() })) });
          }
        } catch {}

        return res.status(200).json({ source: "lookup", query: q, found: results.length > 0, results });
      }

      default:
        return res.status(400).json({ error: "Unknown source." });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
