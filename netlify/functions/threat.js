exports.handler = async function (event) {
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const source = event.queryStringParameters?.source;

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };

  try {
    switch (source) {
      // ── NVD: Latest critical CVEs (NIST, free, no key) ──
      case "nvd": {
        const now = new Date();
        const past = new Date(now - 7 * 24 * 60 * 60 * 1000); // last 7 days
        const fmt = (d) => d.toISOString().split(".")[0] + "%2B01:00";
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(past)}&pubEndDate=${fmt(now)}&cvssV3Severity=CRITICAL&resultsPerPage=15`;
        const res = await fetch(url, {
          headers: { "User-Agent": "VertexThreatDashboard/1.0" },
        });
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

      // ── CISA KEV: Actively exploited vulnerabilities (free, no key) ──
      case "cisa": {
        const res = await fetch(
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        );
        if (!res.ok) throw new Error(`CISA API error: ${res.status}`);
        const data = await res.json();
        // Most recently added
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

      // ── URLhaus: Live malware URL feed (abuse.ch, free) ──
      case "urlhaus": {
        const res = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: "",
        });
        if (!res.ok) throw new Error(`URLhaus error: ${res.status}`);
        const data = await res.json();
        const urls = (data.urls || []).slice(0, 15).map((u) => ({
          id: u.id,
          url: u.url,
          host: u.host,
          status: u.url_status,
          threat: u.threat,
          tags: u.tags || [],
          dateAdded: u.date_added,
        }));
        return { statusCode: 200, headers, body: JSON.stringify({ source: "urlhaus", data: urls }) };
      }

      // ── HIBP: Recent public breaches (no key needed for breach list) ──
      case "hibp": {
        const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
          headers: {
            "User-Agent": "VertexThreatDashboard/1.0",
          },
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

      default:
        return { statusCode: 400, body: JSON.stringify({ error: "Unknown source. Use: nvd, cisa, urlhaus, hibp" }) };
    }
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
