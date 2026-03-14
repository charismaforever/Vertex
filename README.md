# Vertex — AI Assistant

**Vertex** is an AI-powered chat assistant built for business. Powered by **Llama 3.3 70B** (open-source) via
[Groq](https://groq.com), it delivers instant, intelligent responses to help professionals think faster,
write better, and solve problems with confidence.

Whether you're drafting communications, analysing complex topics, brainstorming strategy, or working through
technical challenges, Vertex is always ready — no setup, no logins, no friction.

Your API key stays safely on the server — users never see it.

---

## Project structure

```
vertex/
├── public/
│   └── index.html          ← The entire frontend (one file)
├── netlify/
│   └── functions/
│       └── chat.js         ← Serverless function (hides your API key)
├── netlify.toml            ← Netlify build + redirect config
└── README.md
```

---

## Deploy in 5 minutes

### Step 1 — Get a free Groq API key

1. Go to [console.groq.com](https://console.groq.com) and sign up (free, no credit card needed).
2. Click **API Keys → Create API Key**.
3. Copy the key — you'll need it in Step 3.

---

### Step 2 — Push to GitHub

```bash
# In this folder:
git init
git add .
git commit -m "Initial commit"

# Create a new repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

---

### Step 3 — Deploy on Netlify

1. Go to [app.netlify.com](https://app.netlify.com) and click **Add new site → Import an existing project**.
2. Connect your GitHub and select your repo.
3. Build settings are auto-detected from `netlify.toml` — no changes needed.
4. Click **Deploy site**.

#### Add your secret API key

After the first deploy:

1. Go to **Site configuration → Environment variables → Add a variable**.
2. Set:
   - **Key:** `GROQ_API_KEY`
   - **Value:** `gsk_...` (your Groq key from Step 1)
3. Click **Save**, then **Trigger deploy → Deploy site** to redeploy with the key active.

---

### Step 4 — Done! 🎉

Your site is live at `https://your-site-name.netlify.app`.

- No login required for users.
- No API key exposed in the browser.
- Groq free tier: **30 requests/minute**, plenty for personal or small team use.

---

## Local development

```bash
npm install -g netlify-cli
netlify dev
```

Create a `.env` file in the project root:

```
GROQ_API_KEY=gsk_your_key_here
```

Then visit `http://localhost:8888`.

---

## Customisation

| What | Where |
|------|-------|
| App name / branding | `public/index.html` — search for "Vertex" |
| System prompt | `netlify/functions/chat.js` — `system` field |
| AI model | `netlify/functions/chat.js` — `model` field |
| Max response length | `netlify/functions/chat.js` — `max_tokens` |

### Other free Groq models you can use

| Model string | Notes |
|---|---|
| `llama-3.3-70b-versatile` | Default — best quality |
| `llama-3.1-8b-instant` | Faster, lighter |
| `mixtral-8x7b-32768` | Long context window |
| `gemma2-9b-it` | Google Gemma 2 |

Change the `model` value in `chat.js` to switch.

---

## Rate limits (Groq free tier)

- 30 requests / minute
- 6,000 requests / day
- 500,000 tokens / day

More than enough for demos and small teams. Paid tiers available if you scale.
