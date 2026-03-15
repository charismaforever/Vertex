export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const GROQ_API_KEY = process.env.GROQ_API_KEY;
  if (!GROQ_API_KEY) {
    return res.status(500).json({ error: "GROQ_API_KEY environment variable not set." });
  }

  const { messages, system, model } = req.body;
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: "messages array required." });
  }

  const ALLOWED_MODELS = [
    'llama-3.3-70b-versatile',
    'deepseek-r1-distill-llama-70b',
    'qwen-qwq-32b',
    'mixtral-8x7b-32768',
    'llama-3.1-8b-instant',
    'gemma2-9b-it',
  ];

  const selectedModel = ALLOWED_MODELS.includes(model) ? model : 'llama-3.3-70b-versatile';

  try {
    const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model: selectedModel,
        max_tokens: 2048,
        messages: [
          {
            role: "system",
            content: system || "You are a helpful, knowledgeable, and friendly AI assistant. Be thorough but concise. Use markdown formatting when it helps clarity.",
          },
          ...messages,
        ],
      }),
    });

    if (!groqRes.ok) {
      const err = await groqRes.json().catch(() => ({}));
      return res.status(groqRes.status).json({ error: err?.error?.message || "Groq API error" });
    }

    const data = await groqRes.json();
    const reply = data.choices?.[0]?.message?.content || "(no response)";
    return res.status(200).json({ reply });

  } catch (err) {
    return res.status(500).json({ error: "Internal error: " + err.message });
  }
}
