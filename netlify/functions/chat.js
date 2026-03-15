exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const GROQ_API_KEY = process.env.GROQ_API_KEY;
  if (!GROQ_API_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "GROQ_API_KEY environment variable not set." }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON body." }) };
  }

  const { messages, system, model } = body;
  if (!messages || !Array.isArray(messages)) {
    return { statusCode: 400, body: JSON.stringify({ error: "messages array required." }) };
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
            content:
              system ||
              "You are a helpful, knowledgeable, and friendly AI assistant. Be thorough but concise. Use markdown formatting when it helps clarity.",
          },
          ...messages,
        ],
      }),
    });

    if (!groqRes.ok) {
      const err = await groqRes.json().catch(() => ({}));
      return {
        statusCode: groqRes.status,
        body: JSON.stringify({ error: err?.error?.message || "Groq API error" }),
      };
    }

    const data = await groqRes.json();
    const reply = data.choices?.[0]?.message?.content || "(no response)";

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reply }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal error: " + err.message }),
    };
  }
};
