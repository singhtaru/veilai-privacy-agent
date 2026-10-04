from groq import Groq
from config import GROQ_API_KEY, MODEL_NAME, LLM_TIMEOUT_SECONDS

client = Groq(api_key=GROQ_API_KEY, timeout=LLM_TIMEOUT_SECONDS, max_retries=2)

SYSTEM_PROMPT = (
    "You are a university assistant for VIT. "
    "Always use the provided tools to look up student or notice data; never answer "
    "from memory and never invent records. "
    "Do not refuse on your own: access control is handled by the system, so if the "
    "user asks for data, call the appropriate tool. "
    "Values like [PERSON_1] or [VIT_REG_NO_1] are placeholders for protected data. "
    "Keep them exactly as written in your answer and pass them unchanged as tool arguments. "
    "If a tool returns no record, say so. Keep answers short and factual."
)


def call_llm(messages, tools):
    """Send the conversation to Groq and return the model's message."""
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, *messages],
        tools=tools,
        tool_choice="auto",
        reasoning_effort="low",
        max_completion_tokens=2048,
    )
    return response.choices[0].message


def assistant_message(message):
    """Rebuild the model's tool-call message in the plain format Groq expects back."""
    return {
        "role": "assistant",
        "content": message.content,
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name,
                             "arguments": tc.function.arguments or "{}"},
            }
            for tc in message.tool_calls
        ],
    }
