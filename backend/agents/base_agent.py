from groq import Groq
from backend.config import Config
from typing import Optional

class BaseAgent:
    def __init__(self):
        self.llm = Groq(api_key=Config.GROQ_API_KEY)
        self.model = " "  
    
    def _call_llm(self, prompt: str, temperature: float = 0.2) -> str:
        try:
            response = self.llm.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=2000
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"LLM Error: {str(e)}"
