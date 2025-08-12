import os
import openai
import tiktoken
import logging

from src.config import *


class LLMBot:
    def __init__(self):
        # llm_settings
        llm_settings = SETTINGS.llm_settings

        self.messages = [{"role": "system", "content": llm_settings.system_prompt}]
        self.client = openai.OpenAI(
            api_key=llm_settings.api_key or os.environ.get("LLM_API_KEY"),
            base_url=llm_settings.base_url or os.environ.get("LLM_BASE_URL")
        )
        self.model = llm_settings.model
        self.max_tokens = llm_settings.max_tokens

        self.logger = logging.getLogger(__name__)
        self.logger.disabled = False

    def _is_tokens_exceeded(self, message):
        try:
            tokenizer = tiktoken.encoding_for_model(self.model)
        except KeyError:
            tokenizer = tiktoken.get_encoding("cl100k_base")
        return len(tokenizer.encode(message)) > self.max_tokens

    def query(self, message=""):
        # 检查消息长度
        if self._is_tokens_exceeded(message):
            raise Exception("[LLMBot] Message length exceeds the maximum token limit")

        self.messages.append({"role": "user", "content": message})
        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.messages
        )
        content = response.choices[0].message.content

        # 记录 LLM 的响应
        self.messages.append({"role": "assistant", "content": content})
        return content
