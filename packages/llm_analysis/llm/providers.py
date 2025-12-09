#!/usr/bin/env python3
"""
LLM Provider Implementations

Unified interface for multiple LLM providers with consistent API.
"""

import json
import re
import sys
import requests
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.logging import get_logger
from .config import ModelConfig

logger = get_logger()


@dataclass
class LLMResponse:
    """Standardised LLM response."""
    content: str
    model: str
    provider: str
    tokens_used: int
    cost: float
    finish_reason: str
    raw_response: Optional[Dict[str, Any]] = None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.total_tokens = 0
        self.total_cost = 0.0

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion from the model."""
        pass

    @abstractmethod
    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Generate structured output matching the provided schema."""
        pass

    def track_usage(self, tokens: int, cost: float) -> None:
        """Track token usage and cost."""
        self.total_tokens += tokens
        self.total_cost += cost
        logger.debug(f"LLM usage: {tokens} tokens, ${cost:.4f} (total: {self.total_tokens} tokens, ${self.total_cost:.4f})")


class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=config.api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using Claude."""
        try:
            messages = [{"role": "user", "content": prompt}]

            response = self.client.messages.create(
                model=self.config.model_name,
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
                temperature=kwargs.get('temperature', self.config.temperature),
                system=system_prompt or "",
                messages=messages,
            )

            content = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens
            cost = (tokens_used / 1000) * self.config.cost_per_1k_tokens

            self.track_usage(tokens_used, cost)

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider="anthropic",
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=response.stop_reason,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else None,
            )

        except Exception as e:
            logger.error(f"Claude API error: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured JSON output."""
        structured_prompt = f"""{prompt}

You MUST respond with valid JSON matching this exact schema:
{json.dumps(schema, indent=2)}

Respond with ONLY the JSON object, no other text."""

        response = self.generate(structured_prompt, system_prompt)

        # Parse JSON from response
        try:
            content = response.content.strip()

            # Remove markdown code blocks if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            return json.loads(content), response.content
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response content: {response.content}")
            raise


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        try:
            import openai
            self.client = openai.OpenAI(api_key=config.api_key)
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using GPT."""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.config.model_name,
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
                temperature=kwargs.get('temperature', self.config.temperature),
                messages=messages,
            )

            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens
            cost = (tokens_used / 1000) * self.config.cost_per_1k_tokens

            self.track_usage(tokens_used, cost)

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider="openai",
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=response.choices[0].finish_reason,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else None,
            )

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured JSON output."""
        # OpenAI supports JSON mode
        try:
            import openai
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            structured_prompt = f"""{prompt}

Respond with valid JSON matching this schema:
{json.dumps(schema, indent=2)}"""

            messages.append({"role": "user", "content": structured_prompt})

            response = self.client.chat.completions.create(
                model=self.config.model_name,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=messages,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content

            # Track usage
            tokens_used = response.usage.total_tokens
            cost = (tokens_used / 1000) * self.config.cost_per_1k_tokens
            self.track_usage(tokens_used, cost)

            return json.loads(content), content

        except Exception as e:
            logger.error(f"OpenAI structured generation error: {e}")
            raise


class OllamaProvider(LLMProvider):
    """Ollama local model provider (DeepSeek, Qwen, Llama, Mistral, etc.)."""

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not config.api_base:
            raise ValueError("Ollama api_base must be configured in ModelConfig")
        self.api_base = config.api_base
        self.session = requests.Session()
        self.available_models = []

        # Log initialization
        logger.info(f"Initializing Ollama provider: {self.api_base}")
        logger.debug(f"Ollama configuration: model={config.model_name}, timeout={config.timeout}s")

        # Verify Ollama is available and check models
        try:
            response = self.session.get(f"{self.api_base}/api/tags", timeout=5)
            if response.status_code == 200:
                tags_data = response.json()
                self.available_models = [model['name'] for model in tags_data.get('models', [])]
                logger.info(f"Ollama connected. Available models: {', '.join(self.available_models[:5])}")

                # Check if requested model is available
                if config.model_name not in self.available_models:
                    logger.warning(f"Model '{config.model_name}' not found in Ollama. Available: {self.available_models}")
                    logger.warning(f"Run: ollama pull {config.model_name}")
            else:
                logger.warning(f"Ollama server returned {response.status_code} at {self.api_base}")
                raise RuntimeError(f"Ollama not available: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Cannot connect to Ollama server at {self.api_base}: {e}")
            if "localhost" in self.api_base or "127.0.0.1" in self.api_base:
                logger.error("Make sure Ollama is running locally: ollama serve")
            else:
                logger.error(f"Check remote Ollama server is accessible: {self.api_base}")
                logger.error("Verify network connectivity and firewall settings")
            raise RuntimeError(f"Ollama connection failed: {e}")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using Ollama."""
        # Check if model is available
        if self.available_models and self.config.model_name not in self.available_models:
            error_msg = f"Model '{self.config.model_name}' not available. Run: ollama pull {self.config.model_name}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        try:
            payload = {
                "model": self.config.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": kwargs.get('temperature', self.config.temperature),
                    "num_predict": kwargs.get('max_tokens', self.config.max_tokens),
                }
            }

            if system_prompt:
                payload["system"] = system_prompt

            logger.debug(f"Sending request to Ollama: {self.api_base}/api/generate")
            logger.debug(f"Model: {self.config.model_name}, timeout: {self.config.timeout}s")

            response = self.session.post(
                f"{self.api_base}/api/generate",
                json=payload,
                timeout=self.config.timeout,
            )

            # Better error handling
            if response.status_code == 404:
                raise RuntimeError(
                    f"Ollama model '{self.config.model_name}' not found. "
                    f"Run: ollama pull {self.config.model_name}"
                )
            elif response.status_code == 405:
                raise RuntimeError(
                    f"Ollama API method not allowed. Check Ollama version. "
                    f"Endpoint: {self.api_base}/api/generate"
                )

            response.raise_for_status()

            data = response.json()
            content = data.get("response", "")

            if not content:
                logger.warning("Ollama returned empty response")

            # Ollama doesn't provide exact token counts, estimate
            tokens_used = len(prompt.split()) + len(content.split())
            cost = 0.0  # Local inference is free

            self.track_usage(tokens_used, cost)

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider="ollama",
                tokens_used=tokens_used,
                cost=cost,
                finish_reason="stop",
                raw_response=data,
            )

        except requests.exceptions.Timeout:
            logger.error(f"Ollama request timed out after {self.config.timeout}s")
            if "localhost" not in self.api_base and "127.0.0.1" not in self.api_base:
                logger.error(f"Remote server {self.api_base} may be slow or overloaded")
                logger.error("Consider increasing timeout in ModelConfig")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to Ollama at {self.api_base}")
            if "localhost" in self.api_base or "127.0.0.1" in self.api_base:
                logger.error("Make sure Ollama is running locally: ollama serve")
            else:
                logger.error(f"Check remote Ollama server is accessible: {self.api_base}")
                logger.error("Verify network connectivity and firewall settings")
            raise RuntimeError(f"Ollama connection failed: {e}")
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured JSON output."""
        structured_prompt = f"""{prompt}

You MUST respond with valid JSON matching this exact schema:
{json.dumps(schema, indent=2)}

Respond with ONLY the JSON object, no markdown, no other text."""

        response = self.generate(structured_prompt, system_prompt)

                # Parse JSON from response
        try:
            content = response.content.strip()

            #logger.debug(f"RAW RESPONSE FROM OLLAMA: {content[:1000]}") #useful if the ollama response is malformed
            # use for debugging malformed responses only otherwise it messes output up 

            # Remove thinking tags from reasoning models (qwen3, deepseek-r1, etc.)
            if "<think>" in content.lower():
                # Extract content after </think> tag
                # Remove everything between <think> and </think> (case insensitive)
                content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL | re.IGNORECASE)

            # Remove comments from JSON (Ollama code models add them)
            content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)  # JavaScript //
            content = re.sub(r'#.*?$', '', content, flags=re.MULTILINE)   # Python #
            content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)  # C /* */
            content = content.strip()

            # Remove markdown code blocks if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            # Try to extract JSON if there's additional text
            if content and not content.startswith('{') and not content.startswith('['):
                # Look for JSON object or array in the content
                json_match = re.search(r'(\{[^{}]*\}|\[[^\[\]]*\])', content, re.DOTALL)
                if json_match:
                    content = json_match.group(1)

            # If still no valid JSON, try to find the first { and last }
            if not content or not (content.startswith('{') or content.startswith('[')):
                start_idx = content.find('{')
                end_idx = content.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    content = content[start_idx:end_idx+1]

            # Try to find JSON after thinking content
            if not content or not (content.startswith('{') or content.startswith('[')):
                # Look for JSON after any thinking or explanation text
                json_start = content.find('{')
                if json_start != -1:
                    # Try to parse from the first { onwards
                    potential_json = content[json_start:]
                    # Find matching closing brace
                    brace_count = 0
                    end_pos = json_start
                    for i, char in enumerate(potential_json):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end_pos = json_start + i + 1
                                break
                    if brace_count == 0:
                        content = content[json_start:end_pos]

            if not content:
                logger.error("Empty content after cleaning")
                logger.debug(f"Original response: {response.content[:1000]}")
                raise ValueError("No valid JSON found in response")

            # Try to fix common JSON issues
            content = content.replace('\\"', '"')  # Fix escaped quotes
            content = re.sub(r',\s*}', '}', content)  # Remove trailing commas
            content = re.sub(r',\s*]', ']', content)  # Remove trailing commas in arrays

            return json.loads(content), response.content

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from Ollama: {e}")
            logger.debug(f"Response content: {response.content[:1000]}")
            logger.debug(f"Cleaned content: {content[:500]}")
            # Log the full raw response for debugging
            logger.error(f"RAW RESPONSE FROM OLLAMA: {response.content}")

            # For exploit generation, try to extract code from the response even if JSON is malformed
            if "exploit" in prompt.lower() and "code" in schema and "reasoning" in schema:
                logger.warning("Attempting to extract code from malformed response...")

                # Try to extract code and reasoning using regex
                code_match = re.search(r'"code"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', response.content, re.DOTALL)
                reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', response.content, re.DOTALL)

                if code_match:
                    extracted_code = code_match.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t')
                    extracted_reasoning = reasoning_match.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t') if reasoning_match else "Extracted from malformed JSON response"

                    logger.info("Successfully extracted code from malformed response")
                    return {"code": extracted_code, "reasoning": extracted_reasoning}, response.content

            raise


def create_provider(config: ModelConfig) -> LLMProvider:
    """Factory function to create appropriate provider."""
    providers = {
        "anthropic": ClaudeProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }

    provider_class = providers.get(config.provider.lower())
    if not provider_class:
        raise ValueError(f"Unknown provider: {config.provider}")

    return provider_class(config)
