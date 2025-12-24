#!/usr/bin/env python3
"""
Pydantic schemas for validating LiteLLM YAML configuration.

Provides schema validation at config load time to catch edge cases early:
- Type mismatches (model_list as int instead of list)
- Missing required fields (model_name, litellm_params)
- Invalid formats (model without provider prefix)
- Invalid ranges (temperature outside 0.0-2.0)
- Duplicate model aliases

Usage:
    from .yaml_schema import LiteLLMConfigSchema

    config_dict = yaml.safe_load(f)
    validated = LiteLLMConfigSchema.model_validate(config_dict)
    models = [m.model_dump() for m in validated.model_list]
"""

from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import Optional, List


class LiteLLMParamsSchema(BaseModel):
    """
    Validates litellm_params section of model entry.

    Required:
        model: Provider/model format (e.g., 'openai/gpt-4o', 'anthropic/claude-sonnet-4.5')

    Optional:
        api_key: Literal API key or 'os.environ/VAR_NAME' format
        api_base: Custom API endpoint
        temperature: Sampling temperature (0.0-2.0)
        max_tokens: Maximum output tokens (> 0)
        timeout: Request timeout in seconds
    """
    model: str = Field(..., description="Model in 'provider/name' format")
    api_key: Optional[str] = Field(None, description="API key or os.environ/VAR format")
    api_base: Optional[str] = Field(None, description="Custom API endpoint URL")
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(None, gt=0, description="Maximum output tokens")
    timeout: Optional[int] = Field(None, gt=0, description="Request timeout in seconds")

    # Allow additional fields (LiteLLM supports many provider-specific params)
    model_config = ConfigDict(extra="allow")

    @model_validator(mode='after')
    def validate_model_format(self):
        """Ensure model follows 'provider/name' format."""
        if not self.model or '/' not in self.model:
            raise ValueError(
                f"Model must be in 'provider/name' format (e.g., 'openai/gpt-4o'), "
                f"got: '{self.model}'. Check litellm_params.model field."
            )

        # Validate provider is not empty
        provider, model_name = self.model.split('/', 1)
        if not provider or not model_name:
            raise ValueError(
                f"Both provider and model name must be non-empty, "
                f"got: '{self.model}'"
            )

        return self

    @model_validator(mode='after')
    def validate_api_key_format(self):
        """Validate API key format if provided."""
        if self.api_key and self.api_key.startswith('$'):
            raise ValueError(
                f"API key uses shell variable syntax: '{self.api_key}'. "
                f"Use 'os.environ/VAR_NAME' format instead."
            )
        return self


class ModelInfoSchema(BaseModel):
    """
    Validates model_info section of model entry.

    All fields are optional. Provides metadata about model capabilities.

    Common fields:
        max_input_tokens: Maximum input context size
        max_output_tokens: Maximum output token limit
        supports_vision: Whether model supports image inputs
        supports_function_calling: Whether model supports function/tool calling
        supports_reasoning: Whether model has explicit reasoning mode (e.g., o1, gemini-deep-think)
    """
    max_input_tokens: Optional[int] = Field(None, gt=0, description="Maximum input tokens")
    max_output_tokens: Optional[int] = Field(None, gt=0, description="Maximum output tokens")
    supports_vision: Optional[bool] = Field(None, description="Supports image inputs")
    supports_function_calling: Optional[bool] = Field(None, description="Supports function calling")
    supports_reasoning: Optional[bool] = Field(None, description="Has explicit reasoning mode")

    # Allow additional capability flags
    model_config = ConfigDict(extra="allow")


class ModelEntrySchema(BaseModel):
    """
    Validates a single model entry in model_list.

    Required:
        model_name: Alias/friendly name for this model (must be unique)
        litellm_params: Configuration for LiteLLM (provider, model ID, API key, etc.)

    Optional:
        model_info: Metadata about model capabilities
    """
    model_name: str = Field(..., description="Alias for this model (must be unique)")
    litellm_params: LiteLLMParamsSchema = Field(..., description="LiteLLM configuration")
    model_info: Optional[ModelInfoSchema] = Field(None, description="Model capabilities metadata")

    @model_validator(mode='after')
    def validate_model_name_not_empty(self):
        """Ensure model_name is not empty or whitespace-only."""
        if not self.model_name or not self.model_name.strip():
            raise ValueError(
                "model_name cannot be empty or whitespace-only. "
                "Provide a unique alias for this model."
            )
        return self


class LiteLLMConfigSchema(BaseModel):
    """
    Validates entire LiteLLM config.yaml file.

    Top-level structure:
        model_list: List of model entries (required, can be empty)

    Validation:
        - model_list must be a list (not int, string, bool, null)
        - Each entry must be a valid ModelEntrySchema
        - No duplicate model_name aliases allowed
    """
    model_list: List[ModelEntrySchema] = Field(
        default_factory=list,
        description="List of available models"
    )

    @model_validator(mode='after')
    def validate_no_duplicate_aliases(self):
        """Ensure model_name aliases are unique."""
        if not self.model_list:
            return self  # Empty list is valid

        aliases = [m.model_name for m in self.model_list]
        seen = set()
        duplicates = set()

        for alias in aliases:
            if alias in seen:
                duplicates.add(alias)
            seen.add(alias)

        if duplicates:
            raise ValueError(
                f"Duplicate model_name aliases found: {sorted(duplicates)}. "
                f"Each model must have a unique alias. Check your config.yaml model_list."
            )

        return self
