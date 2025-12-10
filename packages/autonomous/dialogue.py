#!/usr/bin/env python3
"""
Multi-Turn LLM Dialogue - Iterative Reasoning

This module enables RAPTOR to have multi-turn conversations with LLMs
for deeper analysis and iterative refinement, rather than single-shot prompts.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

from core.logging import get_logger
from packages.llm_analysis.llm.providers import LLMProvider

logger = get_logger()


class DialogueState(Enum):
    """State of the dialogue."""
    INITIAL = "initial"
    ANALYZING = "analyzing"
    REFINING = "refining"
    VALIDATING = "validating"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class Message:
    """A single message in the dialogue."""
    role: str  # "user" or "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DialogueContext:
    """Context for the dialogue - what we're trying to accomplish."""
    goal: str  # What we're trying to achieve (e.g., "analyse crash", "refine exploit")
    crash_info: Optional[Dict] = None  # Crash details if relevant
    exploit_code: Optional[str] = None  # Exploit code if refining
    validation_results: Optional[Dict] = None  # Validation results if iterating
    max_turns: int = 5  # Maximum dialogue turns


class MultiTurnAnalyser:
    """
    Multi-turn dialogue system for iterative analysis and refinement.

    Instead of asking the LLM once and accepting the answer, this system:
    1. Asks an initial question
    2. Evaluates the response
    3. Asks follow-up questions to refine understanding
    4. Iterates until confidence is high or max turns reached
    5. Validates results and requests corrections if needed
    """

    def __init__(self, llm_client: LLMProvider, memory=None):
        """
        Initialise the multi-turn analyser.

        Args:
            llm_client: LLM client for communication
            memory: FuzzingMemory for learning (optional)
        """
        self.llm = llm_client
        self.memory = memory
        self.dialogue_history: List[List[Message]] = []
        logger.info("Multi-turn analyser initialised")

    def analyse_crash_deeply(self, crash_context, max_turns: int = 5) -> Dict:
        """
        Perform deep, multi-turn analysis of a crash.

        Instead of single-shot analysis, we:
        1. Get initial analysis
        2. Ask follow-up questions about unclear points
        3. Request deeper investigation of interesting aspects
        4. Validate conclusions
        5. Refine understanding

        Args:
            crash_context: CrashContext object
            max_turns: Maximum dialogue turns

        Returns:
            Dictionary with analysis results and confidence
        """
        logger.info("=" * 70)
        logger.info("MULTI-TURN CRASH ANALYSIS")
        logger.info("=" * 70)

        context = DialogueContext(
            goal="analyse crash deeply",
            crash_info={
                "signal": crash_context.signal,
                "function": crash_context.function_name,
                "stack_trace": crash_context.stack_trace,
                "registers": crash_context.registers,
            },
            max_turns=max_turns,
        )

        messages = []
        analysis_result = {
            "vulnerability_type": "unknown",
            "exploitability": "unknown",
            "confidence": 0.0,
            "reasoning_steps": [],
        }

        # Turn 1: Initial analysis
        logger.info("Turn 1: Initial analysis")
        initial_prompt = self._build_initial_crash_prompt(crash_context)
        messages.append(Message(role="user", content=initial_prompt))

        llm_response = self.llm.generate(initial_prompt)
        response = llm_response.content
        messages.append(Message(role="assistant", content=response))
        analysis_result["reasoning_steps"].append({
            "turn": 1,
            "question": "Initial analysis",
            "response": response[:200] + "...",
        })

        # Parse initial response
        initial_analysis = self._parse_crash_analysis(response)
        analysis_result.update(initial_analysis)

        # Turn 2: Clarify exploitability
        if analysis_result["confidence"] < 0.8:
            logger.info("Turn 2: Clarifying exploitability")
            clarification = self._build_clarification_prompt(initial_analysis, crash_context)
            messages.append(Message(role="user", content=clarification))

            llm_response = self.llm.generate(clarification)
            response = llm_response.content
            messages.append(Message(role="assistant", content=response))
            analysis_result["reasoning_steps"].append({
                "turn": 2,
                "question": "Exploitability clarification",
                "response": response[:200] + "...",
            })

            # Update analysis with clarifications
            refined = self._parse_crash_analysis(response)
            analysis_result["exploitability"] = refined.get("exploitability", analysis_result["exploitability"])
            analysis_result["confidence"] = min(1.0, analysis_result["confidence"] + 0.2)

        # Turn 3: Validate with memory
        if self.memory and analysis_result["confidence"] < 0.9:
            logger.info("Turn 3: Validating with memory")
            validation = self._validate_with_memory(analysis_result, crash_context)
            if validation:
                analysis_result["confidence"] = min(1.0, analysis_result["confidence"] + 0.1)
                analysis_result["reasoning_steps"].append({
                    "turn": 3,
                    "question": "Memory validation",
                    "response": validation,
                })

        logger.info(f"Final analysis confidence: {analysis_result['confidence']:.2f}")
        logger.info(f"Vulnerability type: {analysis_result['vulnerability_type']}")
        logger.info(f"Exploitability: {analysis_result['exploitability']}")

        # Record dialogue
        self.dialogue_history.append(messages)

        return analysis_result

    def refine_exploit_iteratively(self, exploit_code: str, crash_context,
                                   validation_errors: List[str],
                                   max_iterations: int = 3) -> Optional[str]:
        """
        Iteratively refine an exploit based on validation failures.

        Args:
            exploit_code: Initial exploit code
            crash_context: Crash context
            validation_errors: List of compilation/runtime errors
            max_iterations: Maximum refinement iterations

        Returns:
            Refined exploit code or None if refinement failed
        """
        logger.info("=" * 70)
        logger.info("ITERATIVE EXPLOIT REFINEMENT")
        logger.info("=" * 70)

        context = DialogueContext(
            goal="refine exploit",
            crash_info={"signal": crash_context.signal, "function": crash_context.function_name},
            exploit_code=exploit_code,
            validation_results={"errors": validation_errors},
            max_turns=max_iterations,
        )

        messages = []
        current_code = exploit_code

        for iteration in range(1, max_iterations + 1):
            logger.info(f"Iteration {iteration}: Refining exploit")

            # Build refinement prompt
            refinement_prompt = self._build_refinement_prompt(
                current_code, validation_errors, crash_context, iteration
            )
            messages.append(Message(role="user", content=refinement_prompt))

            # Get refined code
            llm_response = self.llm.generate(refinement_prompt)
            response = llm_response.content
            messages.append(Message(role="assistant", content=response))

            # Extract code from response
            refined_code = self._extract_code_from_response(response)
            if not refined_code:
                logger.warning(f"Iteration {iteration}: Failed to extract code from response")
                continue

            current_code = refined_code

            # Validate refined code
            new_errors = self._quick_validate_code(refined_code)
            if not new_errors:
                logger.info(f"Iteration {iteration}: Refinement successful!")
                self.dialogue_history.append(messages)
                return refined_code

            logger.info(f"Iteration {iteration}: Still has {len(new_errors)} errors")
            validation_errors = new_errors

        logger.warning("Max iterations reached without successful refinement")
        self.dialogue_history.append(messages)
        return current_code  # Return best attempt

    def ask_strategic_question(self, question: str, context_data: Dict = None) -> str:
        """
        Ask the LLM a strategic question about fuzzing.

        Examples:
        - "Should I continue fuzzing or stop?"
        - "Which mutation strategy should I try next?"
        - "Is this crash worth deeper analysis?"

        Args:
            question: Question to ask
            context_data: Optional context data

        Returns:
            LLM's response
        """
        logger.info(f"Strategic question: {question}")

        prompt = f"""You are an expert fuzzing strategist helping make autonomous decisions.

**Question:** {question}

**Context:**
"""
        if context_data:
            for key, value in context_data.items():
                prompt += f"- {key}: {value}\n"

        prompt += """
**Instructions:**
1. Analyse the situation carefully
2. Consider multiple options
3. Recommend the best course of action
4. Explain your reasoning
5. Be decisive - provide a clear recommendation

**Response:**"""

        llm_response = self.llm.generate(prompt)
        response = llm_response.content
        logger.info(f"LLM recommendation: {response[:200]}...")

        return response

    def _build_initial_crash_prompt(self, crash_context) -> str:
        """Build initial crash analysis prompt."""
        return f"""Analyse this crash in detail:

**Crash Signal:** {crash_context.signal}
**Function:** {crash_context.function_name or 'unknown'}

**Stack Trace:**
```
{crash_context.stack_trace or 'Not available'}
```

**Registers:**
```
{crash_context.registers or 'Not available'}
```

**Questions to answer:**
1. What type of vulnerability is this? (buffer overflow, use-after-free, etc.)
2. How exploitable is this? (High/Medium/Low/None)
3. What exploitation techniques would work?
4. What are the key indicators that led to your conclusion?
5. Are there any protections that could stop successful exploitation?

Provide a detailed analysis."""

    def _build_clarification_prompt(self, initial_analysis: Dict, crash_context) -> str:
        """Build clarification prompt based on initial analysis."""
        return f"""Based on your initial analysis, I need clarification on the exploitability.

**Your initial assessment:** {initial_analysis.get('exploitability', 'unknown')}

**Additional context:**
- Input size: {crash_context.size if hasattr(crash_context, 'size') else 'unknown'} bytes
- Binary protections: {crash_context.binary_info if hasattr(crash_context, 'binary_info') else 'unknown'}

**Specific questions:**
1. Can an attacker control the crash location?
2. Can an attacker control the crash value/data?
3. What are the constraints on exploitation?
4. What is your confidence level (0-100%) in the exploitability assessment?

Be specific and provide clear reasoning."""

    def _build_refinement_prompt(self, code: str, errors: List[str],
                                crash_context, iteration: int) -> str:
        """Build exploit refinement prompt."""
        errors_text = "\n".join(f"- {e}" for e in errors[:5])  # First 5 errors

        return f"""The exploit code has compilation/validation errors. Please fix them.

**Iteration:** {iteration}
**Crash type:** {crash_context.signal}

**Current errors:**
{errors_text}

**Current code:**
```c
{code[:1000]}
```

**Instructions:**
1. Fix the specific errors listed above
2. Ensure the code compiles with: gcc -o exploit exploit.c
3. Keep the exploit logic intact
4. Return ONLY the complete fixed C code
5. Do not add any explanations outside the code block

**Fixed code:**"""

    def _parse_crash_analysis(self, response: str) -> Dict:
        """Parse LLM response for crash analysis."""
        analysis = {
            "vulnerability_type": "unknown",
            "exploitability": "unknown",
            "confidence": 0.5,
        }

        response_lower = response.lower()

        # Detect vulnerability type
        if "buffer overflow" in response_lower or "stack overflow" in response_lower:
            analysis["vulnerability_type"] = "buffer_overflow"
        elif "heap overflow" in response_lower:
            analysis["vulnerability_type"] = "heap_overflow"
        elif "use-after-free" in response_lower or "use after free" in response_lower:
            analysis["vulnerability_type"] = "use_after_free"
        elif "null pointer" in response_lower:
            analysis["vulnerability_type"] = "null_pointer_dereference"

        # Detect exploitability
        if "high" in response_lower and "exploit" in response_lower:
            analysis["exploitability"] = "high"
            analysis["confidence"] = 0.8
        elif "medium" in response_lower and "exploit" in response_lower:
            analysis["exploitability"] = "medium"
            analysis["confidence"] = 0.7
        elif "low" in response_lower and "exploit" in response_lower:
            analysis["exploitability"] = "low"
            analysis["confidence"] = 0.6
        elif "not exploitable" in response_lower or "none" in response_lower:
            analysis["exploitability"] = "none"
            analysis["confidence"] = 0.7

        return analysis

    def _extract_code_from_response(self, response: str) -> Optional[str]:
        """Extract C code from LLM response."""
        import re

        # Look for code blocks
        code_block_match = re.search(r'```c\n(.*?)```', response, re.DOTALL)
        if code_block_match:
            return code_block_match.group(1).strip()

        # Look for any code block
        code_block_match = re.search(r'```\n(.*?)```', response, re.DOTALL)
        if code_block_match:
            return code_block_match.group(1).strip()

        return None

    def _quick_validate_code(self, code: str) -> List[str]:
        """Quick validation of C code (basic syntax checks)."""
        errors = []

        # Basic syntax checks
        if code.count('{') != code.count('}'):
            errors.append("Mismatched braces")

        if code.count('(') != code.count(')'):
            errors.append("Mismatched parentheses")

        # Check for common issues
        if '#ifdef "__' in code or '#ifndef "__' in code:
            errors.append("Invalid preprocessor directive with Chinese characters")

        if '\\T' in code or '\\0x' in code:
            errors.append("Invalid escape sequence")

        return errors

    def _validate_with_memory(self, analysis: Dict, crash_context) -> Optional[str]:
        """Validate analysis against memory."""
        if not self.memory:
            return None

        signal = crash_context.signal
        function = crash_context.function_name or "unknown"

        # Check if we've seen this pattern before
        probability = self.memory.is_crash_likely_exploitable(signal, function)

        if probability > 0.7 and analysis["exploitability"] == "low":
            return f"Warning: Memory suggests this pattern is usually exploitable (p={probability:.2f})"
        elif probability < 0.3 and analysis["exploitability"] == "high":
            return f"Warning: Memory suggests this pattern is rarely exploitable (p={probability:.2f})"

        return f"Memory validation: consistent with history (p={probability:.2f})"

    def _messages_to_context(self, messages: List[Message]) -> str:
        """Convert message history to context string for LLM."""
        context = ""
        for msg in messages[-4:]:  # Last 4 messages for context
            role = "User" if msg.role == "user" else "Assistant"
            context += f"{role}: {msg.content[:300]}\n\n"
        return context

    def get_dialogue_summary(self) -> Dict:
        """Get summary of all dialogues."""
        return {
            "total_dialogues": len(self.dialogue_history),
            "total_turns": sum(len(d) for d in self.dialogue_history),
        }
