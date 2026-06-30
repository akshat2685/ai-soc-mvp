from langchain_core.prompts import FewShotPromptTemplate, PromptTemplate

def build_few_shot_triage_prompt(alert_title: str, evidence_str: str, past_verdicts: list[dict]) -> str:
    """
    Constructs a Few-Shot Prompt using LangChain to guide the LLM
    based on historical analyst decisions.
    """
    
    # 1. Define the example template
    example_template = """
Alert Type: {alert_type}
Evidence: {evidence}
Analyst Verdict: {verdict}
Analyst Notes: {notes}
"""
    example_prompt = PromptTemplate(
        input_variables=["alert_type", "evidence", "verdict", "notes"],
        template=example_template
    )
    
    # 2. Format the historical data into the expected dictionary format
    examples = []
    for pv in past_verdicts:
        examples.append({
            "alert_type": pv.get("title", "Unknown"),
            "evidence": pv.get("evidence", "{}"),
            "verdict": pv.get("verdict", "TRUE_POSITIVE"),
            "notes": pv.get("notes", "No notes provided.")
        })
        
    # 3. Create the FewShotPromptTemplate
    prefix = """You are an AI Security Operations Center (SOC) Analyst.
Your job is to analyze incoming alerts and determine if they are TRUE_POSITIVE, FALSE_POSITIVE, or BENIGN.
Use the following historical examples of how human analysts have classified similar alerts to guide your decision-making."""

    suffix = """
--- NEW INCOMING ALERT ---
Alert Type: {input_alert_type}
Evidence: {input_evidence}

Please provide a short summary of the threat, cite evidence, and state your confidence score.
"""

    few_shot_prompt = FewShotPromptTemplate(
        examples=examples,
        example_prompt=example_prompt,
        prefix=prefix,
        suffix=suffix,
        input_variables=["input_alert_type", "input_evidence"],
        example_separator="\n---\n"
    )
    
    # 4. Render the final prompt string
    return few_shot_prompt.format(
        input_alert_type=alert_title,
        input_evidence=evidence_str
    )
