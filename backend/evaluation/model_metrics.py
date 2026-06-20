import logging
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import pandas as pd

logger = logging.getLogger(__name__)

def evaluate_triage_model(y_true: list[str], y_pred: list[str]) -> dict:
    """
    Evaluates the AI SOC's triage decision accuracy against analyst ground truth.
    y_true: list of actual analyst verdicts (e.g. ['TRUE_POSITIVE', 'FALSE_POSITIVE'])
    y_pred: list of AI predicted verdicts
    """
    # Filter out PENDING items from ground truth
    valid_indices = [i for i, val in enumerate(y_true) if val != 'PENDING']
    y_true_clean = [y_true[i] for i in valid_indices]
    y_pred_clean = [y_pred[i] for i in valid_indices]

    if not y_true_clean:
        return {"error": "No labeled ground truth data available for evaluation."}

    # Calculate metrics
    precision = precision_score(y_true_clean, y_pred_clean, average='weighted', zero_division=0)
    recall = recall_score(y_true_clean, y_pred_clean, average='weighted', zero_division=0)
    f1 = f1_score(y_true_clean, y_pred_clean, average='weighted', zero_division=0)
    accuracy = accuracy_score(y_true_clean, y_pred_clean)

    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "samples_evaluated": len(y_true_clean)
    }
    
    logger.info(f"[EVALUATION] Triage Model Performance: {metrics}")
    return metrics

def run_evaluation_on_db() -> dict:
    """Pulls all resolved alerts from the database and runs the evaluation."""
    from database import get_db
    with get_db() as conn:
        cur = conn.execute(
            "SELECT verdict as true_verdict, llm_summary FROM alerts WHERE verdict != 'PENDING' AND llm_summary IS NOT NULL"
        )
        rows = [dict(r) for r in cur.fetchall()]

    if not rows:
        return {"error": "Not enough resolved alerts to evaluate."}

    y_true = []
    y_pred = []

    for r in rows:
        y_true.append(r['true_verdict'])
        
        # Super simple heuristic to extract predicted verdict from llm_summary for the MVP
        # In production, the LLM should output structured JSON with a 'predicted_verdict' field.
        summary_lower = r['llm_summary'].lower()
        if "false positive" in summary_lower:
            y_pred.append("FALSE_POSITIVE")
        elif "benign" in summary_lower:
            y_pred.append("BENIGN")
        else:
            y_pred.append("TRUE_POSITIVE")

    return evaluate_triage_model(y_true, y_pred)
