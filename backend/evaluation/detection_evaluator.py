"""Detection Rules Quality Evaluator.

Calculates Precision, Recall, False Positive Rate (FPR), and False Negative Rate (FNR)
for the rules/detections engine.
"""
from __future__ import annotations

import logging
from typing import Dict

log = logging.getLogger(__name__)

def calculate_detection_metrics(
    tp: int,  # True Positives
    fp: int,  # False Positives
    fn: int,  # False Negatives
    tn: int   # True Negatives (benign events correctly ignored)
) -> Dict[str, float]:
    """Calculate detection quality metrics."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4)
    }
