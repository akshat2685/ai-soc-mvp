"""RAG Retrieval Evaluator.

Calculates Recall@K, Precision@K, and Mean Reciprocal Rank (MRR) for semantic
and graph retrieval layers.
"""
from __future__ import annotations

import logging
from typing import List, Any, Dict

log = logging.getLogger(__name__)

def calculate_recall_at_k(retrieved_ids: List[Any], ground_truth_ids: List[Any], k: int) -> float:
    """Recall@K = (relevant retrieved in top K) / (total relevant)."""
    if not ground_truth_ids:
        return 0.0
    
    top_k_retrieved = set(retrieved_ids[:k])
    relevant_retrieved = top_k_retrieved.intersection(set(ground_truth_ids))
    return len(relevant_retrieved) / len(ground_truth_ids)


def calculate_precision_at_k(retrieved_ids: List[Any], ground_truth_ids: List[Any], k: int) -> float:
    """Precision@K = (relevant retrieved in top K) / K."""
    if k <= 0:
        return 0.0
    
    top_k_retrieved = set(retrieved_ids[:k])
    relevant_retrieved = top_k_retrieved.intersection(set(ground_truth_ids))
    return len(relevant_retrieved) / k


def calculate_mrr(retrieved_ids: List[Any], ground_truth_ids: List[Any]) -> float:
    """MRR = 1 / (rank of first relevant item)."""
    if not ground_truth_ids:
        return 0.0
    
    ground_truth_set = set(ground_truth_ids)
    for rank, item in enumerate(retrieved_ids, start=1):
        if item in ground_truth_set:
            return 1.0 / rank
    return 0.0


def evaluate_retrieval(
    retrieved_ids: List[Any],
    ground_truth_ids: List[Any],
    k: int = 5
) -> Dict[str, float]:
    """Calculates all RAG metrics for a retrieval run."""
    return {
        "recall_at_k": round(calculate_recall_at_k(retrieved_ids, ground_truth_ids, k), 4),
        "precision_at_k": round(calculate_precision_at_k(retrieved_ids, ground_truth_ids, k), 4),
        "mrr": round(calculate_mrr(retrieved_ids, ground_truth_ids), 4)
    }
