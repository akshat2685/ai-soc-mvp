import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.evaluation.rag_evaluator import calculate_recall_at_k, calculate_precision_at_k, calculate_mrr, evaluate_retrieval
from backend.evaluation.agent_evaluator import evaluate_agent_run, evaluate_consistency
from backend.evaluation.llm_evaluator import evaluate_llm_quality
from backend.evaluation.detection_evaluator import calculate_detection_metrics

class TestEvaluator(unittest.TestCase):
    
    def test_rag_metrics(self):
        # Retrieved items: AST1, AST2, AST3, AST4, AST5
        # Ground truth: AST3, AST5, AST9
        retrieved = ["AST1", "AST2", "AST3", "AST4", "AST5"]
        ground_truth = ["AST3", "AST5", "AST9"]
        
        # Test Recall@K (top 5 retrieved)
        # Top 5 retrieved contains AST3, AST5 (2 out of 3 total relevant items)
        recall = calculate_recall_at_k(retrieved, ground_truth, k=5)
        self.assertAlmostEqual(recall, 2/3)
        
        # Test Precision@K (top 3 retrieved)
        # Top 3 retrieved contains AST3 (1 out of 3 retrieved items)
        precision = calculate_precision_at_k(retrieved, ground_truth, k=3)
        self.assertAlmostEqual(precision, 1/3)
        
        # Test MRR
        # AST3 is the first relevant item, retrieved at index 2 (rank 3)
        mrr = calculate_mrr(retrieved, ground_truth)
        self.assertAlmostEqual(mrr, 1/3)

    @patch('backend.evaluation.agent_evaluator._call_llm')
    def test_agent_evaluator_judge(self, mock_llm):
        mock_llm.return_value = '{"task_success": 0.9, "correctness": 0.8, "explanation": "Good execution."}'
        
        res = evaluate_agent_run("Triage the alert", "Agent triaged the alert successfully.")
        self.assertEqual(res["task_success"], 0.9)
        self.assertEqual(res["correctness"], 0.8)
        self.assertEqual(res["explanation"], "Good execution.")

    @patch('backend.evaluation.llm_evaluator._call_llm')
    def test_llm_evaluator_judge(self, mock_llm):
        mock_llm.return_value = '{"grounding_score": 0.95, "hallucination_score": 0.05, "factuality_score": 0.9, "reasoning": "Accurate output."}'
        
        res = evaluate_llm_quality("The attacker IP is 8.8.8.8", "Attacker IP was verified as 8.8.8.8")
        self.assertEqual(res["grounding_score"], 0.95)
        self.assertEqual(res["hallucination_score"], 0.05)
        self.assertEqual(res["factuality_score"], 0.9)
        
    def test_detection_metrics(self):
        # TP=80, FP=20, FN=10, TN=90
        # Precision = 80 / 100 = 0.8
        # Recall = 80 / 90 = 0.8889
        metrics = calculate_detection_metrics(tp=80, fp=20, fn=10, tn=90)
        self.assertEqual(metrics["precision"], 0.8)
        self.assertAlmostEqual(metrics["recall"], 0.8889)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.1818, places=4)

if __name__ == "__main__":
    unittest.main()
