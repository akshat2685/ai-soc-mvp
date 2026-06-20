import os
import json
import logging
from typing import List, Dict
import sys

# Add backend to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import get_db

logger = logging.getLogger(__name__)

class DatasetBuilder:
    """
    Exports historical Incidents and Analyst Feedback into the Gemini Fine-Tuning format.
    Format: {"text_input": prompt, "output": ideal_response}
    """
    
    @staticmethod
    def build_gemini_tuning_dataset(output_file: str = "gemini_training_data.jsonl"):
        logger.info(f"Extracting Ground Truth data for Gemini Tuning...")
        
        training_samples = []
        
        # 1. Fetch Incidents where analyst confirmed status (e.g. MALICIOUS or FALSE_POSITIVE)
        with get_db() as conn:
            # We assume 'status' indicates the analyst's final verdict (e.g. 'closed_true_positive')
            cur = conn.execute("SELECT * FROM incidents WHERE status LIKE 'closed_%' LIMIT 5000")
            incidents = cur.fetchall()
            
            for inc in incidents:
                inc_dict = dict(inc)
                
                # Construct the prompt exactly as it would look to the model during triage
                prompt = f"""You are a SOC analyst. Analyze this incident:
Title: {inc_dict.get('title')}
Severity: {inc_dict.get('severity')}
Evidence: {inc_dict.get('evidence_summary', '{}')}
Provide a concise analysis and recommended action."""

                # Construct the ideal response based on what the analyst actually did
                verdict = "MALICIOUS" if "true_positive" in inc_dict.get('status', '').lower() else "BENIGN"
                ideal_response = f"Analysis: {inc_dict.get('analyst_notes', 'Pattern matches known threat profile.')}\nVerdict: {verdict}"
                
                training_samples.append({
                    "text_input": prompt,
                    "output": ideal_response
                })
                
        # 2. Add some synthetic edge cases to balance the dataset
        from learning.synthetic_generator import SyntheticAttackGenerator
        synthetic = SyntheticAttackGenerator.generate_training_dataset(count=50)
        for syn in synthetic:
            prompt = f"You are a SOC analyst. Analyze this alert:\nEvent: {syn['event_type']}\nUser: {syn['user_id']}\nIP: {syn['source_ip']}"
            training_samples.append({
                "text_input": prompt,
                "output": f"Analysis: Simulated {syn['attack_type']} attack.\nVerdict: MALICIOUS"
            })
            
        # Write to JSONL
        out_path = os.path.join(os.path.dirname(__file__), "..", "data", output_file)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        
        with open(out_path, "w") as f:
            for sample in training_samples:
                f.write(json.dumps(sample) + "\n")
                
        logger.info(f"Successfully exported {len(training_samples)} tuning samples to {out_path}")
        return out_path

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    DatasetBuilder.build_gemini_tuning_dataset()
