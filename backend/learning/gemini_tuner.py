import os
import time
import argparse
import logging
from .dataset_builder import DatasetBuilder

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Automated Gemini Fine-Tuning CLI")
    parser.add_argument("--api-key", type=str, help="Your Gemini API Key")
    parser.add_argument("--dataset", type=str, default="gemini_training_data.jsonl", help="Dataset filename")
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs")
    
    args = parser.parse_args()
    api_key = args.api_key or os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("ERROR: --api-key is required or GEMINI_API_KEY env var must be set.")
        return
        
    logging.basicConfig(level=logging.INFO)
    
    try:
        import google.generativeai as genai
    except ImportError as e:
        print(f"ERROR: google-generativeai SDK import failed. Details: {e}")
        import traceback
        traceback.print_exc()
        return
        
    genai.configure(api_key=api_key)
    
    # 1. Build the Dataset
    dataset_path = DatasetBuilder.build_gemini_tuning_dataset(args.dataset)
    
    # 2. Upload to Gemini Cloud
    logger.info(f"Uploading {dataset_path} to Gemini Cloud...")
    try:
        # We need to read the JSONL file and parse into the required list of dicts
        import json
        training_data = []
        with open(dataset_path, "r") as f:
            for line in f:
                if line.strip():
                    training_data.append(json.loads(line))
    except Exception as e:
        logger.error(f"Failed to read dataset: {e}")
        return

    logger.info(f"Starting Fine-Tuning Operation with {len(training_data)} samples...")
    try:
        # Create tuned model
        # Note: Gemini 1.5 Flash is the recommended model for text-tuning currently
        operation = genai.create_tuned_model(
            display_name="edysor-soc-v1",
            source_model="models/gemini-1.5-flash-001-tuning",
            epoch_count=args.epochs,
            batch_size=4,
            learning_rate=0.001,
            training_data=training_data,
        )
        
        logger.info(f"Tuning operation started. Job ID: {operation.name}")
        logger.info("Waiting for completion... This may take up to an hour depending on queue times.")
        
        # Poll status
        for status in operation.wait_bar():
            time.sleep(10)
            
        result = operation.result()
        logger.info("\n" + "="*50)
        logger.info(f"✅ FINE-TUNING SUCCESSFUL!")
        logger.info(f"New Model ID: {result.name}")
        logger.info(f"Update your .env file with: GEMINI_MODEL={result.name}")
        logger.info("="*50 + "\n")
        
    except Exception as e:
        logger.error(f"Fine-Tuning failed: {e}")

if __name__ == "__main__":
    main()
