import json
from multimodal.sandbox import MultimodalSandbox
from multimodal.pcap_parser import PCAPParser
from multimodal.memory_parser import MemoryParser

def test_multimodal_analysis():
    print("Testing PCAP Parser...")
    pcap_res = PCAPParser.parse_pcap("Sample PCAP summary with large outbound flows.")
    print(json.dumps(pcap_res, indent=2))
    
    print("\nTesting Memory Parser...")
    mem_res = MemoryParser.analyze_memory_dump({"volatility_profile": "Win10x64"})
    print(json.dumps(mem_res, indent=2))
    
    print("\nTesting Sandbox Analysis...")
    sand_res = MultimodalSandbox.analyze_executable({"filename": "invoice_updated.exe"})
    print(json.dumps(sand_res, indent=2))

if __name__ == "__main__":
    test_multimodal_analysis()
