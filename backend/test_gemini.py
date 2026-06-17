import os
from dotenv import load_dotenv
load_dotenv()

key = os.environ.get("GEMINI_API_KEY")
print("Key exists:", bool(key))
if key:
    print("Key starts with:", key[:5])
    try:
        import google.generativeai as genai
        genai.configure(api_key=key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        res = model.generate_content("Say hello")
        print("Gemini says:", res.text)
    except Exception as e:
        print("Gemini error:", e)
