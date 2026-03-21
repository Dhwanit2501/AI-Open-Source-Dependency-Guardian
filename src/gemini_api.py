import os
import requests
from dotenv import load_dotenv
import streamlit as st

# If running locally and have API key in .env
#Comment the next 2 lines and uncomment the streamlit secrets line
load_dotenv()
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# If you have API key stored in Streamlit Secrets

#GEMINI_API_KEY = st.secrets["GEMINI_API_KEY"]

GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent'

def call_gemini(prompt):
    if not GEMINI_API_KEY:
        return "Gemini API key not found. Please set GEMINI_API_KEY in your .env file."
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY
    }
    data = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    try:
        response = requests.post(GEMINI_API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        return f"Gemini API error: {e}"
