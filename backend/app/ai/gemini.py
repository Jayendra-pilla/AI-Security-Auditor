import logging
import json
import time
import httpx
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)

class GeminiClient:
    """
    Client for interacting with Google Gemini API models via REST API.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = 10.0):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.timeout = timeout
        self.model = settings.GEMINI_MODEL
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    def analyze_vulnerabilities(self, prompt: str) -> Dict[str, Any]:
        """
        Sends the analysis prompt to the Gemini API and returns the parsed JSON response.
        Raises an exception if the API key is missing, a timeout occurs, or the API fails.
        """
        if not self.api_key or self.api_key == "your-gemini-api-key":
            logger.error("Gemini API key is missing or not configured.")
            raise ValueError("GEMINI_API_KEY is missing")

        headers = {"Content-Type": "application/json"}
        params = {"key": self.api_key}
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }

        logger.info(f"Sending prompt to Gemini API at {self.url} (timeout={self.timeout}s)...")
        
        max_retries = 3
        backoff = 1.0

        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(self.url, json=payload, headers=headers, params=params)
                    
                    if response.status_code in [429, 500, 502, 503, 504]:
                        if attempt < max_retries - 1:
                            logger.warning(f"Gemini API returned transient status {response.status_code}. Retrying in {backoff}s...")
                            time.sleep(backoff)
                            backoff *= 2.0
                            continue
                    
                    response.raise_for_status()
                    response_json = response.json()
                    
                    # Extract response text
                    text = response_json["candidates"][0]["content"]["parts"][0]["text"]
                    logger.info("Successfully received response from Gemini API.")
                    
                    parsed = json.loads(text)
                    if not isinstance(parsed, dict):
                        raise ValueError("Gemini returned invalid non-dictionary JSON structure")
                    return parsed
                    
            except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                exc_str = str(exc).replace(self.api_key, "***REDACTED***") if self.api_key else str(exc)
                if attempt < max_retries - 1:
                    logger.warning(f"Gemini client encountered transient issue: {exc_str}. Retrying in {backoff}s...")
                    time.sleep(backoff)
                    backoff *= 2.0
                else:
                    logger.error(f"Gemini client reached max retries. Error: {exc_str}")
                    raise Exception(f"Gemini API Error: {exc_str}") from None
            except Exception as e:
                e_str = str(e).replace(self.api_key, "***REDACTED***") if self.api_key else str(e)
                logger.error(f"Unexpected error during Gemini API call: {e_str}")
                raise Exception(f"Unexpected Gemini API error: {e_str}") from None

