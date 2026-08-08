import os
import aiohttp
from typing import Dict, Any, Optional
from engine.external_intel.base import BaseExternalIntelProvider

class GoogleSafeBrowsingProvider(BaseExternalIntelProvider):
    name = "GoogleSafeBrowsing"

    def __init__(self):
        self.api_key = os.environ.get("VIGILO_SAFE_BROWSING_API_KEY", "").strip()
        self.enabled = bool(self.api_key)

    async def check_url(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
            payload = {
                "client": {"clientId": "vigilo-security", "clientVersion": "4.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1.0)) as session:
                async with session.post(endpoint, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        matches = data.get("matches", [])
                        if matches:
                            threat = matches[0].get("threatType", "SOCIAL_ENGINEERING")
                            return {
                                "matched": True,
                                "score": 40,
                                "threat_type": f"Google Safe Browsing {threat}",
                                "details": f"Upstream Google Safe Browsing identified {url} as {threat}."
                            }
        except Exception:
            pass

        return None
