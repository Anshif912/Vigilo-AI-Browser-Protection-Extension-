import os
import aiohttp
from typing import Dict, Any, Optional
from engine.external_intel.base import BaseExternalIntelProvider

class VirusTotalProvider(BaseExternalIntelProvider):
    name = "VirusTotal"

    def __init__(self):
        self.api_key = os.environ.get("VIGILO_VT_API_KEY", "").strip()
        self.enabled = bool(self.api_key)

    async def check_url(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        try:
            # Async VirusTotal lookup with strict 1.0s timeout
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1.0)) as session:
                headers = {"x-apikey": self.api_key}
                async with session.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        if malicious > 0 or suspicious > 0:
                            return {
                                "matched": True,
                                "score": min(malicious * 15 + suspicious * 10, 50),
                                "threat_type": "VirusTotal Malicious Flag",
                                "details": f"VirusTotal flagged {domain} across {malicious} security vendors."
                            }
        except Exception:
            pass

        return None
