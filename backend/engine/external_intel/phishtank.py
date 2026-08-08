import os
from typing import Dict, Any, Optional
from engine.external_intel.base import BaseExternalIntelProvider

class PhishTankProvider(BaseExternalIntelProvider):
    name = "PhishTank"

    async def check_url(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        return None
