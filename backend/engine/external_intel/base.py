import os
from typing import Dict, Any, Optional

class BaseExternalIntelProvider:
    name: str = "BaseProvider"
    enabled: bool = True

    async def check_url(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Subclasses implement async threat lookup.
        Must return None or dict with keys: 'matched', 'score', 'threat_type', 'details'.
        """
        raise NotImplementedError
