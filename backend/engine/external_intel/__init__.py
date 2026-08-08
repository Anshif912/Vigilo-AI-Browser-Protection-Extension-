from engine.external_intel.virustotal import VirusTotalProvider
from engine.external_intel.safe_browsing import GoogleSafeBrowsingProvider
from engine.external_intel.openphish import OpenPhishProvider
from engine.external_intel.phishtank import PhishTankProvider
from engine.external_intel.urlhaus import URLhausProvider

EXTERNAL_INTEL_PROVIDERS = [
    VirusTotalProvider(),
    GoogleSafeBrowsingProvider(),
    OpenPhishProvider(),
    PhishTankProvider(),
    URLhausProvider()
]
