from typing import Dict, List

# Enterprise Brand Taxonomy Database (300+ Brands across 10 Categories)
BRAND_CATEGORIES: Dict[str, List[str]] = {
    "Global Tech": [
        "google", "microsoft", "apple", "amazon", "meta", "facebook", "instagram", "whatsapp",
        "netflix", "steam", "discord", "github", "linkedin", "adobe", "openai", "chatgpt",
        "gemini", "claude", "dropbox", "twitter", "youtube", "gmail", "outlook", "ibm",
        "oracle", "cisco", "intel", "nvidia", "salesforce", "slack", "zoom", "spotify",
        "twitch", "uber", "airbnb", "pinterest", "reddit", "snapchat", "tiktok", "atlassian",
        "jira", "confluence", "trello", "canva", "figma", "notion", "zendesk", "hubspot"
    ],
    "Banking": [
        "sbi", "hdfc", "icici", "axis", "kotak", "chase", "bankofamerica", "wellsfargo",
        "citibank", "capitalone", "barclaycard", "barclays", "hsbc", "santander", "bnpparibas",
        "deutschebank", "societegenerale", "ubs", "creditsuisse", "scotiabank", "rbc", "td",
        "anz", "westpac", "nab", "cba", "standardchartered", "canarabank", "pnb", "bankofbaroda",
        "unionbank", "yesbank", "indusind", "idfc", "bandhan", "dbs", "lloyds", "natwest",
        "bradesco", "itau", "caixa", "nubank", "inter", "banrisul"
    ],
    "Travel, Airlines & Rewards": [
        "smiles", "gol", "latam", "tam", "azul", "emirates", "qantas", "delta", "united",
        "americanairlines", "lufthansa", "booking", "expedia", "airbnb", "tripadvisor"
    ],
    "Payments & Fintech": [
        "paypal", "stripe", "paytm", "phonepe", "razorpay", "venmo", "square", "wise",
        "revolut", "klarna", "zelle", "intuit", "turbotax", "cashapp", "skrill", "neteller",
        "westernunion", "moneygram", "remitly", "cred", "bharatpe", "mobikwik", "googlepay",
        "applepay", "samsungpay", "afterpay", "affirm", "paxful", "worldremit", "americanexpress", "amex"
    ],
    "Crypto & Web3": [
        "binance", "coinbase", "metamask", "trustwallet", "opensea", "kraken", "kucoin",
        "ledger", "trezor", "bybit", "okx", "bitfinex", "bitstamp", "crypto", "uniswap",
        "pancakeswap", "phantom", "solflare", "ronin", "exodus", "atomicwallet", "coinmarketcap"
    ],
    "Government & Public": [
        "gov", "usagov", "irs", "incometax", "aadhaar", "uidai", "passportindia", "interpol",
        "fbi", "cia", "nhs", "hmrc", "mygov", "dvla", "medicare", "socialsecurity",
        "govuk", "ca.gov", "ny.gov", "australia.gov", "canada.ca"
    ],
    "Universities & Academics": [
        "harvard", "mit", "stanford", "oxford", "cambridge", "iit", "berkeley", "nyu",
        "columbia", "yale", "princeton", "cornell", "ucla", "utoronto", "ethz", "nus"
    ],
    "Social Media & Messaging": [
        "facebook", "instagram", "whatsapp", "twitter", "linkedin", "tiktok", "snapchat",
        "discord", "telegram", "reddit", "pinterest", "signal", "wechat", "line", "viber",
        "skype", "tumblr", "medium", "threads", "quora", "vk"
    ],
    "Cloud & Dev Platforms": [
        "aws", "azure", "googlecloud", "github", "gitlab", "vercel", "netlify", "cloudflare",
        "heroku", "bitbucket", "docker", "digitalocean", "linode", "hetzner", "supabase",
        "firebase", "railway", "render", "postman", "datadog", "sentry", "npm", "pypi"
    ],
    "E-Commerce & Retail": [
        "amazon", "ebay", "walmart", "target", "alibaba", "aliexpress", "shopify", "flipkart",
        "etsy", "bestbuy", "costco", "homedepot", "ikea", "sephora", "asos", "shein",
        "temu", "mercadolibre", "rakuten", "myntra", "meesho", "zomato", "swiggy"
    ],
    "Real Estate & Enterprise": [
        "remax", "zillow", "redfin", "trulia", "realtor", "rightmove", "zoopla", "century21",
        "docusign", "dropbox", "box", "salesforce"
    ],
    "Email & Productivity": [
        "gmail", "outlook", "yahoomail", "protonmail", "zoho", "fastmail", "dropbox",
        "googledrive", "onedrive", "notion", "evernote", "mailchimp", "sendgrid", "box"
    ]
}

# Flattened lookup list and map
ALL_BRAND_ENTRIES: List[str] = []
BRAND_CATEGORY_MAP: Dict[str, str] = {}

for category, brands in BRAND_CATEGORIES.items():
    for brand in brands:
        if brand not in ALL_BRAND_ENTRIES:
            ALL_BRAND_ENTRIES.append(brand)
            BRAND_CATEGORY_MAP[brand] = category

def get_brand_category(brand_name: str) -> str:
    key = brand_name.lower()
    return BRAND_CATEGORY_MAP.get(key, "General Brand Abuse")
