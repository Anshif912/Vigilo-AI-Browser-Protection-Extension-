import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
import json
from services.url_analyzer import UniversalURLAnalyzer

top_100_urls = [
    "00000000000000000000000000000000000000000.xyz",
    "00000000000000000000000000000000000000dfjjjhv.000webhostapp.com",
    "0000000000000000000000000.findyourjacket.com",
    "00000000000000000000000056000005-102299.weeblysite.com",
    "00000000000000000gg.000webhostapp.com",
    "00000000000000000update.emy.ba",
    "000000000000000ooooo.000webhostapp.com",
    "000-00-000-000000.pages.dev",
    "0000000000c0.x9xcax2a.workers.dev",
    "000000000a0uutlook.weebly.com",
    "00000000920.us-south.cf.appdomain.cloud",
    "0000000095.godaddysites.com",
    "00000002.c1.biz",
    "0000000666666.000webhostapp.com",
    "0000000o.weebly.com",
    "0000000wer.000webhostapp.com",
    "000000541840000.co.vu",
    "0000006738.vercel.app",
    "000000788-66666666.000webhostapp.com",
    "00000078uu7u8790090900.000webhostapp.com",
    "000000login.weebly.com",
    "000001010010104106.cloud",
    "000002456171.ml",
    "000002456180.ml",
    "000003.000000000013.repl.co",
    "0000091193.xyz",
    "00000--bancogeneral3.repl.co",
    "00000f.nuevaconfirma.repl.co",
    "00000microsof.tonohost.com",
    "00000wefv.000webhostapp.com",
    "00001062.com",
    "000012151000.co.vu",
    "000012223.weebly.com",
    "00001-888887766.weebly.com",
    "0000-1t8.pages.dev",
    "000025123.com",
    "00003.godaddysites.com",
    "0000666688887777.000webhostapp.com",
    "000066.godaddysites.com",
    "000083.godaddysites.com",
    "00008.godaddysites.com",
    "0000bbffxzzzz900.000webhostapp.com",
    "0000.com.my",
    "0.0.0.0forum.cryptonight.net",
    "0000guatec.davieelchirinos.repl.co",
    "0000h00003.byethost7.com",
    "0000.hopto.org",
    "0.0.0.0mailgate.cryptonight.net",
    "0000mscautorizationclientid.com",
    "0.0.0.0ns10.cryptonight.net",
    "0000qwew341432edxzt.000webhostapp.com",
    "0.0.0.0ssl.cryptonight.net",
    "0000wa0outlook.weebly.com",
    "00010xsea34dsd.co.vu",
    "000111.pages.net.br",
    "00012sbcglobal.weebly.com",
    "000133210.000webhostapp.com",
    "0001.353527440.workers.dev",
    "000193.azurewebsites.net",
    "0001home.webflow.io",
    "0001qwis.webflow.io",
    "000220.000webhostapp.com",
    "000247aa8f117a13af2094b691ab1b3e.serveo.net",
    "0002-i-nastolatek-to-przegrales-zycie-i-to-z-kretesem.fun",
    "00030ae9.qepfmq.shop",
    "000343594567126312342754pgsbsnsswrng.000webhostapp.com",
    "0005tecnicoasistente.000webhostapp.com",
    "000667993.codepen.website",
    "000690750.deployed.codepen.website",
    "0006.mediafirew.xyz",
    "0006.uk",
    "000717-coinbase.com",
    "0007854.atwebpages.com",
    "0007933738373.myportfolio.com",
    "000-7yt65t564656ythygy.000webhostapp.com",
    "000811893962007154932393170597959432.hanefra7bikiemta.com",
    "000838774343.000webhostapp.com",
    "00099881111.000webhostapp.com",
    "0009aak.pages.dev",
    "000.abreubueno91.repl.co",
    "000agreementmail.weebly.com",
    "0.0.0assets.cryptonight.net",
    "000cc-ed5446.pages.dev",
    "000ccee008762200ccceecc.pages.dev",
    "000chgojhd78jhvbwreuvk.webnode.com",
    "000codashoppfreee-771.duckdns.org",
    "0.0.0dbs.cryptonight.net",
    "000e-239f-23ea3-yah100-8ta1xb1rs33.netlify.app",
    "000f9e-48.myshopify.com",
    "000ficohs99onli22.125mb.com",
    "0.0.0fileserver.cryptonight.net",
    "000ind002.webflow.io",
    "000int-5403945int.xyz",
    "000itkw.lfd.myj.mybluehost.me",
    "000jbjdvvdhjvbdjvndvdv.s3.us-east-2.amazonaws.com",
    "000l34e.wcomhost.com",
    "000l.weebly.com",
    "000m8ih.wcomhost.com",
    "0.0.0mail3.cryptonight.net",
    "000mclogin.micloud-object-storage-xc-cos-static-web-hosting-qny.s3.us-east.cloud-object-storage.appdomain.cloud"
]

results = []
correctly_detected = 0
false_negatives = 0
false_positives = 0

for i, raw_url in enumerate(top_100_urls, 1):
    res = UniversalURLAnalyzer.analyze_url(raw_url)
    
    # Determine independent verdict based on URL patterns & threat intel rules
    # Any free hosting provider (000webhostapp, weebly, pages.dev, workers.dev, repl.co, godaddysites, etc.) with obfuscated/numeric subdomains or brand typos (outlook, coinbase, micloud, microsof) is independently malicious/suspicious.
    is_phishing = False
    reasons = []
    
    url_lower = raw_url.lower()
    
    # Signals for independent analysis:
    if any(host in url_lower for host in ["000webhostapp.com", "weebly.com", "weeblysite.com", "pages.dev", "workers.dev", "repl.co", "godaddysites.com", "atwebpages.com", "webflow.io", "netlify.app", "duckdns.org", "appdomain.cloud", "s3.us-", "s3.ap-"]):
        is_phishing = True
        reasons.append("Hosted on free/disposable cloud platform commonly abused for phishing")
        
    if any(brand in url_lower for brand in ["outlook", "microsof", "coinbase", "sbcglobal", "bancogeneral", "ficohs", "yah100", "codashop", "micloud", "agreementmail"]):
        is_phishing = True
        reasons.append("Contains brand keywords or brand typosquatting")
        
    if "0000" in url_lower or len(url_lower.split(".")[0]) > 25:
        is_phishing = True
        reasons.append("Extreme zero-padding or excessive subdomain obfuscation")

    independent_verdict = "Critical / High Risk" if is_phishing else "Safe"
    vigilo_verdict = f"{res.status} ({res.threat_score}/100)"
    
    is_match = (is_phishing and res.threat_score >= 40) or (not is_phishing and res.threat_score < 40)
    
    if is_match:
        correctly_detected += 1
    elif is_phishing and res.threat_score < 40:
        false_negatives += 1
    elif not is_phishing and res.threat_score >= 40:
        false_positives += 1
        
    results.append({
        "index": i,
        "url": raw_url,
        "independent_verdict": independent_verdict,
        "vigilo_status": res.status,
        "vigilo_score": res.threat_score,
        "category": res.category,
        "matched_rules_count": len(res.score_breakdown),
        "is_match": is_match,
        "reasons": reasons
    })

print(json.dumps({
    "total_evaluated": len(top_100_urls),
    "correctly_detected": correctly_detected,
    "false_negatives": false_negatives,
    "false_positives": false_positives,
    "accuracy_pct": round((correctly_detected / len(top_100_urls)) * 100, 2),
    "details": results
}, indent=2))
