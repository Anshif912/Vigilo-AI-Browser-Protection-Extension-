import pandas as pd
import numpy as np

def solve():
    df = pd.read_csv('datasets/phiusiil/phishing_url.csv')
    
    # We will test a set of rows where the value is not 1.0
    subset = df[df['CharContinuationRate'] < 1.0].head(10)
    
    for idx, row in subset.iterrows():
        url = str(row['URL'])
        dom = str(row['Domain'])
        rate = float(row['CharContinuationRate'])
        
        # Let's count different transitions in dom
        # Type classification
        # Try different definitions of char type:
        # T1: alpha vs digit vs special
        # T2: alpha vs other
        # T3: alpha-digit vs other
        
        print(f"URL: {url:<40} | Domain: {dom:<30} | Rate: {rate:.8f}")
        
        # Let's see: for uni-mainz.de, rate is 2/3 (0.66666667)
        # for voicefmradio.co.uk, rate is 13/15 (0.86666667)
        # for ooty.ind.in, rate is 5/8 (0.625)
        # Let's look at the denominators: 3, 15, 8!
        # Where do 3, 15, 8 come from?
        # Let's inspect the lengths:
        # ooty.ind.in: ooty (4), ind (3), in (2). Total length of registered domain: 11.
        # Length of 'ooty.ind' is 8!
        # uni-mainz.de: uni-mainz (9), de (2). Total length of registered domain: 12.
        # Length of 'uni-mainz' is 9. Why is the denominator 3? Maybe 9/3 = 3?
        # voicefmradio.co.uk: voicefmradio (12), co (2), uk (2). Total length: 18.
        # Length of 'voicefmradio.co' is 15!
        
        # Look at that:
        # For ooty.ind.in: denominator 8 is the length of 'ooty.ind' (subdomain + domain)
        # For voicefmradio.co.uk: denominator 15 is the length of 'voicefmradio.co' (domain + 1st suffix)
        # For uni-mainz.de: denominator 3? Wait! uni-mainz has a hyphen.
        # Wait, if uni-mainz has a hyphen, the parts are 'uni' (3) and 'mainz' (5).
        # What if it's the average of the lengths of the parts?
        # Let's check!
        
if __name__ == "__main__":
    solve()
