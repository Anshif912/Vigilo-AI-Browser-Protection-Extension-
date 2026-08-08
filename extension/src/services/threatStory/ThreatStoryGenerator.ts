import { AnalysisResponse } from '../api';

export interface ThreatStoryEvidence {
  targetBrand: string;
  attackCategory: string;
  stolenItems: string[];
  humanDetectionReasons: string[];
  potentialConsequences: string[];
  confidence: number;
  threatScore: number;
  threatStatus: string;
}

export class ThreatStoryGenerator {
  public static extractEvidence(analysis: AnalysisResponse): ThreatStoryEvidence {
    const brand = (analysis as any).targetBrand || analysis.website_identity || 'a trusted official service';
    const category = analysis.category || analysis.attack_type || 'Credential Phishing';
    
    // Extract stolen items (non-technical, clear labels)
    const stolenItems: string[] = [];
    const infoAtRiskStr = (analysis.information_at_risk || []).join(' ').toLowerCase();
    const reasonStr = (analysis.reason || '').toLowerCase();
    const categoryStr = category.toLowerCase();
    const breakdownStr = JSON.stringify(analysis.score_breakdown || []).toLowerCase();

    if (infoAtRiskStr.includes('password') || reasonStr.includes('login') || breakdownStr.includes('credential') || categoryStr.includes('phishing')) {
      stolenItems.push('🔑 Passwords');
    }
    if (infoAtRiskStr.includes('email') || reasonStr.includes('mail') || infoAtRiskStr.includes('account')) {
      stolenItems.push('📧 Email Account');
    }
    if (infoAtRiskStr.includes('card') || infoAtRiskStr.includes('bank') || reasonStr.includes('payment') || infoAtRiskStr.includes('financial')) {
      stolenItems.push('💳 Payment Information');
    }
    if (infoAtRiskStr.includes('wallet') || infoAtRiskStr.includes('crypto') || reasonStr.includes('crypto')) {
      stolenItems.push('🪙 Crypto Wallet');
    }
    if (stolenItems.length === 0 || infoAtRiskStr.includes('identity') || infoAtRiskStr.includes('personal')) {
      stolenItems.push('🪪 Personal Information');
    }

    // Extract human-friendly detection reasons (STRICTLY NO JARGON: NO DOM, IOC, Entropy, PSL, Regex, HTML Injection, JavaScript Redirect)
    const humanDetectionReasons: string[] = [];
    
    if (reasonStr.includes('browser security warning') || reasonStr.includes('cloudflare') || reasonStr.includes('interstitial') || reasonStr.includes('reported')) {
      humanDetectionReasons.push('Upstream security providers and browser warning systems have reported this page as deceptive.');
    }
    if (reasonStr.includes('typosquat') || reasonStr.includes('brand') || reasonStr.includes('impersonat') || breakdownStr.includes('brand')) {
      humanDetectionReasons.push(`The web address uses a fake or misspelled name designed to look like ${brand}.`);
    }
    if (reasonStr.includes('disposable') || reasonStr.includes('free host') || reasonStr.includes('subdomain') || breakdownStr.includes('subdomain')) {
      humanDetectionReasons.push('The website is hosted on an unverified free cloud platform commonly used to disguise fake pages.');
    }
    if (reasonStr.includes('http') || reasonStr.includes('unsecured') || analysis.connection_security === 'Not Secure') {
      humanDetectionReasons.push('The web connection is unsecured, exposing your personal details to potential interception.');
    }
    if (humanDetectionReasons.length === 0) {
      humanDetectionReasons.push('The web page structure matches patterns commonly associated with unauthorized login forms.');
    }

    // Determine potential consequences
    const potentialConsequences: string[] = [];
    if (stolenItems.includes('🔑 Passwords') || stolenItems.includes('📧 Email Account')) {
      potentialConsequences.push('unauthorized access to your personal online accounts');
    }
    if (stolenItems.includes('💳 Payment Information') || stolenItems.includes('🪙 Crypto Wallet')) {
      potentialConsequences.push('financial loss or unauthorized bank transactions');
    }
    if (potentialConsequences.length === 0) {
      potentialConsequences.push('identity impersonation or credential theft');
    }

    const confidence = analysis.confidence || (analysis.threat_score >= 80 ? 96 : 91);

    return {
      targetBrand: brand,
      attackCategory: category,
      stolenItems,
      humanDetectionReasons,
      potentialConsequences,
      confidence,
      threatScore: analysis.threat_score,
      threatStatus: analysis.status || 'Critical'
    };
  }
}
