export type LanguageCode = 'en' | 'ta' | 'hi' | 'kn' | 'te' | 'ml';

export interface TranslationDictionary {
  attackPrevented: string;
  guardianActive: string;
  threatLevel: string;
  threatScore: string;
  targetBrand: string;
  attackPurpose: string;
  whyBlocked: string;
  infoAtRisk: string;
  aiExplanation: string;
  recommendations: string;
  socSummary: string;
  goBack: string;
  continueAnyway: string;
  exportJson: string;
  exportPdf: string;
  ruleCoverage: string;
  confidence: string;
  connectionSecurity: string;
  safeStatus: string;
  lowRiskStatus: string;
  suspiciousStatus: string;
  highRiskStatus: string;
  criticalStatus: string;
  threatStoryTitle: string;
  potentialImpact: string;
  confidenceBadge: string;
}

export const translations: Record<LanguageCode, TranslationDictionary> = {
  en: {
    attackPrevented: "ATTACK PREVENTED",
    guardianActive: "GUARDIAN ACTIVE",
    threatLevel: "Threat Level",
    threatScore: "Threat Score",
    targetBrand: "Pretending to be",
    attackPurpose: "Attack Purpose",
    whyBlocked: "Why Was This Blocked?",
    infoAtRisk: "Potential Information At Risk",
    aiExplanation: "AI THREAT EXPLANATION SUMMARY",
    recommendations: "Actionable AI Recommendations",
    socSummary: "SOC Analyst Decision Summary",
    goBack: "Go Back to Safety",
    continueAnyway: "Proceed Anyway (Unsafe)",
    exportJson: "Export JSON Report",
    exportPdf: "Export PDF Report",
    ruleCoverage: "Rule Coverage",
    confidence: "AI Confidence Engine",
    connectionSecurity: "Connection Security",
    safeStatus: "Safe",
    lowRiskStatus: "Low Risk",
    suspiciousStatus: "Suspicious",
    highRiskStatus: "High Risk",
    criticalStatus: "Critical",
    threatStoryTitle: "🧠 Threat Story",
    potentialImpact: "Potential Impact",
    confidenceBadge: "Confidence"
  },
  ta: {
    attackPrevented: "தாக்குதல் தடுக்கப்பட்டது",
    guardianActive: "பாதுகாவலர் செயலில் உள்ளார்",
    threatLevel: "அச்சுறுத்தல் நிலை",
    threatScore: "அச்சுறுத்தல் புள்ளி",
    targetBrand: "போலியாக நடிக்கும் நிறுவனம்",
    attackPurpose: "தாக்குதலின் நோக்கம்",
    whyBlocked: "இது ஏன் தடுக்கப்பட்டது?",
    infoAtRisk: "ஆபத்தில் உள்ள தகவல்கள்",
    aiExplanation: "AI அச்சுறுத்தல் விளக்க சுருக்கம்",
    recommendations: "பரிந்துரைக்கப்பட்ட நடவடிக்கைகள்",
    socSummary: "SOC பகுப்பாய்வாளர் முடிவு",
    goBack: "பாதுகாப்பான இடத்திற்குச் செல்",
    continueAnyway: "தொடர்ந்து செல் (ஆபத்தானது)",
    exportJson: "JSON அறிக்கையை பதிவிறக்கு",
    exportPdf: "PDF அறிக்கையை பதிவிறக்கு",
    ruleCoverage: "விதிகளின் பாதுகாப்பு எல்லை",
    confidence: "AI நம்பிக்கை நிலை",
    connectionSecurity: "இணைப்பு பாதுகாப்பு",
    safeStatus: "பாதுகாப்பானது",
    lowRiskStatus: "குறைந்த அபாயம்",
    suspiciousStatus: "சந்தேகத்திற்குரியது",
    highRiskStatus: "அதிக அபாயம்",
    criticalStatus: "மிகவும் ஆபத்தானது",
    threatStoryTitle: "🧠 அச்சுறுத்தல் கதை",
    potentialImpact: "சாத்தியமான பாதிப்பு",
    confidenceBadge: "நம்பிக்கை நிலை"
  },
  hi: {
    attackPrevented: "हमला रोका गया",
    guardianActive: "सुरक्षा सक्रिय है",
    threatLevel: "खतरे का स्तर",
    threatScore: "खतरा स्कोर",
    targetBrand: "नकली पहचान",
    attackPurpose: "हमले का उद्देश्य",
    whyBlocked: "इसे क्यों ब्लॉक किया गया?",
    infoAtRisk: "जोखिम में संभावित जानकारी",
    aiExplanation: "एआई खतरा स्पष्टीकरण सारांश",
    recommendations: "कार्रवाई योग्य सिफारिशें",
    socSummary: "एसओसी विश्लेषक निर्णय सारांश",
    goBack: "सुरक्षित स्थान पर लौटें",
    continueAnyway: "फिर भी आगे बढ़ें (असुरक्षित)",
    exportJson: "JSON रिपोर्ट निर्यात करें",
    exportPdf: "PDF रिपोर्ट निर्यात करें",
    ruleCoverage: "नियम कवरेज",
    confidence: "एआई आत्मविश्वास इंजन",
    connectionSecurity: "कनेक्शन सुरक्षा",
    safeStatus: "सुरक्षित",
    lowRiskStatus: "कम जोखिम",
    suspiciousStatus: "संदिग्ध",
    highRiskStatus: "उच्च जोखिम",
    criticalStatus: "गंभीर",
    threatStoryTitle: "🧠 खतरा कहानी",
    potentialImpact: "संभावित प्रभाव",
    confidenceBadge: "आत्मविश्वास"
  },
  kn: {
    attackPrevented: "ದಾಳಿಯನ್ನು ತಡೆಯಲಾಗಿದೆ",
    guardianActive: "ರಕ್ಷಣೆ ಸಕ್ರಿಯವಾಗಿದೆ",
    threatLevel: "ಅಪಾಯದ ಮಟ್ಟ",
    threatScore: "ಅಪಾಯದ ಅಂಕಗಳು",
    targetBrand: "ನಕಲಿ ಸಂಸ್ಥೆ",
    attackPurpose: "ದಾಳಿಯ ಉದ್ದೇಶ",
    whyBlocked: "ಇದನ್ನು ಏಕೆ ತಡೆಯಲಾಗಿದೆ?",
    infoAtRisk: "ಅಪಾಯದಲ್ಲಿರುವ ಮಾಹಿತಿ",
    aiExplanation: "AI ಅಪಾಯ ವಿವರಣೆ ಸಾರಾಂಶ",
    recommendations: "ಶಿಫಾರಸು ಮಾಡಿದ ಕ್ರಮಗಳು",
    socSummary: "SOC ವಿಶ್ಲೇಷಕರ ನಿರ್ಧಾರ",
    goBack: "ಸುರಕ್ಷಿತವಾಗಿ ಹಿಂತಿರುಗಿ",
    continueAnyway: "ಮುಂದುವರಿಯಿರಿ (ಅಸುರಕ್ಷಿತ)",
    exportJson: "JSON ವರದಿ ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ",
    exportPdf: "PDF ವರದಿ ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ",
    ruleCoverage: "ನಿಯಮಗಳ ರಕ್ಷಣಾ ವ್ಯಾಪ್ತಿ",
    confidence: "AI ಆತ್ಮವಿಶ್ವಾಸದ ಮಟ್ಟ",
    connectionSecurity: "ಸಂಪರ್ಕ ಸುರಕ್ಷತೆ",
    safeStatus: "ಸುರಕ್ಷಿತ",
    lowRiskStatus: "ಕಡಿಮೆ ಅಪಾಯ",
    suspiciousStatus: "ಸಂದೇಹಾಸ್ಪದ",
    highRiskStatus: "ಹೆಚ್ಚಿನ ಅಪಾಯ",
    criticalStatus: "ಅತ್ಯಂತ ಅಪಾಯಕಾರಿ",
    threatStoryTitle: "🧠 ಅಪಾಯದ ಕಥೆ",
    potentialImpact: "ಸಂಭಾವ್ಯ ಪರಿಣಾಮ",
    confidenceBadge: "ಆತ್ಮವಿಶ್ವಾಸ"
  },
  te: {
    attackPrevented: "దాడి నిరోధించబడింది",
    guardianActive: "రక్షణ చురుగ్గా ఉంది",
    threatLevel: "ప్రమాద స్థాయి",
    threatScore: "ప్రమాద స్కోరు",
    targetBrand: "నకిలీ సంస్థ",
    attackPurpose: "దాడి యొక్క ఉద్దేశ్యం",
    whyBlocked: "ఇది ఎందుకు నిరోధించబడింది?",
    infoAtRisk: "ప్రమాదంలో ఉన్న సమాచారం",
    aiExplanation: "AI ప్రమాద వివరణ సారాంశం",
    recommendations: "సిఫార్సు చేయబడిన చర్యలు",
    socSummary: "SOC విశ్లేషకుడి నిర్ణయం",
    goBack: "సురక్షిత ప్రాంతానికి వెళ్ళండి",
    continueAnyway: "అయినా కొనసాగించండి (అసురక్షితం)",
    exportJson: "JSON నివేదికను డౌన్‌లోడ్ చేయండి",
    exportPdf: "PDF నివేదికను డౌన్‌లోడ్ చేయండి",
    ruleCoverage: "నియమాల రక్షణ పరిధి",
    confidence: "AI విశ్వసనీయత స్థాయి",
    connectionSecurity: "కనెక్షన్ భద్రత",
    safeStatus: "సురక్షితం",
    lowRiskStatus: "తక్కువ ప్రమాదం",
    suspiciousStatus: "సందేహాస్పదం",
    highRiskStatus: "అధిక ప్రమాదం",
    criticalStatus: "అత్యంత ప్రమాదకరం",
    threatStoryTitle: "🧠 ప్రమాద కథ",
    potentialImpact: "సాధ్యమయ్యే ప్రభావం",
    confidenceBadge: "విశ్వసనీయత"
  },
  ml: {
    attackPrevented: "ആക്രമണം തടഞ്ഞു",
    guardianActive: "സുരക്ഷ സജീവമാണ്",
    threatLevel: "ഭീഷണി നില",
    threatScore: "ഭീഷണി സ്കോർ",
    targetBrand: "വ്യാജ സ്ഥാപനം",
    attackPurpose: "ആക്രമണ ലക്ഷ്യം",
    whyBlocked: "ഇത് എന്തുകൊണ്ട് തടഞ്ഞു?",
    infoAtRisk: "അപകടസാധ്യതയുള്ള വിവരങ്ങൾ",
    aiExplanation: "AI ഭീഷണി വിശദീകരണ സംഗ്രഹം",
    recommendations: "നിർദ്ദേശിച്ച നടപടികൾ",
    socSummary: "SOC വിശകലന വിദഗ്ദ്ധന്റെ തീരുമാനം",
    goBack: "സുരക്ഷിത സ്ഥാനത്തേക്ക് മടങ്ങുക",
    continueAnyway: "മുന്നോട്ട് പോവുക (അപകടകരം)",
    exportJson: "JSON റിപ്പോർട്ട് ഡൗൺലോഡ് ചെയ്യുക",
    exportPdf: "PDF റിപ്പോർട്ട് ഡൗൺലോഡ് ചെയ്യുക",
    ruleCoverage: "നിയമ പരിരക്ഷാ വ്യാപ്തി",
    confidence: "AI ആത്മവിശ്വാസ നില",
    connectionSecurity: "കണക്ഷൻ സുരക്ഷ",
    safeStatus: "സുരക്ഷിതം",
    lowRiskStatus: "കുറഞ്ഞ അപകടസാധ്യത",
    suspiciousStatus: "സംശയകരം",
    highRiskStatus: "ഉയർന്ന അപകടസാധ്യത",
    criticalStatus: "വളരെ അപകടകരം",
    threatStoryTitle: "🧠 ഭീഷണി കഥ",
    potentialImpact: "സാധ്യമായ ആഘാതം",
    confidenceBadge: "ആത്മവിശ്വാസം"
  }
};

export function getTranslation(lang: LanguageCode): TranslationDictionary {
  return translations[lang] || translations.en;
}

export function detectBrowserLanguage(): LanguageCode {
  if (typeof navigator === 'undefined') return 'en';
  const lang = (navigator.language || 'en').toLowerCase();
  if (lang.startsWith('ta')) return 'ta';
  if (lang.startsWith('hi')) return 'hi';
  if (lang.startsWith('kn')) return 'kn';
  if (lang.startsWith('te')) return 'te';
  if (lang.startsWith('ml')) return 'ml';
  return 'en';
}
