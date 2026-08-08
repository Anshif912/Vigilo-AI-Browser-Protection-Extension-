import { ThreatStoryEvidence } from './ThreatStoryGenerator';
import { LanguageCode } from '../../i18n/locales';

export interface ThreatStoryFormatted {
  storyText: string;
  storyPoints: string[];
  impactItems: string[];
  confidence: number;
}

export class ThreatStoryFormatter {
  private static sanitizeJargon(text: string): string {
    return text
      .replace(/\bDOM\b/gi, 'web page structure')
      .replace(/\bIOC\b/gi, 'threat indicators')
      .replace(/\bEntropy\b/gi, 'randomness')
      .replace(/\bPSL\b/gi, 'domain registry')
      .replace(/\bRegex\b/gi, 'pattern matching')
      .replace(/\bHTML Injection\b/gi, 'page manipulation')
      .replace(/\bJavaScript Redirect\b/gi, 'automatic web page redirection');
  }

  public static formatStory(evidence: ThreatStoryEvidence, lang: LanguageCode): ThreatStoryFormatted {
    const brand = evidence.targetBrand;
    const stolenStr = evidence.stolenItems.map(i => i.replace(/^[^\s]+\s+/, '')).join(' and ');
    const reasonText = evidence.humanDetectionReasons.join(' ');
    const consequenceText = evidence.potentialConsequences.join(' or ');

    let storyPoints: string[] = [];

    switch (lang) {
      case 'ta':
        storyPoints = [
          `போலி நிறுவனம்: இந்த இணையதளம் ${brand} போல நடித்து உங்களை ஏமாற்ற முயல்கிறது.`,
          `இலக்கு தகவல்கள்: உங்களின் ${stolenStr} போன்ற ரகசியத் தகவல்களைப் பெற முயற்சிக்கிறது.`,
          `கண்டறிந்த காரணம்: ${reasonText}`,
          `சாத்தியமான ஆபத்து: தொடர்வது உங்கள் கணக்குகளில் ${consequenceText} வழிவகுக்கும்.`,
          `பாதுகாப்பு நடவடிக்கை: உங்களின் தகவல்கள் சோர்வதற்கு முன்பே Vigilo இந்த பக்கத்தை தடுத்து நிறுத்தியுள்ளது.`
        ];
        break;

      case 'hi':
        storyPoints = [
          `नकली पहचान: यह वेबसाइट ${brand} होने का दिखावा कर रही है।`,
          `लक्ष्य डेटा: यह पेज आपसे आपका ${stolenStr} दर्ज करने के लिए कह रहा है।`,
          `पता लगाने का कारण: ${reasonText}`,
          `संभावित जोखिम: आगे बढ़ने से ${consequenceText} जैसी स्थिति उत्पन्न हो सकती है।`,
          `सुरक्षा कार्रवाई: जानकारी चोरी होने से पहले ही विगिलियो ने इस पेज को ब्लॉक कर दिया।`
        ];
        break;

      case 'kn':
        storyPoints = [
          `ನಕಲಿ ಸಂಸ್ಥೆ: ಈ ಜಾಲತಾಣವು ${brand} ಸಂಸ್ಥೆಯಂತೆ ನಟಿಸುತ್ತಿದೆ.`,
          `ದಾಳಿಯ ಗುರಿ: ನಿಮ್ಮ ${stolenStr} ವಿವರಗಳನ್ನು ಪಡೆಯಲು ಯತ್ನಿಸುತ್ತಿದೆ.`,
          `ಪತ್ತೆಗೆ ಕಾರಣ: ${reasonText}`,
          `ಸಂಭಾವ್ಯ ಅಪಾಯ: ಮುಂದುವರಿಯುವುದು ನಿಮ್ಮ ಖಾತೆಯ ${consequenceText} ಸಂಭವಿಸಬಹುದು.`,
          `ರಕ್ಷಣಾ ಕ್ರಮ: ಯಾವುದೇ ಮಾಹಿತಿ ಸೋರಿಕೆಯಾಗುವ ಮೊದಲೇ ವಿಗಿಲಿಯೊ ಈ ಪುಟವನ್ನು ತಡೆದಿದೆ.`
        ];
        break;

      case 'te':
        storyPoints = [
          `నకిలీ సంస్థ: ఈ వెబ్‌సైట్ ${brand} గా నటిస్తూ మోసగించడానికి ప్రయత్నిస్తోంది.`,
          `లక్ష్య సమాచారం: ఈ పేజీ మీ ${stolenStr} వివరాలను సేకరించడానికి ప్రయత్నిస్తోంది.`,
          `గుర్తించిన కారణం: ${reasonText}`,
          `సాధ్యమయ్యే ప్రమాదం: కొనసాగడం వల్ల మీ ఖాతాల ${consequenceText} జరగవచ్చు.`,
          `రక్షణ చర్య: ఎటువంటి సమాచారం చేజారక ముందే Vigilo ఈ పేజీని నిరోధించింది.`
        ];
        break;

      case 'ml':
        storyPoints = [
          `വ്യാജ സ്ഥാപനം: ഈ വെബ്‌സൈറ്റ് ${brand} ആണെന്ന് വ്യാജമായി അവകാശപ്പെടുന്നു.`,
          `ലക്ഷ്യമിടുന്ന വിവരങ്ങൾ: നിങ്ങളുടെ ${stolenStr} ശേഖരിക്കാനാണ് ഈ പേജ് ശ്രമിക്കുന്നത്.`,
          `കണ്ടെത്തൽ കാരണം: ${reasonText}`,
          `സാധ്യമായ അപകടം: മുന്നോട്ട് പോകുന്നത് ${consequenceText} കാരണമായേക്കാം.`,
          `സുരക്ഷാ നടപടി: വിവരങ്ങൾ ചോരുന്നതിന് മുമ്പ് തന്നെ വിഗിലോ ഈ പേജ് വിജയകരമായി തടഞ്ഞു.`
        ];
        break;

      case 'en':
      default:
        storyPoints = [
          `Target Impersonation: This website is pretending to be ${brand}.`,
          `Attacker Goal: Attempting to collect your sensitive ${stolenStr}.`,
          `Detection Reason: ${reasonText}`,
          `Potential Risk: Continuing could lead to ${consequenceText}.`,
          `Protection Action: Vigilo automatically blocked the page before data could be stolen.`
        ];
        break;
    }

    storyPoints = storyPoints.map(p => this.sanitizeJargon(p));
    const storyText = storyPoints.join('\n');

    return {
      storyText,
      storyPoints,
      impactItems: evidence.stolenItems,
      confidence: evidence.confidence
    };
  }
}
