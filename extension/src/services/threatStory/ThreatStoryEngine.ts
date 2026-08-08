import { AnalysisResponse } from '../api';
import { LanguageCode } from '../../i18n/locales';
import { ThreatStoryGenerator, ThreatStoryEvidence } from './ThreatStoryGenerator';
import { ThreatStoryFormatter, ThreatStoryFormatted } from './ThreatStoryFormatter';

export interface ThreatStoryResult extends ThreatStoryFormatted {
  generationTimeMs: number;
}

export class ThreatStoryEngine {
  private static cache: Map<string, ThreatStoryResult> = new Map();

  public static generateStory(analysis: AnalysisResponse, lang: LanguageCode = 'en'): ThreatStoryResult | null {
    // Show ONLY for Suspicious, High Risk, Critical (never show for Safe or Low Risk)
    const status = (analysis.status || '').toLowerCase();
    const score = analysis.threat_score || 0;

    if (status === 'safe' || status === 'low risk' || (score < 40 && status !== 'suspicious' && status !== 'critical' && status !== 'high risk')) {
      return null;
    }

    const cacheKey = `${analysis.analysis_id || analysis.url}_${lang}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const startTime = performance.now();

    const evidence: ThreatStoryEvidence = ThreatStoryGenerator.extractEvidence(analysis);
    const formatted: ThreatStoryFormatted = ThreatStoryFormatter.formatStory(evidence, lang);

    const endTime = performance.now();
    const generationTimeMs = Math.round((endTime - startTime) * 100) / 100;

    const result: ThreatStoryResult = {
      ...formatted,
      generationTimeMs
    };

    this.cache.set(cacheKey, result);
    return result;
  }
}
