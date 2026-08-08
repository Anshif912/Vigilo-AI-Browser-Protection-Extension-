import React, { useState } from 'react';
import { AnalysisResponse } from '../services/api';
import { useLanguage } from '../i18n';
import { ThreatStoryEngine, ThreatStoryResult } from '../services/threatStory/ThreatStoryEngine';

interface ThreatStoryCardProps {
  analysis: AnalysisResponse | null;
}

export const ThreatStoryCard: React.FC<ThreatStoryCardProps> = ({ analysis }) => {
  const { language, t } = useLanguage();
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  if (!analysis) return null;

  const storyResult: ThreatStoryResult | null = ThreatStoryEngine.generateStory(analysis, language);

  // Never show for Safe or Low Risk websites
  if (!storyResult) return null;

  return (
    <div style={{
      marginTop: '12px',
      marginBottom: '12px',
      borderRadius: '12px',
      background: 'rgba(255, 255, 255, 0.04)',
      backdropFilter: 'blur(12px)',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.2)',
      overflow: 'hidden',
      transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)'
    }}>
      {/* Header Button */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        style={{
          width: '100%',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          outline: 'none',
          color: '#F8FAFC',
          fontSize: '14px',
          fontWeight: 600,
          fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", sans-serif',
          letterSpacing: '-0.01em'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '16px' }}>{t('threatStory.title')}</span>
          <span style={{
            fontSize: '10px',
            padding: '2px 8px',
            borderRadius: '10px',
            background: 'rgba(239, 68, 68, 0.15)',
            color: '#F87171',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            fontWeight: 500
          }}>
            {t('threatStory.confidenceBadge')} {storyResult.confidence}%
          </span>
        </div>

        <div style={{
          transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
          color: '#94A3B8',
          display: 'flex',
          alignItems: 'center'
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </button>

      {/* Collapsible Content */}
      {isExpanded && (
        <div style={{
          padding: '0 16px 16px 16px',
          color: '#CBD5E1',
          fontSize: '13px',
          lineHeight: '1.6',
          fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", sans-serif',
          animation: 'fadeIn 0.25s ease-out'
        }}>
          {/* Neat thin bulleted list container */}
          <div style={{
            padding: '12px 14px',
            borderRadius: '8px',
            background: 'rgba(0, 0, 0, 0.25)',
            borderLeft: '3px solid #EF4444',
            marginBottom: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {storyResult.storyPoints && storyResult.storyPoints.length > 0 ? (
              storyResult.storyPoints.map((pt, idx) => {
                const parts = pt.split(': ');
                const hasPrefix = parts.length > 1;
                return (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '12.5px', lineHeight: '1.5' }}>
                    <span style={{ color: '#F87171', fontSize: '12px', lineHeight: '1.6', flexShrink: 0 }}>•</span>
                    <span style={{ color: '#E2E8F0', fontWeight: 400 }}>
                      {hasPrefix ? (
                        <>
                          <strong style={{ color: '#F8FAFC', fontWeight: 600 }}>{parts[0]}:</strong> {parts.slice(1).join(': ')}
                        </>
                      ) : (
                        pt
                      )}
                    </span>
                  </div>
                );
              })
            ) : (
              <p style={{ margin: 0, color: '#E2E8F0', fontWeight: 400 }}>
                {storyResult.storyText}
              </p>
            )}
          </div>

          {/* Potential Impact Badges */}
          {storyResult.impactItems && storyResult.impactItems.length > 0 && (
            <div style={{
              paddingTop: '8px',
              borderTop: '1px dashed rgba(255, 255, 255, 0.1)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px'
            }}>
              <span style={{
                fontSize: '11px',
                fontWeight: 600,
                color: '#94A3B8',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                {t('threatStory.potentialImpact')}
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {storyResult.impactItems.map((item, idx) => (
                  <span
                    key={idx}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      fontSize: '11px',
                      padding: '3px 8px',
                      borderRadius: '6px',
                      background: 'rgba(239, 68, 68, 0.12)',
                      color: '#FECACA',
                      border: '1px solid rgba(239, 68, 68, 0.2)',
                      fontWeight: 500
                    }}
                  >
                    {item}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
