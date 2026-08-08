import React from 'react';
import { Radar } from './Radar';

export const RadarBackground: React.FC = () => {
  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        overflow: 'hidden',
        pointerEvents: 'none',
        zIndex: 0,
        background: 'linear-gradient(135deg, #0D0620 0%, #080D26 35%, #0F172A 70%, #060919 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}
    >
      {/* Ambient Glowing Purple & Blue Radial Orbs */}
      <div
        style={{
          position: 'absolute',
          top: '-10%',
          left: '25%',
          width: '50vw',
          height: '50vw',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(168, 85, 247, 0.28) 0%, rgba(93, 235, 255, 0.08) 50%, transparent 75%)',
          filter: 'blur(90px)',
          pointerEvents: 'none'
        }}
      />
      <div
        style={{
          position: 'absolute',
          bottom: '-15%',
          right: '15%',
          width: '45vw',
          height: '45vw',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.25) 0%, rgba(139, 92, 246, 0.12) 50%, transparent 75%)',
          filter: 'blur(100px)',
          pointerEvents: 'none'
        }}
      />

      <div
        style={{
          width: '100%',
          height: '100%',
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <Radar
          speed={0.25}
          scale={1.2}
          color="#A855F7"
          backgroundColor="transparent"
        />
      </div>

      {/* Subtle Environmental Glass Vignette */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          width: '100%',
          height: '100%',
          background: 'radial-gradient(circle at center, transparent 30%, rgba(9, 6, 23, 0.65) 100%)',
          backdropFilter: 'blur(1px)',
          WebkitBackdropFilter: 'blur(1px)',
          pointerEvents: 'none'
        }}
      />
    </div>
  );
};
