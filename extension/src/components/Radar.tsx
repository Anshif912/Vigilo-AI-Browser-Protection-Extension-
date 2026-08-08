import React, { useEffect, useRef } from 'react';

export interface RadarProps {
  speed?: number;
  scale?: number;
  ringCount?: number;
  spokeCount?: number;
  color?: string;
  backgroundColor?: string;
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  alpha: number;
  depth: number;
}

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  pulsePhase: number;
}

export const Radar: React.FC<RadarProps> = ({
  speed = 0.15,
  scale = 1.1,
  color = '#8B5CF6',
  backgroundColor = '#050608'
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let startTime = performance.now();

    const resizeCanvas = () => {
      const parent = canvas.parentElement || document.body;
      const rect = parent.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = (rect.width || window.innerWidth || 1920) * dpr;
      canvas.height = (rect.height || window.innerHeight || 1080) * dpr;
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    const resizeObserver = new ResizeObserver(resizeCanvas);
    if (canvas.parentElement) {
      resizeObserver.observe(canvas.parentElement);
    }

    // Layer 4: Multi-Depth Intelligence Particles
    const particleCount = 45;
    const particles: Particle[] = Array.from({ length: particleCount }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.00015,
      vy: (Math.random() - 0.5) * 0.00015,
      size: Math.random() * 1.8 + 0.6,
      alpha: Math.random() * 0.25 + 0.05,
      depth: Math.random() * 0.8 + 0.2
    }));

    // Layer 5: Faint Intelligence Network Nodes
    const nodeCount = 14;
    const nodes: Node[] = Array.from({ length: nodeCount }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.0001,
      vy: (Math.random() - 0.5) * 0.0001,
      pulsePhase: Math.random() * Math.PI * 2
    }));

    const render = (now: number) => {
      const elapsedTime = (now - startTime) / 1000;
      const width = canvas.width;
      const height = canvas.height;

      if (width === 0 || height === 0) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.save();

      // LAYER 1: Deep Dark Background (#050608)
      ctx.fillStyle = backgroundColor;
      ctx.fillRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const baseRadius = (Math.min(width, height) / 2) * scale;

      // LAYER 2: Large Soft Ambient Glow Orbs (Subtle 8% Opacity)
      const glowGrad1 = ctx.createRadialGradient(
        centerX, centerY, 0,
        centerX, centerY, baseRadius * 1.4
      );
      glowGrad1.addColorStop(0, 'rgba(139, 92, 246, 0.07)'); // Soft purple
      glowGrad1.addColorStop(0.5, 'rgba(79, 141, 255, 0.03)'); // Soft blue
      glowGrad1.addColorStop(1, 'rgba(5, 6, 8, 0)');
      ctx.fillStyle = glowGrad1;
      ctx.fillRect(0, 0, width, height);

      // LAYER 3: Very Faint Cyber Grid (Opacity < 4%)
      const gridSize = 80 * (width / 1920);
      ctx.lineWidth = 0.75;
      ctx.strokeStyle = 'rgba(139, 92, 246, 0.025)';
      ctx.beginPath();
      for (let x = (elapsedTime * 4) % gridSize; x < width; x += gridSize) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
      }
      ctx.stroke();

      // LAYER 6: Sub-10% Opacity Environmental Radar (30-second sweep, soft blur)
      const sweepAngle = (elapsedTime * (Math.PI * 2 / 30) * speed * 2) % (Math.PI * 2);
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(139, 92, 246, 0.05)';

      // Faint ambient radar rings
      for (let i = 1; i <= 6; i++) {
        const r = (baseRadius / 6) * i;
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Environmental soft sweep arc
      const arcSpread = Math.PI / 3;
      const arcSteps = 20;
      for (let s = 0; s < arcSteps; s++) {
        const stepRatio = s / arcSteps;
        const startA = sweepAngle - (arcSpread * (1 - stepRatio));
        const endA = sweepAngle - (arcSpread * (1 - (s + 1) / arcSteps));
        const alpha = Math.pow(stepRatio, 3) * 0.045; // Sub 5% opacity

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, baseRadius * 1.1, startA, endA);
        ctx.closePath();
        ctx.fillStyle = `rgba(139, 92, 246, ${alpha})`;
        ctx.fill();
      }

      // LAYER 5: Animated Network Lines & Intelligence Nodes
      nodes.forEach(node => {
        node.x = (node.x + node.vx + 1) % 1;
        node.y = (node.y + node.vy + 1) % 1;
      });

      ctx.lineWidth = 0.75;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const n1 = nodes[i];
          const n2 = nodes[j];
          const dx = (n1.x - n2.x) * width;
          const dy = (n1.y - n2.y) * height;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 220) {
            const lineAlpha = (1 - dist / 220) * 0.04;
            ctx.strokeStyle = `rgba(93, 235, 255, ${lineAlpha})`;
            ctx.beginPath();
            ctx.moveTo(n1.x * width, n1.y * height);
            ctx.lineTo(n2.x * width, n2.y * height);
            ctx.stroke();
          }
        }
      }

      nodes.forEach(node => {
        const nx = node.x * width;
        const ny = node.y * height;
        const pulse = 0.6 + 0.4 * Math.sin(elapsedTime * 1.2 + node.pulsePhase);
        ctx.beginPath();
        ctx.arc(nx, ny, 2, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(139, 92, 246, ${0.15 * pulse})`;
        ctx.fill();
      });

      // LAYER 4: Multi-Depth Slow Particles
      particles.forEach(p => {
        p.x = (p.x + p.vx * p.depth + 1) % 1;
        p.y = (p.y + p.vy * p.depth + 1) % 1;

        const px = p.x * width;
        const py = p.y * height;

        ctx.beginPath();
        ctx.arc(px, py, p.size * p.depth, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${p.alpha * p.depth})`;
        ctx.fill();
      });

      // CINEMATIC VIGNETTE OVERLAY (Subtle focus on central hero cards)
      const vignette = ctx.createRadialGradient(
        centerX, centerY, baseRadius * 0.5,
        centerX, centerY, Math.max(width, height) * 0.75
      );
      vignette.addColorStop(0, 'rgba(5, 6, 8, 0)');
      vignette.addColorStop(1, 'rgba(5, 6, 8, 0.7)');
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, width, height);

      ctx.restore();
      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', resizeCanvas);
      resizeObserver.disconnect();
    };
  }, [speed, scale, color, backgroundColor]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width: '100%',
        height: '100%',
        display: 'block',
        pointerEvents: 'none'
      }}
    />
  );
};
