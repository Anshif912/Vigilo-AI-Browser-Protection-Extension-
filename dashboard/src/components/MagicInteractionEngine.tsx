import React, { useEffect, useRef } from 'react';

export const MagicInteractionEngine: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let targetX = mouseX;
    let targetY = mouseY;
    let animFrameId: number;

    const handleMouseMove = (e: MouseEvent) => {
      targetX = e.clientX;
      targetY = e.clientY;

      const hoveredCard = (e.target as HTMLElement)?.closest('.glass-card, button, select, [role="button"]') as HTMLElement;
      if (hoveredCard) {
        const rect = hoveredCard.getBoundingClientRect();
        const cardX = e.clientX - rect.left;
        const cardY = e.clientY - rect.top;
        hoveredCard.style.setProperty('--card-x', `${cardX}px`);
        hoveredCard.style.setProperty('--card-y', `${cardY}px`);
      }
    };

    const update = () => {
      mouseX += (targetX - mouseX) * 0.15;
      mouseY += (targetY - mouseY) * 0.15;

      container.style.setProperty('--mouse-x', `${mouseX}px`);
      container.style.setProperty('--mouse-y', `${mouseY}px`);

      animFrameId = requestAnimationFrame(update);
    };

    window.addEventListener('mousemove', handleMouseMove);
    animFrameId = requestAnimationFrame(update);

    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const clickable = target.closest('button, a, [role="button"], .glass-card') as HTMLElement;
      if (!clickable) return;

      const rect = clickable.getBoundingClientRect();
      const ripple = document.createElement('span');
      const diameter = Math.max(rect.width, rect.height) * 2;
      const radius = diameter / 2;

      ripple.style.position = 'absolute';
      ripple.style.width = `${diameter}px`;
      ripple.style.height = `${diameter}px`;
      ripple.style.left = `${e.clientX - rect.left - radius}px`;
      ripple.style.top = `${e.clientY - rect.top - radius}px`;
      ripple.style.borderRadius = '50%';
      ripple.style.background = 'radial-gradient(circle, rgba(168, 85, 247, 0.5) 0%, rgba(59, 130, 246, 0.2) 40%, rgba(139, 92, 246, 0) 75%)';
      ripple.style.pointerEvents = 'none';
      ripple.style.transform = 'scale(0)';
      ripple.style.opacity = '1';
      ripple.style.transition = 'transform 0.45s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.45s ease-out';
      ripple.style.zIndex = '9999';

      const style = window.getComputedStyle(clickable);
      if (style.position === 'static') {
        clickable.style.position = 'relative';
      }
      clickable.style.overflow = 'hidden';

      clickable.appendChild(ripple);

      requestAnimationFrame(() => {
        ripple.style.transform = 'scale(1)';
        ripple.style.opacity = '0';
      });

      setTimeout(() => {
        ripple.remove();
      }, 500);
    };

    window.addEventListener('click', handleClick);

    return () => {
      if (animFrameId) cancelAnimationFrame(animFrameId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('click', handleClick);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="magic-interaction-wrapper"
      style={{
        width: '100%',
        minHeight: '100vh',
        position: 'relative'
      }}
    >
      <div
        className="magic-spotlight-layer"
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: 'none',
          zIndex: 1,
          background: 'radial-gradient(750px circle at var(--mouse-x, 50vw) var(--mouse-y, 50vh), rgba(168, 85, 247, 0.16), rgba(59, 130, 246, 0.08) 40%, transparent 75%)',
          transition: 'background 0.03s ease-out'
        }}
      />

      <div style={{ position: 'relative', zIndex: 2 }}>
        {children}
      </div>
    </div>
  );
};
