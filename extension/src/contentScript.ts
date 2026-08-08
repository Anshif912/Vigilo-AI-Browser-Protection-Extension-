// Vigilo v3.4.1 Content Script — Real-Time DOM & Interstitial Inspector

let hasInspectedAndReported = false;

function inspectDomForVendorWarnings() {
  const domTitle = document.title || '';
  const domText = (document.body ? document.body.innerText : '').slice(0, 4000);
  const combined = (domTitle + ' ' + domText + ' ' + window.location.href).toLowerCase();

  const warningKeywords = [
    'suspected phishing', 'potential phishing', 'attention required! | cloudflare',
    'deceptive site ahead', 'phishing attack ahead', 'malware ahead',
    'this site has been reported as unsafe', 'this website has been reported',
    'dangerous site', 'reported web forgery', 'cloudflare ray id', 'steal sensitive information'
  ];

  const hasWarning = warningKeywords.some(kw => combined.includes(kw));

  if (hasWarning && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    hasInspectedAndReported = true;
    chrome.runtime.sendMessage({
      action: 'DOM_INTERSTITIAL_DETECTED',
      url: window.location.href,
      dom_title: domTitle,
      dom_text: domText
    }).catch(() => {});
  }
}

// 1. Initial Inspection
inspectDomForVendorWarnings();

// 2. Delayed Inspection Cycles for Dynamic Rendering
[200, 600, 1500, 3000].forEach((delay) => {
  setTimeout(() => {
    if (!hasInspectedAndReported) {
      inspectDomForVendorWarnings();
    }
  }, delay);
});

// 3. Event Listener Triggers
if (document.readyState !== 'complete') {
  window.addEventListener('DOMContentLoaded', inspectDomForVendorWarnings);
  window.addEventListener('load', inspectDomForVendorWarnings);
}

// 4. MutationObserver for Dynamic Template Changes
if (typeof MutationObserver !== 'undefined' && document.documentElement) {
  const observer = new MutationObserver(() => {
    if (!hasInspectedAndReported) {
      inspectDomForVendorWarnings();
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

chrome.runtime.onMessage.addListener((message, _sender, _sendResponse) => {
  if (!message || message.type !== 'VIGILO_NOTIFICATION') return;

  const { title, text, style } = message;

  // Remove existing toast if present
  const existing = document.getElementById('vigilo-notification-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'vigilo-notification-toast';
  toast.style.position = 'fixed';
  toast.style.top = '16px';
  toast.style.right = '16px';
  toast.style.zIndex = '2147483647';
  toast.style.padding = '12px 18px';
  toast.style.borderRadius = '12px';
  toast.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  toast.style.fontSize = '13px';
  toast.style.fontWeight = '600';
  toast.style.boxShadow = '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)';
  toast.style.display = 'flex';
  toast.style.alignItems = 'center';
  toast.style.gap = '10px';
  toast.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
  toast.style.opacity = '0';
  toast.style.transform = 'translateY(-10px)';

  if (style === 'safe') {
    toast.style.backgroundColor = '#064E3B';
    toast.style.color = '#34D399';
    toast.style.border = '1px solid #059669';
    toast.innerHTML = `<span style="font-size:16px;">✓</span> <div><div>${title}</div><div style="font-size:11px;font-weight:400;color:#A7F3D0;">${text}</div></div>`;
  } else if (style === 'not_secure') {
    toast.style.backgroundColor = '#78350F';
    toast.style.color = '#FBBF24';
    toast.style.border = '1px solid #D97706';
    toast.innerHTML = `<span style="font-size:16px;">⚠</span> <div><div>${title}</div><div style="font-size:11px;font-weight:400;color:#FDE68A;">${text}</div></div>`;
  } else if (style === 'suspicious') {
    toast.style.backgroundColor = '#7C2D12';
    toast.style.color = '#FB923C';
    toast.style.border = '1px solid #EA580C';
    toast.innerHTML = `<span style="font-size:16px;">⚠</span> <div><div>${title}</div><div style="font-size:11px;font-weight:400;color:#FFEDD5;">${text}</div></div>`;
  }

  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  });

  // Auto-dismiss after 2.5 seconds for safe/info toasts
  if (style === 'safe' || style === 'not_secure') {
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px)';
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }
});
