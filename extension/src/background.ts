import { analysisService } from './services/analysisService';
import { getSettings, updateSettings } from './services/storage';

// Initialize default storage settings on extension install
chrome.runtime.onInstalled.addListener(async () => {
  const current = await getSettings();
  await updateSettings(current);
});

// Listen for tab navigation updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const url = changeInfo.url || tab.url;
  if (!url) return;

  // Delegate processing to thin AnalysisService
  analysisService.handleNavigation(tabId, url);
});

// Listen for extension messages (e.g., bypass approval or DOM Interstitial inspection)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.action === 'ALLOW_BYPASS' && message.url) {
    analysisService.allowBypass(message.url);
    sendResponse({ status: 'bypassed' });
  } else if (message && message.action === 'DOM_INTERSTITIAL_DETECTED' && sender.tab?.id) {
    analysisService.handleDomInspection(sender.tab.id, message.url, message.dom_title, message.dom_text);
    sendResponse({ status: 'analyzed' });
  }
});
