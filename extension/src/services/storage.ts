export interface ActivityLog {
  domain: string;
  status: 'safe' | 'suspicious' | 'blocked';
  timestamp?: string;
}

export interface ExtensionSettings {
  protectionEnabled: boolean;
  threatsBlockedCount: number;
  lastThreat: string;
  recentActivity: ActivityLog[];
  language: string;
}

const DEFAULT_SETTINGS: ExtensionSettings = {
  protectionEnabled: true,
  threatsBlockedCount: 3,
  lastThreat: 'Fake SBI Login',
  recentActivity: [
    { domain: 'google.com', status: 'safe' },
    { domain: 'fake-sbi-login.xyz', status: 'blocked' },
    { domain: 'github.com', status: 'safe' }
  ],
  language: 'en'
};

export async function getSettings(): Promise<ExtensionSettings> {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
    return DEFAULT_SETTINGS;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(
      ['protectionEnabled', 'threatsBlockedCount', 'lastThreat', 'recentActivity', 'language'],
      (res) => {
        resolve({
          protectionEnabled: res.protectionEnabled !== undefined ? res.protectionEnabled : DEFAULT_SETTINGS.protectionEnabled,
          threatsBlockedCount: res.threatsBlockedCount !== undefined ? res.threatsBlockedCount : DEFAULT_SETTINGS.threatsBlockedCount,
          lastThreat: res.lastThreat || DEFAULT_SETTINGS.lastThreat,
          recentActivity: res.recentActivity || DEFAULT_SETTINGS.recentActivity,
          language: res.language || DEFAULT_SETTINGS.language
        });
      }
    );
  });
}

export async function updateSettings(partial: Partial<ExtensionSettings>): Promise<void> {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
  return new Promise((resolve) => {
    chrome.storage.local.set(partial, () => resolve());
  });
}

export async function recordThreatBlocked(threatIdentity: string, domain: string): Promise<void> {
  const current = await getSettings();
  const newCount = current.threatsBlockedCount + 1;
  const updatedActivity: ActivityLog[] = [
    { domain, status: 'blocked', timestamp: new Date().toISOString() },
    ...current.recentActivity.slice(0, 4)
  ];

  await updateSettings({
    threatsBlockedCount: newCount,
    lastThreat: threatIdentity || domain,
    recentActivity: updatedActivity
  });
}

export async function recordActivity(domain: string, status: 'safe' | 'suspicious' | 'blocked'): Promise<void> {
  const current = await getSettings();
  // Prevent duplicate consecutive entries for the same domain
  if (current.recentActivity.length > 0 && current.recentActivity[0].domain === domain && current.recentActivity[0].status === status) {
    return;
  }
  const updatedActivity: ActivityLog[] = [
    { domain, status, timestamp: new Date().toISOString() },
    ...current.recentActivity.filter(a => a.domain !== domain).slice(0, 4)
  ];
  await updateSettings({ recentActivity: updatedActivity });
}
