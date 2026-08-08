import React, { createContext, useContext, useEffect, useState } from 'react';
import en from './locales/en.json';
import ta from './locales/ta.json';
import hi from './locales/hi.json';
import kn from './locales/kn.json';
import te from './locales/te.json';
import ml from './locales/ml.json';

declare var chrome: any;

export type LanguageCode = 'en' | 'ta' | 'hi' | 'kn' | 'te' | 'ml';

export const LOCALES: Record<LanguageCode, any> = { en, ta, hi, kn, te, ml };

export const LANGUAGE_LABELS: Record<LanguageCode, { label: string; nativeName: string }> = {
  en: { label: 'English', nativeName: 'English' },
  ta: { label: 'Tamil', nativeName: 'தமிழ்' },
  hi: { label: 'Hindi', nativeName: 'हिन्दी' },
  kn: { label: 'Kannada', nativeName: 'ಕನ್ನಡ' },
  te: { label: 'Telugu', nativeName: 'తెలుగు' },
  ml: { label: 'Malayalam', nativeName: 'മലയാളം' }
};

interface LanguageContextType {
  language: LanguageCode;
  setLanguage: (lang: LanguageCode) => void;
  t: (keyPath: string) => string;
}

const LanguageContext = createContext<LanguageContextType>({
  language: 'en',
  setLanguage: () => {},
  t: (keyPath: string) => keyPath
});

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [language, setLanguageState] = useState<LanguageCode>('en');

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      const storageArea = chrome.storage.sync || chrome.storage.local;
      if (storageArea) {
        storageArea.get(['vigilo_language'], (res: any) => {
          if (res && res.vigilo_language && LOCALES[res.vigilo_language as LanguageCode]) {
            setLanguageState(res.vigilo_language as LanguageCode);
          }
        });

        const handleStorageChange = (changes: any, areaName: string) => {
          if ((areaName === 'sync' || areaName === 'local') && changes.vigilo_language) {
            const nextLang = changes.vigilo_language.newValue as LanguageCode;
            if (LOCALES[nextLang]) {
              setLanguageState(nextLang);
            }
          }
        };

        chrome.storage.onChanged.addListener(handleStorageChange);
        return () => chrome.storage.onChanged.removeListener(handleStorageChange);
      }
    } else if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem('vigilo_language') as LanguageCode;
      if (stored && LOCALES[stored]) {
        setLanguageState(stored);
      }
    }
  }, []);

  const setLanguage = (nextLang: LanguageCode) => {
    if (!LOCALES[nextLang]) return;
    setLanguageState(nextLang);

    if (typeof chrome !== 'undefined' && chrome.storage) {
      const storageArea = chrome.storage.sync || chrome.storage.local;
      if (storageArea) {
        storageArea.set({ vigilo_language: nextLang });
      }
    }
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('vigilo_language', nextLang);
    }
  };

  const t = (keyPath: string): string => {
    const keys = keyPath.split('.');
    
    // 1. Try selected language
    let current = LOCALES[language];
    for (const key of keys) {
      if (current && current[key] !== undefined) {
        current = current[key];
      } else {
        current = null;
        break;
      }
    }
    if (typeof current === 'string') return current;

    // 2. Fallback to English
    current = LOCALES['en'];
    for (const key of keys) {
      if (current && current[key] !== undefined) {
        current = current[key];
      } else {
        current = null;
        break;
      }
    }
    if (typeof current === 'string') return current;

    // 3. Last resort: key name
    return keys[keys.length - 1] || keyPath;
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => useContext(LanguageContext);
