import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Globe, Check, ChevronDown } from 'lucide-react';
import { useLanguage, LANGUAGE_LABELS, type LanguageCode } from '../i18n';

interface LanguageSelectorProps {
  className?: string;
  dropPosition?: 'bottom-right' | 'bottom-left' | 'top-right';
}

export const LanguageSelector: React.FC<LanguageSelectorProps> = ({
  className = '',
  dropPosition = 'bottom-right'
}) => {
  const { language, setLanguage } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const languagesList = Object.keys(LANGUAGE_LABELS) as LanguageCode[];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!isOpen) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
          e.preventDefault();
          setIsOpen(true);
          setFocusedIndex(languagesList.indexOf(language));
        }
        return;
      }

      if (e.key === 'Escape') {
        e.preventDefault();
        setIsOpen(false);
        buttonRef.current?.focus();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setFocusedIndex((prev) => (prev + 1) % languagesList.length);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setFocusedIndex((prev) => (prev - 1 + languagesList.length) % languagesList.length);
      } else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (focusedIndex >= 0 && focusedIndex < languagesList.length) {
          const selectedLang = languagesList[focusedIndex];
          setLanguage(selectedLang);
          setIsOpen(false);
          buttonRef.current?.focus();
        }
      }
    },
    [isOpen, focusedIndex, language, languagesList, setLanguage]
  );

  const positionClasses =
    dropPosition === 'top-right'
      ? 'bottom-full right-0 mb-2'
      : dropPosition === 'bottom-left'
      ? 'top-full left-0 mt-2'
      : 'top-full right-0 mt-2';

  return (
    <div
      className={`relative inline-block text-left z-[9999] ${className}`}
      ref={dropdownRef}
      onKeyDown={handleKeyDown}
    >
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-label="Select Application Language"
        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700/90 text-xs font-semibold text-slate-200 transition-all duration-200 shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500/50 cursor-pointer"
      >
        <Globe className="w-3.5 h-3.5 text-blue-400 shrink-0" />
        <span className="uppercase tracking-wider font-bold text-blue-300">{language}</span>
        <ChevronDown
          className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${
            isOpen ? 'rotate-180 text-blue-400' : ''
          }`}
        />
      </button>

      {isOpen && (
        <div
          role="listbox"
          aria-label="Languages"
          className={`absolute ${positionClasses} w-48 rounded-2xl bg-[#0F172A] border border-slate-700/90 shadow-2xl z-[9999] py-1.5 backdrop-blur-2xl animate-in fade-in zoom-in-95 duration-150`}
          style={{ zIndex: 9999 }}
        >
          <div className="px-3 py-1.5 border-b border-slate-800 text-[10px] uppercase tracking-widest font-bold text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Globe className="w-3 h-3 text-blue-400" />
              Select Language
            </span>
            <span className="text-[9px] text-slate-500 font-mono">In-App</span>
          </div>

          <div className="max-h-60 overflow-y-auto py-1 custom-scrollbar">
            {languagesList.map((code, idx) => {
              const isSelected = code === language;
              const isFocused = idx === focusedIndex;
              const item = LANGUAGE_LABELS[code];

              return (
                <button
                  key={code}
                  role="option"
                  aria-selected={isSelected}
                  type="button"
                  onClick={() => {
                    setLanguage(code);
                    setIsOpen(false);
                    buttonRef.current?.focus();
                  }}
                  onMouseEnter={() => setFocusedIndex(idx)}
                  className={`w-full text-left px-3.5 py-2 text-xs flex items-center justify-between transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-blue-600/20 text-blue-400 font-bold border-l-2 border-blue-500'
                      : isFocused
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-300 hover:bg-slate-800/80'
                  }`}
                >
                  <div className="flex flex-col">
                    <span className="font-semibold text-slate-100">{item.nativeName}</span>
                    <span className="text-[10px] text-slate-400">{item.label} ({code.toUpperCase()})</span>
                  </div>
                  {isSelected && <Check className="w-4 h-4 text-blue-400 shrink-0 ml-2" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
