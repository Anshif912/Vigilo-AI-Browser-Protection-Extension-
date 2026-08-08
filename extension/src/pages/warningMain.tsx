import React from 'react';
import ReactDOM from 'react-dom/client';
import { WarningPage } from './WarningPage';
import { LanguageProvider } from '../i18n';
import '../styles/globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <LanguageProvider>
      <WarningPage />
    </LanguageProvider>
  </React.StrictMode>
);
