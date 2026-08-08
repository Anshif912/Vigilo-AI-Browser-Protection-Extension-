import React from 'react';
import ReactDOM from 'react-dom/client';
import { BlockedPage } from './BlockedPage';
import { LanguageProvider } from '../i18n';
import '../styles/globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <LanguageProvider>
      <BlockedPage />
    </LanguageProvider>
  </React.StrictMode>
);
