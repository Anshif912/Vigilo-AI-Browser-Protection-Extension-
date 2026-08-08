import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { WifiOff, RefreshCw } from 'lucide-react';

interface OfflineBannerProps {
  isOffline: boolean;
}

export const OfflineBanner: React.FC<OfflineBannerProps> = ({ isOffline }) => {
  return (
    <AnimatePresence>
      {isOffline && (
        <motion.div
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -50 }}
          className="fixed top-2 left-1/2 -translate-x-1/2 z-50 bg-rose-950/95 border border-rose-500/80 px-4 py-2 rounded-xl text-rose-200 text-xs font-semibold shadow-2xl flex items-center gap-2 backdrop-blur-md"
        >
          <WifiOff className="w-4 h-4 text-rose-400 animate-pulse" />
          <span>Platform Offline — Attempting Automatic Reconnection...</span>
          <RefreshCw className="w-3.5 h-3.5 text-rose-400 animate-spin ml-1" />
        </motion.div>
      )}
    </AnimatePresence>
  );
};
