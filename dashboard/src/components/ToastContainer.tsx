import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, CheckCircle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'threat' | 'success' | 'info';
  title: string;
  message: string;
}

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      <AnimatePresence>
        {toasts.map((toast) => {
          const isThreat = toast.type === 'threat';
          const isSuccess = toast.type === 'success';
          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -20, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              className={`pointer-events-auto p-3.5 rounded-xl border backdrop-blur-xl shadow-2xl flex items-start justify-between gap-3 ${
                isThreat
                  ? 'bg-rose-950/90 border-rose-500/60 text-rose-100 shadow-rose-950/50'
                  : isSuccess
                  ? 'bg-emerald-950/90 border-emerald-500/60 text-emerald-100 shadow-emerald-950/50'
                  : 'bg-slate-900/90 border-blue-500/60 text-blue-100 shadow-slate-950/50'
              }`}
            >
              <div className="flex items-start gap-2.5">
                {isThreat && <ShieldAlert className="w-5 h-5 text-rose-400 mt-0.5 flex-shrink-0 animate-pulse" />}
                {isSuccess && <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />}
                {!isThreat && !isSuccess && <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />}

                <div>
                  <h4 className="text-xs font-bold tracking-tight">{toast.title}</h4>
                  <p className="text-[11px] opacity-90 font-mono mt-0.5">{toast.message}</p>
                </div>
              </div>

              <button
                onClick={() => onDismiss(toast.id)}
                className="text-slate-400 hover:text-white transition-colors p-0.5"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
};
