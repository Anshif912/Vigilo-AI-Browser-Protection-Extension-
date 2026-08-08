import React from 'react';
import { motion } from 'framer-motion';

export const SkeletonLoader: React.FC = () => {
  return (
    <main className="flex-1 p-6 overflow-y-auto bg-slate-950/40 space-y-6">
      {/* Hero Skeleton */}
      <motion.div
        initial={{ opacity: 0.5 }}
        animate={{ opacity: [0.4, 0.8, 0.4] }}
        transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut" }}
        className="h-44 bg-slate-900/60 rounded-2xl border border-slate-800/80 p-6 space-y-4"
      >
        <div className="flex justify-between">
          <div className="space-y-2">
            <div className="h-5 w-32 bg-slate-800 rounded" />
            <div className="h-8 w-64 bg-slate-800 rounded" />
            <div className="h-4 w-48 bg-slate-800 rounded" />
          </div>
          <div className="h-12 w-20 bg-slate-800 rounded" />
        </div>
        <div className="grid grid-cols-4 gap-4 pt-4 border-t border-slate-800">
          <div className="h-8 bg-slate-800 rounded" />
          <div className="h-8 bg-slate-800 rounded" />
          <div className="h-8 bg-slate-800 rounded" />
          <div className="h-8 bg-slate-800 rounded" />
        </div>
      </motion.div>

      {/* Score Breakdown Skeleton */}
      <motion.div
        initial={{ opacity: 0.5 }}
        animate={{ opacity: [0.4, 0.8, 0.4] }}
        transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut", delay: 0.2 }}
        className="h-48 bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3"
      >
        <div className="h-6 w-48 bg-slate-800 rounded" />
        <div className="h-12 bg-slate-800/60 rounded-lg" />
        <div className="grid grid-cols-2 gap-3">
          <div className="h-12 bg-slate-800/60 rounded-lg" />
          <div className="h-12 bg-slate-800/60 rounded-lg" />
        </div>
      </motion.div>

      {/* Timeline & IOC Skeleton */}
      <motion.div
        initial={{ opacity: 0.5 }}
        animate={{ opacity: [0.4, 0.8, 0.4] }}
        transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut", delay: 0.4 }}
        className="h-64 bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3"
      >
        <div className="h-6 w-56 bg-slate-800 rounded" />
        <div className="space-y-2">
          <div className="h-10 bg-slate-800/40 rounded" />
          <div className="h-10 bg-slate-800/40 rounded" />
          <div className="h-10 bg-slate-800/40 rounded" />
        </div>
      </motion.div>
    </main>
  );
};
