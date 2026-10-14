import React, { useEffect, useState, useCallback } from 'react';
import {
  Shield,
  LayoutDashboard,
  Filter,
  Cpu,
  Crosshair,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  BookOpen,
  Server,
} from 'lucide-react';
import { api } from './api';
import OverviewPage from './pages/OverviewPage';
import PreprocessingPage from './pages/PreprocessingPage';
import SvmTrainingPage from './pages/SvmTrainingPage';
import PredictionExportPage from './pages/PredictionExportPage';

const NAV_ITEMS = [
  {
    id: 'overview',
    num: '01',
    label: 'Overview & Koneksi CTI',
    subtitle: 'MISP, Wazuh & Honeypot',
    icon: LayoutDashboard,
  },
  {
    id: 'preprocessing',
    num: '02',
    label: 'Preprocessing & Validasi',
    subtitle: 'Bab 4.4 – 4.5 (Tabel 4.2–4.18)',
    icon: Filter,
  },
  {
    id: 'training',
    num: '03',
    label: 'Training & Evaluasi SVM',
    subtitle: 'Kernel RBF/Linear & Metrik',
    icon: Cpu,
  },
  {
    id: 'prediction',
    num: '04',
    label: 'Prediksi Honeypot & Ekspor',
    subtitle: 'Unseen Data, Wazuh XML & MISP JSON',
    icon: Crosshair,
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState(null);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [error, setError] = useState(null);

  const fetchOverview = useCallback(async () => {
    setLoadingOverview(true);
    setError(null);
    try {
      const data = await api.getOverview();
      setOverview(data);
    } catch (err) {
      setError(err.message || 'Gagal menghubungi Backend API di port 8000');
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
  }, [fetchOverview]);

  const totalThreats = overview?.dataset_summary?.total || 0;
  const latestSvm = overview?.latest_svm_run || null;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col lg:flex-row">
      {/* Sidebar */}
      <aside className="w-full lg:w-72 bg-slate-900/95 border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col justify-between shrink-0 lg:sticky lg:top-0 lg:h-screen">
        <div>
          {/* Brand Header */}
          <div className="p-5 border-b border-slate-800 flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
              <Shield className="w-6 h-6 text-slate-950" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-base tracking-tight text-white">
                  Proactive CTI-SVM
                </h1>
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Cyber Security Defense Model
              </p>
            </div>
          </div>

          {/* Navigation Menu */}
          <div className="p-3 space-y-1.5">
            <div className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Menu Utama Sistem
            </div>
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full text-left px-3.5 py-3 rounded-xl transition flex items-start gap-3 group ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                      : 'text-slate-300 hover:bg-slate-800/70 hover:text-white border border-transparent'
                  }`}
                >
                  <div
                    className={`p-2 rounded-lg mt-0.5 transition ${
                      isActive
                        ? 'bg-cyan-500 text-slate-950'
                        : 'bg-slate-800 text-slate-400 group-hover:text-slate-200'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-semibold truncate">{item.label}</span>
                      <span className="text-[10px] font-mono opacity-60">{item.num}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate mt-0.5">
                      {item.subtitle}
                    </p>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* System Status Footer in Sidebar */}
        <div className="p-4 border-t border-slate-800 space-y-3 bg-slate-950/50">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>Status Pipeline</span>
            <button
              onClick={fetchOverview}
              title="Refresh Status"
              className="text-slate-400 hover:text-cyan-400 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingOverview ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between bg-slate-900 px-3 py-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" /> Dataset CTI
              </span>
              <span className="font-mono font-semibold text-slate-200">
                {Number(totalThreats).toLocaleString()} baris
              </span>
            </div>

            <div className="flex items-center justify-between bg-slate-900 px-3 py-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-emerald-400" /> Model SVM
              </span>
              {latestSvm ? (
                <span className="font-mono font-semibold text-emerald-400">
                  {Number(latestSvm.accuracy).toFixed(1)}% ({latestSvm.kernel.toUpperCase()})
                </span>
              ) : (
                <span className="text-amber-400 text-[11px]">Belum Dilatih</span>
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-2">
            <BookOpen className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
            <span>
              Implementasi Tesis PhD: <em>Syurahbil (UUM, 2024)</em> — Bab 3, 4 &amp; 5
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="bg-slate-900/60 backdrop-blur border-b border-slate-800 px-6 py-4 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-20">
          <div>
            <div className="flex items-center gap-2 text-xs text-cyan-400 font-medium">
              <span>Proactive Cyber Security Defense Model</span>
              <span>•</span>
              <span>Multi-Source CTI (MISP, Wazuh, Honeypot)</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-0.5">
              {NAV_ITEMS.find((i) => i.id === activeTab)?.label}
            </h2>
          </div>

          <div className="flex items-center gap-3">
            {error ? (
              <div className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-300">
                <AlertCircle className="w-3.5 h-3.5" />
                <span>API Offline</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-300">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>React + PHP Backend + Python SVM Connected</span>
              </div>
            )}
          </div>
        </header>

        {/* Page Body */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 text-sm flex items-center justify-between">
              <div>
                <span className="font-semibold">Koneksi ke Server Gagal: </span>
                {error}
              </div>
              <button
                onClick={fetchOverview}
                className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-xs font-medium transition"
              >
                Coba Lagi
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewPage
              overview={overview}
              onRefresh={fetchOverview}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'preprocessing' && (
            <PreprocessingPage onNavigate={setActiveTab} />
          )}

          {activeTab === 'training' && (
            <SvmTrainingPage
              onRefreshOverview={fetchOverview}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'prediction' && (
            <PredictionExportPage onRefreshOverview={fetchOverview} />
          )}
        </main>
      </div>
    </div>
  );
}
