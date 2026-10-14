import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Database,
  Activity,
  RefreshCw,
  Upload,
  Settings,
  DownloadCloud,
  Server,
  Radio,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api';

export default function OverviewPage({ overview, onRefresh, onNavigate }) {
  const [loadingAction, setLoadingAction] = useState('');
  const [banner, setBanner] = useState(null);
  const [editingSource, setEditingSource] = useState(null);
  const [pullLimit, setPullLimit] = useState(100);
  const [uploadContent, setUploadContent] = useState('');
  const [uploadPlatform, setUploadPlatform] = useState('Honeypot');

  const summary = overview?.dataset_summary || {};
  const latestSvm = overview?.latest_svm_run || null;
  const sources = overview?.sources || [];
  const predSummary = overview?.predictions_summary || {};

  const handlePull = async (sourceName) => {
    setLoadingAction(`pull-${sourceName}`);
    setBanner(null);
    try {
      const res = await api.pullFromSource({ source_name: sourceName, limit: Number(pullLimit) || 100 });
      setBanner({ type: 'success', text: res.message });
      await onRefresh();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoadingAction('');
    }
  };

  const handleSeed12500 = async () => {
    setLoadingAction('seed-12500');
    setBanner(null);
    try {
      const res = await api.seedDataset({ total_samples: 12500, reset_existing: true });
      setBanner({ type: 'success', text: res.message });
      await onRefresh();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoadingAction('');
    }
  };

  const handleSaveConfig = async (e) => {
    e.preventDefault();
    if (!editingSource) return;
    setLoadingAction('save-config');
    try {
      const res = await api.updateSourceConfig(editingSource);
      setBanner({ type: 'success', text: res.message });
      setEditingSource(null);
      await onRefresh();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoadingAction('');
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!uploadContent.trim()) return;
    setLoadingAction('upload-logs');
    setBanner(null);
    try {
      const res = await api.uploadLogs({
        content: uploadContent,
        source_platform: uploadPlatform,
      });
      setBanner({ type: 'success', text: res.message });
      setUploadContent('');
      await onRefresh();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoadingAction('');
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setUploadContent(String(ev.target?.result || ''));
    };
    reader.readAsText(file);
  };

  const loadSampleCowrieLog = () => {
    const sample = [
      JSON.stringify({
        direction: 'inbound',
        protocol: 'TCP',
        ids_type: 'network',
        timestamp: '2026-04-18 10:15:32',
        vendor_product: 'Cowrie',
        app: 'cowrie',
        src_ip: '68.183.55.117',
        dest_port: 22,
        src_port: 57368,
        dest_ip: '68.183.44.135',
        payload_size: 1024,
        signature: 'SSH session on cowrie honeypot',
        attack_type: 'SSH Brute Force',
        severity: 'high',
      }),
      JSON.stringify({
        direction: 'inbound',
        protocol: 'TCP',
        ids_type: 'network',
        timestamp: '2026-04-18 10:16:05',
        vendor_product: 'Amun',
        app: 'amun',
        src_ip: '222.174.141.18',
        dest_port: 3389,
        src_port: 59241,
        dest_ip: '157.230.253.124',
        payload_size: 2048,
        signature: 'Connection to Honeypot',
        attack_type: 'Malware Payload',
        severity: 'high',
      }),
    ].join('\n');
    setUploadContent(sample);
  };

  return (
    <div className="space-y-6">
      {banner && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between ${
            banner.type === 'error'
              ? 'bg-red-950/60 border-red-700 text-red-200'
              : 'bg-emerald-950/60 border-emerald-700 text-emerald-200'
          }`}
        >
          <span className="text-sm font-medium">{banner.text}</span>
          <button onClick={() => setBanner(null)} className="text-xs underline ml-4">
            Tutup
          </button>
        </div>
      )}

      {/* Top Hero & Quick Dataset Generator */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/60 to-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 mb-2">
            <Radio className="w-3.5 h-3.5" /> Proactive Cyber Security Defense Model (CTI + SVM)
          </span>
          <h2 className="text-2xl font-bold text-white">
            Pusat Akuisisi Cyber Threat Intelligence & Monitoring
          </h2>
          <p className="text-slate-400 text-sm mt-1 max-w-3xl">
            Mengumpulkan data indikator ancaman siber (IoC) dan log serangan secara satu arah (Pull) dari{' '}
            <strong className="text-slate-200">MISP</strong>,{' '}
            <strong className="text-slate-200">Wazuh IDS/SIEM</strong>, dan{' '}
            <strong className="text-slate-200">Honeypot (Cowrie/Amun)</strong> untuk pelatihan dan klasifikasi{' '}
            <strong className="text-indigo-300">Support Vector Machine (SVM)</strong>.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleSeed12500}
            disabled={loadingAction === 'seed-12500'}
            className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold flex items-center gap-2 shadow-lg shadow-indigo-600/20 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loadingAction === 'seed-12500' ? 'animate-spin' : ''}`} />
            {loadingAction === 'seed-12500' ? 'Membuat Dataset...' : 'Reset Dataset Tesis (12.500 Sampel)'}
          </button>
          <button
            onClick={() => onNavigate('preprocessing')}
            className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 cursor-pointer"
          >
            Lanjut ke Preprocessing &rarr;
          </button>
        </div>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Total Sampel Dataset CTI</span>
            <Database className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-3xl font-bold text-white mt-2">
            {(summary.total_samples || 0).toLocaleString('id-ID')}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Gabungan <span className="text-slate-200">D_MISP ∪ D_Wazuh ∪ D_Honeypot</span>
          </p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Kelas Cyber Threat (+1)</span>
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
          <div className="text-3xl font-bold text-rose-400 mt-2">
            {(summary.threat_count || 0).toLocaleString('id-ID')}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            True Positive (TP) sampel aktivitas berbahaya
          </p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Kelas Benign / Normal (-1)</span>
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-emerald-400 mt-2">
            {(summary.benign_count || 0).toLocaleString('id-ID')}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            True Negative (TN) trafik jaringan normal
          </p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Performa Model SVM Aktif</span>
            <Activity className="w-5 h-5 text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-amber-400 mt-2">
            {latestSvm ? `${latestSvm.accuracy}%` : 'Siap Latih'}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            {latestSvm
              ? `Kernel: ${String(latestSvm.kernel).toUpperCase()} | F1: ${latestSvm.f1_score}% | AUC: ${latestSvm.auc_score}`
              : `Deteksi Honeypot: ${predSummary.predicted_threats || 0} Threat`}
          </p>
        </div>
      </div>

      {/* CTI Sources Connectors (MISP, Wazuh, Honeypot) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-5">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-indigo-400" />
              Konektor Sumber Data CTI (Satu Arah: Pull &amp; Ingest)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Tarik data langsung dari REST API MISP, Wazuh SIEM/IDS, dan Sensor Honeypot (otomatis fallback ke mode simulasi jika server lokal belum aktif).
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <label className="text-slate-400">Jumlah Tarik per Klik:</label>
            <select
              value={pullLimit}
              onChange={(e) => setPullLimit(Number(e.target.value))}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200"
            >
              <option value={25}>25 baris</option>
              <option value={100}>100 baris</option>
              <option value={500}>500 baris</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {sources.map((src) => (
            <div
              key={src.source_name}
              className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                    {src.source_name}
                  </span>
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Aktif
                  </span>
                </div>

                <div className="mt-3 space-y-1.5 text-xs">
                  <div className="text-slate-400">
                    Endpoint:{' '}
                    <code className="text-slate-200 bg-slate-900 px-1.5 py-0.5 rounded break-all">
                      {src.base_url}
                    </code>
                  </div>
                  <div className="text-slate-400">
                    Protokol:{' '}
                    <span className="text-slate-300 font-medium">
                      {src.source_name === 'MISP'
                        ? 'REST API (POST /events/restSearch)'
                        : src.source_name === 'Wazuh'
                        ? 'Wazuh REST API (JWT + /alerts)'
                        : 'Cowrie & Amun JSON Log Stream'}
                    </span>
                  </div>
                  <div className="text-slate-400">
                    Status Terakhir:{' '}
                    <span className="text-amber-300">{src.last_status || 'Siap'}</span>
                  </div>
                  {src.last_sync_at && (
                    <div className="text-slate-500">Sinkronisasi: {src.last_sync_at}</div>
                  )}
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center gap-2">
                <button
                  onClick={() => handlePull(src.source_name)}
                  disabled={loadingAction === `pull-${src.source_name}`}
                  className="flex-1 py-2 px-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <DownloadCloud className="w-4 h-4" />
                  {loadingAction === `pull-${src.source_name}`
                    ? 'Menarik Data...'
                    : `Pull Data ${src.source_name}`}
                </button>
                <button
                  onClick={() => setEditingSource({ ...src })}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer"
                  title="Konfigurasi Koneksi"
                >
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Distribution Breakdown & Log Upload */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Distribution by Source & Attack Type */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-5">
          <h3 className="text-base font-bold text-white">
            Distribusi Dataset Berdasarkan Sumber &amp; Tipe Serangan
          </h3>

          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase mb-2">
              Proporsi Sumber Platform CTI
            </div>
            <div className="grid grid-cols-3 gap-3">
              {(summary.by_platform || []).map((item) => (
                <div
                  key={item.source_platform}
                  className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-center"
                >
                  <div className="text-xs text-slate-400">{item.source_platform}</div>
                  <div className="text-lg font-bold text-white mt-0.5">
                    {Number(item.count).toLocaleString('id-ID')}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase mb-2">
              Distribusi Kategori Serangan (Attack Type)
            </div>
            <div className="space-y-2">
              {(summary.by_attack_type || []).map((atk) => {
                const pct = summary.total_samples
                  ? Math.round((Number(atk.count) / summary.total_samples) * 100)
                  : 0;
                const isBenign = String(atk.attack_type).toLowerCase() === 'normal';
                return (
                  <div key={atk.attack_type} className="text-xs">
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span className="font-medium">{atk.attack_type}</span>
                      <span className="text-slate-400">
                        {Number(atk.count).toLocaleString('id-ID')} ({pct}%)
                      </span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          isBenign ? 'bg-emerald-500' : 'bg-rose-500'
                        }`}
                        style={{ width: `${Math.max(4, pct)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Upload Raw JSON / Cowrie Honeypot / CSV Logs */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-indigo-400" />
                Impor Log Mentah (JSON Cowrie/Amun, MISP, atau CSV)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Unggah file log atau tempel format JSON seperti pada Gambar 1.3 tesis.
              </p>
            </div>
            <button
              type="button"
              onClick={loadSampleCowrieLog}
              className="text-xs text-indigo-400 hover:text-indigo-300 underline cursor-pointer"
            >
              Isi Contoh Log Gambar 1.3
            </button>
          </div>

          <form onSubmit={handleUploadSubmit} className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <select
                value={uploadPlatform}
                onChange={(e) => setUploadPlatform(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
              >
                <option value="Honeypot">Sumber: Honeypot (Cowrie / Amun)</option>
                <option value="MISP">Sumber: MISP Event JSON</option>
                <option value="Wazuh">Sumber: Wazuh IDS Alert</option>
              </select>

              <input
                type="file"
                accept=".json,.jsonl,.log,.csv,.txt"
                onChange={handleFileChange}
                className="text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700"
              />
            </div>

            <textarea
              rows={6}
              value={uploadContent}
              onChange={(e) => setUploadContent(e.target.value)}
              placeholder='{"direction": "inbound", "protocol": "TCP", "vendor_product": "Cowrie", "src_ip": "68.183.55.117", "dest_port": 22, "signature": "SSH session on cowrie honeypot", "severity": "high"}'
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
            />

            <button
              type="submit"
              disabled={loadingAction === 'upload-logs' || !uploadContent.trim()}
              className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold cursor-pointer"
            >
              {loadingAction === 'upload-logs' ? 'Mengimpor Log...' : 'Parsing & Simpan ke Tabel Threats'}
            </button>
          </form>
        </div>
      </div>

      {/* Modal Konfigurasi Konektor */}
      {editingSource && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4">
            <h4 className="text-lg font-bold text-white">
              Konfigurasi Konektor {editingSource.source_name}
            </h4>
            <form onSubmit={handleSaveConfig} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Base URL / Endpoint</label>
                <input
                  type="text"
                  value={editingSource.base_url || ''}
                  onChange={(e) =>
                    setEditingSource({ ...editingSource, base_url: e.target.value })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                />
              </div>

              {editingSource.source_name !== 'Wazuh' && (
                <div>
                  <label className="block text-slate-400 mb-1">API Key / Sensor Token</label>
                  <input
                    type="text"
                    value={editingSource.api_key || ''}
                    onChange={(e) =>
                      setEditingSource({ ...editingSource, api_key: e.target.value })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                  />
                </div>
              )}

              {editingSource.source_name === 'Wazuh' && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1">Wazuh API User</label>
                    <input
                      type="text"
                      value={editingSource.username || ''}
                      onChange={(e) =>
                        setEditingSource({ ...editingSource, username: e.target.value })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Wazuh API Password</label>
                    <input
                      type="password"
                      value={editingSource.password || ''}
                      onChange={(e) =>
                        setEditingSource({ ...editingSource, password: e.target.value })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setEditingSource(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
                >
                  Simpan Konfigurasi
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
