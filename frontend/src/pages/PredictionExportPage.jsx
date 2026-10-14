import React, { useEffect, useState } from 'react';
import {
  Crosshair,
  Download,
  FileCode,
  FileJson,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { api } from '../api';

export default function PredictionExportPage({ onRefreshOverview }) {
  const [predData, setPredData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState('');
  const [banner, setBanner] = useState(null);
  const [filterClass, setFilterClass] = useState('ALL');
  const [exportPreview, setExportPreview] = useState(null);

  const [singleForm, setSingleForm] = useState({
    source_ip: '68.183.55.117',
    port: 22,
    protocol: 'TCP',
    payload_size: 1024,
    attack_type: 'SSH Brute Force',
    ip_reputation_score: 91.5,
    attack_frequency: 45,
    file_hash_score: 88.0,
    honeypot_sensor: 'Cowrie',
    domain_name: 'circl.lu',
  });

  const loadPredictions = async () => {
    setLoading(true);
    try {
      const res = await api.getPredictions();
      setPredData(res);
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPredictions();
  }, []);

  const handlePredictSingle = async (e) => {
    e.preventDefault();
    setActionLoading('single');
    setBanner(null);
    try {
      const res = await api.predictUnseen({ records: [singleForm] });
      const first = res.result?.predictions?.[0];
      setBanner({
        type: first?.predicted_label === 1 ? 'warning' : 'success',
        text: `Hasil Prediksi SVM untuk IP ${singleForm.source_ip}: ${first?.prediction_text} | f(x) = ${first?.decision_value} | Confidence: ${first?.confidence_score}%`,
      });
      await loadPredictions();
      if (onRefreshOverview) await onRefreshOverview();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setActionLoading('');
    }
  };

  const handlePullHoneypotBatch = async () => {
    setActionLoading('batch');
    setBanner(null);
    try {
      const res = await api.predictHoneypotBatch({ count: 10 });
      setBanner({ type: 'success', text: res.message });
      await loadPredictions();
      if (onRefreshOverview) await onRefreshOverview();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setActionLoading('');
    }
  };

  const triggerDownload = (filename, content, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportWazuh = async (downloadImmediately = true) => {
    setActionLoading('wazuh');
    try {
      const res = await api.exportWazuhRules();
      setExportPreview({
        type: 'Wazuh Custom IDS XML Rules',
        filename: res.filename,
        count: `${res.rule_count} IP Rules`,
        content: res.xml_content,
        mime: 'application/xml',
      });
      if (downloadImmediately) {
        triggerDownload(res.filename, res.xml_content, 'application/xml');
      }
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setActionLoading('');
    }
  };

  const handleExportMisp = async (downloadImmediately = true) => {
    setActionLoading('misp');
    try {
      const res = await api.exportMispFeed();
      setExportPreview({
        type: 'MISP Event & Attributes JSON Feed (Gambar 3.3 Tesis)',
        filename: res.filename,
        count: `${res.threat_count} Threats (${res.attribute_count} IoC Attributes)`,
        content: res.json_content,
        mime: 'application/json',
      });
      if (downloadImmediately) {
        triggerDownload(res.filename, res.json_content, 'application/json');
      }
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setActionLoading('');
    }
  };

  const fillPreset = (presetType) => {
    if (presetType === 'threat') {
      setSingleForm({
        source_ip: '222.174.141.18',
        port: 3389,
        protocol: 'TCP',
        payload_size: 4096,
        attack_type: 'Malware Payload',
        ip_reputation_score: 95.4,
        attack_frequency: 68,
        file_hash_score: 92.0,
        honeypot_sensor: 'Amun',
        domain_name: 'c2-botnet-node.ru',
      });
    } else {
      setSingleForm({
        source_ip: '10.0.14.22',
        port: 443,
        protocol: 'TCP',
        payload_size: 240,
        attack_type: 'Normal',
        ip_reputation_score: 6.5,
        attack_frequency: 2,
        file_hash_score: 4.0,
        honeypot_sensor: 'Cowrie',
        domain_name: 'internal.corp.local',
      });
    }
  };

  const predictions = predData?.predictions || [];
  const filteredPredictions = predictions.filter((p) => {
    if (filterClass === 'THREAT') return Number(p.predicted_label) === 1;
    if (filterClass === 'BENIGN') return Number(p.predicted_label) === -1;
    return true;
  });

  return (
    <div className="space-y-6">
      {banner && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between ${
            banner.type === 'error'
              ? 'bg-red-950/60 border-red-700 text-red-200'
              : banner.type === 'warning'
              ? 'bg-rose-950/70 border-rose-600 text-rose-200'
              : 'bg-emerald-950/60 border-emerald-700 text-emerald-200'
          }`}
        >
          <span className="text-sm font-medium">{banner.text}</span>
          <button onClick={() => setBanner(null)} className="text-xs underline ml-4">
            Tutup
          </button>
        </div>
      )}

      {/* Top Section: Single Prediction Form & Export Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Uji Prediksi Unseen Data Honeypot */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
                Bab 3.2.6 &amp; 4.8 — Prediction of New Unseen Data
              </span>
              <h3 className="text-lg font-bold text-white flex items-center gap-2 mt-0.5">
                <Crosshair className="w-5 h-5 text-indigo-400" />
                Uji Prediksi SVM pada Data Baru (Honeypot Sensor)
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <button
                type="button"
                onClick={() => fillPreset('threat')}
                className="px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-300 border border-rose-500/30 hover:bg-rose-500/30 cursor-pointer"
              >
                Preset Serangan Amun
              </button>
              <button
                type="button"
                onClick={() => fillPreset('benign')}
                className="px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 cursor-pointer"
              >
                Preset Trafik Normal
              </button>
            </div>
          </div>

          <form onSubmit={handlePredictSingle} className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Source IP</label>
              <input
                type="text"
                value={singleForm.source_ip}
                onChange={(e) => setSingleForm({ ...singleForm, source_ip: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Destination Port</label>
              <input
                type="number"
                value={singleForm.port}
                onChange={(e) => setSingleForm({ ...singleForm, port: Number(e.target.value) })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Protocol</label>
              <select
                value={singleForm.protocol}
                onChange={(e) => setSingleForm({ ...singleForm, protocol: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Payload Size (Bytes)</label>
              <input
                type="number"
                value={singleForm.payload_size}
                onChange={(e) =>
                  setSingleForm({ ...singleForm, payload_size: Number(e.target.value) })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Attack Type / Pattern</label>
              <select
                value={singleForm.attack_type}
                onChange={(e) => setSingleForm({ ...singleForm, attack_type: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              >
                <option value="SSH Brute Force">SSH Brute Force</option>
                <option value="DDoS">DDoS</option>
                <option value="DNS Flood">DNS Flood</option>
                <option value="SQL Injection">SQL Injection</option>
                <option value="Malware Payload">Malware Payload</option>
                <option value="Port Scanning">Port Scanning</option>
                <option value="Normal">Normal</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">IP Reputation (0-100)</label>
              <input
                type="number"
                step="0.1"
                value={singleForm.ip_reputation_score}
                onChange={(e) =>
                  setSingleForm({
                    ...singleForm,
                    ip_reputation_score: parseFloat(e.target.value) || 0,
                  })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Attack Frequency</label>
              <input
                type="number"
                value={singleForm.attack_frequency}
                onChange={(e) =>
                  setSingleForm({ ...singleForm, attack_frequency: Number(e.target.value) })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">File Hash Score (0-100)</label>
              <input
                type="number"
                step="0.1"
                value={singleForm.file_hash_score}
                onChange={(e) =>
                  setSingleForm({
                    ...singleForm,
                    file_hash_score: parseFloat(e.target.value) || 0,
                  })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>

            <div className="col-span-2 sm:col-span-4 flex flex-wrap items-center gap-3 pt-2">
              <button
                type="submit"
                disabled={actionLoading === 'single'}
                className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold flex items-center gap-2 cursor-pointer"
              >
                <Zap className="w-4 h-4" />
                {actionLoading === 'single' ? 'Mengklasifikasi...' : 'Klasifikasikan dengan Model SVM'}
              </button>

              <button
                type="button"
                onClick={handlePullHoneypotBatch}
                disabled={actionLoading === 'batch'}
                className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 font-medium border border-slate-700 flex items-center gap-2 cursor-pointer"
              >
                <RefreshCw className={`w-4 h-4 ${actionLoading === 'batch' ? 'animate-spin' : ''}`} />
                Tarik &amp; Prediksi 10 Log Baru Honeypot (Cowrie/Amun)
              </button>
            </div>
          </form>
        </div>

        {/* Manual Export Panel (Wazuh XML Rules & MISP JSON Feed) */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
              Bab 3.3 (Gambar 3.6) — Proactive Defense Output
            </span>
            <h3 className="text-lg font-bold text-white mt-0.5">
              Ekspor Manual Rules IDS Wazuh &amp; Feeder MISP
            </h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Seluruh trafik Honeypot yang diprediksi sebagai <strong className="text-rose-300">Cyber Threat (+1)</strong> oleh SVM dapat diekspor menjadi aturan pemblokiran IDS <strong>Wazuh (`.xml`)</strong> dan threat feed <strong>MISP (`.json`)</strong>.
            </p>
          </div>

          <div className="space-y-3 mt-4">
            <div className="flex gap-2">
              <button
                onClick={() => handleExportWazuh(true)}
                disabled={actionLoading === 'wazuh'}
                className="flex-1 py-2.5 px-3 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
              >
                <FileCode className="w-4 h-4" />
                Download Wazuh Rules (.xml)
              </button>
              <button
                onClick={() => handleExportWazuh(false)}
                className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 cursor-pointer"
              >
                Preview
              </button>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => handleExportMisp(true)}
                disabled={actionLoading === 'misp'}
                className="flex-1 py-2.5 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
              >
                <FileJson className="w-4 h-4" />
                Download MISP Feed (.json)
              </button>
              <button
                onClick={() => handleExportMisp(false)}
                className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 cursor-pointer"
              >
                Preview
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Preview Modal / Panel for Exported Wazuh XML or MISP JSON */}
      {exportPreview && (
        <div className="bg-slate-900 border border-indigo-500/40 rounded-2xl p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h4 className="text-sm font-bold text-white">
                Preview File Ekspor: {exportPreview.type}
              </h4>
              <p className="text-xs text-slate-400">
                Nama File: <code className="text-indigo-300">{exportPreview.filename}</code> ({exportPreview.count})
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() =>
                  triggerDownload(
                    exportPreview.filename,
                    exportPreview.content,
                    exportPreview.mime
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" /> Download File
              </button>
              <button
                onClick={() => setExportPreview(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs cursor-pointer"
              >
                Tutup Preview
              </button>
            </div>
          </div>
          <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 overflow-x-auto max-h-72">
            {exportPreview.content}
          </pre>
        </div>
      )}

      {/* Predictions History Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
          <div>
            <h3 className="text-base font-bold text-white">
              Daftar Hasil Prediksi SVM pada Unseen Data Honeypot ({predData?.total || 0} Log)
            </h3>
            <p className="text-xs text-slate-400">
              Terdeteksi sebagai Cyber Threat (+1):{' '}
              <strong className="text-rose-400">{predData?.threat_count || 0}</strong> | Benign (-1):{' '}
              <strong className="text-emerald-400">{predData?.benign_count || 0}</strong>
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            {[
              { id: 'ALL', label: `Semua (${predData?.total || 0})` },
              { id: 'THREAT', label: `Cyber Threat +1 (${predData?.threat_count || 0})` },
              { id: 'BENIGN', label: `Benign -1 (${predData?.benign_count || 0})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterClass(tab.id)}
                className={`px-3 py-1.5 rounded-lg font-semibold cursor-pointer ${
                  filterClass === tab.id
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Sensor</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Port / Proto</th>
                <th className="py-2.5 px-3">Payload</th>
                <th className="py-2.5 px-3">Attack Pattern</th>
                <th className="py-2.5 px-3">IP Rep / Freq</th>
                <th className="py-2.5 px-3">Decision f(x)</th>
                <th className="py-2.5 px-3">Prediksi SVM</th>
              </tr>
            </thead>
            <tbody>
              {filteredPredictions.map((row) => {
                const isThreat = Number(row.predicted_label) === 1;
                return (
                  <tr key={row.id} className="border-b border-slate-800/60 hover:bg-slate-950/50">
                    <td className="py-2.5 px-3 font-mono text-slate-400">{row.timestamp}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-medium">
                        {row.honeypot_sensor}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-white font-semibold">
                      {row.source_ip}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {row.port} / {row.protocol}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{row.payload_size} B</td>
                    <td className="py-2.5 px-3 text-slate-200">{row.attack_type}</td>
                    <td className="py-2.5 px-3 font-mono text-slate-400">
                      {row.ip_reputation_score} / {row.attack_frequency}x
                    </td>
                    <td className="py-2.5 px-3 font-mono text-indigo-300">
                      {Number(row.decision_value).toFixed(3)}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold ${
                          isThreat
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        {isThreat ? (
                          <>
                            <ShieldAlert className="w-3.5 h-3.5" /> Threat (+1) ({row.confidence_score}%)
                          </>
                        ) : (
                          <>
                            <ShieldCheck className="w-3.5 h-3.5" /> Benign (-1) ({row.confidence_score}%)
                          </>
                        )}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
