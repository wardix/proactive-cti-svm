import React, { useEffect, useState } from 'react';
import {
  Filter,
  Sparkles,
  CheckCircle,
  AlertTriangle,
  Sliders,
  Layers,
  Play,
} from 'lucide-react';
import { api } from '../api';

export default function PreprocessingPage({ onNavigate }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [threshold, setThreshold] = useState(0.92);
  const [activeStage, setActiveStage] = useState('cleaning');

  const runPipeline = async (corrVal = threshold) => {
    setLoading(true);
    try {
      const res = await api.runPreprocessing({ correlation_threshold: Number(corrVal) });
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runPipeline(0.92);
  }, []);

  if (loading && !data) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-400">
        Menjalankan Pipeline Data Cleaning, Validation, Feature Selection &amp; Z-Score Scaling...
      </div>
    );
  }

  const report = data?.preprocessing_report || {};
  const counts = report.counts || {};
  const impStats = report.imputation_stats || {};
  const examples = report.stage_examples || {};
  const featReport = data?.feature_selection_report || {};
  const corrMatrix = featReport.correlation_matrix || {};
  const corrCols = Object.keys(corrMatrix);

  return (
    <div className="space-y-6">
      {/* Header & Pipeline Formula */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
            Bab 4.2, 4.4 &amp; 4.5 — Data Flow &amp; Preprocessing Pipeline
          </span>
          <h2 className="text-xl font-bold text-white mt-1">
            Data Cleaning, Validation, Feature Selection &amp; Z-Score Standardization
          </h2>
          <div className="mt-2 inline-block bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-indigo-300">
            D_raw &rarr; (extract) &rarr; D_structured &rarr; (clean &amp; validate) &rarr; D_clean &rarr; (transform &amp; scale) &rarr; D_feature &rarr; &#123;D_train, D_test&#125;
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs">
            <span className="text-slate-400">Correlation Threshold:</span>
            <input
              type="number"
              step="0.02"
              min="0.50"
              max="1.00"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-white font-mono"
            />
          </div>
          <button
            onClick={() => runPipeline(threshold)}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            {loading ? 'Memproses...' : 'Jalankan Ulang Pipeline'}
          </button>
          <button
            onClick={() => onNavigate('svm')}
            className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 cursor-pointer"
          >
            Lanjut ke Training SVM &rarr;
          </button>
        </div>
      </div>

      {/* Pipeline Counts Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">1. Raw Dataset (D)</div>
          <div className="text-xl font-bold text-white mt-1">
            {(counts.initial_raw_records || 0).toLocaleString('id-ID')}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">2. Corrupt Dihapus</div>
          <div className="text-xl font-bold text-rose-400 mt-1">
            -{counts.corrupted_removed_count || 0}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">3. Duplikat Dihapus</div>
          <div className="text-xl font-bold text-amber-400 mt-1">
            -{counts.duplicates_removed_count || 0}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">4. Missing Diimputasi</div>
          <div className="text-xl font-bold text-sky-400 mt-1">
            {counts.imputed_records_count || 0} baris
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">5. Anomali Rentang</div>
          <div className="text-xl font-bold text-purple-400 mt-1">
            {counts.range_anomalies_count || 0} koreksi
          </div>
        </div>
        <div className="bg-slate-900 border border-emerald-800/60 rounded-xl p-4">
          <div className="text-xs text-emerald-300">6. Dataset Bersih (D_clean)</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">
            {(counts.final_clean_records || 0).toLocaleString('id-ID')}
          </div>
        </div>
      </div>

      {/* Stage Sub-Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'cleaning', label: '1. Data Cleaning (Tabel 4.2 – 4.9)', icon: Sparkles },
          { id: 'validation', label: '2. Data Validation (Tabel 4.10 – 4.15)', icon: CheckCircle },
          { id: 'features', label: '3. Feature Selection & Korelasi (Tabel 4.16)', icon: Filter },
          { id: 'encoding', label: '4. Encoding & Z-Score Scaling (Bab 4.5)', icon: Sliders },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveStage(tab.id)}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer transition ${
                activeStage === tab.id
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* STAGE 1: DATA CLEANING */}
      {activeStage === 'cleaning' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Duplicate Removal */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white">
                a. Penghapusan Duplikat (Tabel 4.2 &amp; 4.3)
              </h3>
              <code className="text-xs text-indigo-300 bg-slate-950 px-2 py-0.5 rounded">
                D_clean = D - D_duplicate
              </code>
            </div>
            <p className="text-xs text-slate-400">
              Mengidentifikasi dan menghapus baris yang memiliki seluruh nilai atribut identik (`timestamp`, `source_ip`, `protocol`, `port`, `payload_size`).
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">Timestamp</th>
                    <th className="py-2 px-2">Source IP</th>
                    <th className="py-2 px-2">Proto</th>
                    <th className="py-2 px-2">Port</th>
                    <th className="py-2 px-2">Payload</th>
                    <th className="py-2 px-2">Attack Type</th>
                  </tr>
                </thead>
                <tbody>
                  {(examples.duplicates_removed || []).map((r, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60 text-amber-300">
                      <td className="py-2 px-2 font-mono">{r.timestamp}</td>
                      <td className="py-2 px-2 font-mono">{r.source_ip}</td>
                      <td className="py-2 px-2">{r.protocol}</td>
                      <td className="py-2 px-2">{r.port}</td>
                      <td className="py-2 px-2">{r.payload_size}</td>
                      <td className="py-2 px-2">{r.attack_type} (Dihapus)</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Missing Values Imputation */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white">
                b. Imputasi Missing Values (Tabel 4.4 &amp; 4.5)
              </h3>
              <span className="text-xs text-sky-400 font-mono">
                Mean = {impStats.thesis_example_mean} | Mode = {impStats.categorical_mode_protocol}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Fitur numerik (<code className="text-slate-200">payload_size</code>) diimputasi dengan <strong>Mean</strong> ((1500+800+1200)/3 = 1166.67 pada contoh tesis, atau rata-rata dataset: {impStats.numerical_mean_payload_size}), sedangkan kategorikal (<code className="text-slate-200">protocol</code>, <code className="text-slate-200">attack_type</code>) dengan <strong>Mode</strong>.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">Source IP</th>
                    <th className="py-2 px-2">Atribut yang Diimputasi</th>
                    <th className="py-2 px-2">Payload</th>
                    <th className="py-2 px-2">Proto</th>
                    <th className="py-2 px-2">Attack Type</th>
                  </tr>
                </thead>
                <tbody>
                  {(examples.imputed_records || []).map((r, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60 text-slate-200">
                      <td className="py-2 px-2 font-mono">{r.source_ip}</td>
                      <td className="py-2 px-2 text-sky-300">{r.imputed_fields}</td>
                      <td className="py-2 px-2 font-mono">{r.payload_size}</td>
                      <td className="py-2 px-2">{r.protocol}</td>
                      <td className="py-2 px-2">{r.attack_type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Filtering Irrelevant Attributes */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">
              c. Penyaringan Atribut Tidak Relevan (Tabel 4.6 &amp; 4.7)
            </h3>
            <div className="space-y-2">
              {(examples.irrelevant_attributes_filtered || []).map((item, i) => (
                <div
                  key={i}
                  className="bg-slate-950 border border-slate-800 rounded-lg p-3 flex items-center justify-between text-xs"
                >
                  <code className="text-rose-300 font-semibold">{item.attribute}</code>
                  <span className="text-slate-400">{item.reason}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Standardizing Formats */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">
              d. Standardisasi Format Data (Tabel 4.8 &amp; 4.9)
            </h3>
            <p className="text-xs text-slate-400">
              Menyeragamkan timestamp ke ISO (`YYYY-MM-DD HH:MM:SS`), protokol ke kapital (`TCP`/`UDP`), dan menghapus satuan teks `"bytes"` pada payload.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">IP</th>
                    <th className="py-2 px-2">Timestamp (Sebelum &rarr; Sesudah)</th>
                    <th className="py-2 px-2">Protokol</th>
                    <th className="py-2 px-2">Payload</th>
                  </tr>
                </thead>
                <tbody>
                  {(examples.standardized_records || []).map((r, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60 text-slate-200">
                      <td className="py-2 px-2 font-mono">{r.source_ip}</td>
                      <td className="py-2 px-2 font-mono">
                        <span className="text-rose-300">{r.before_timestamp}</span> &rarr;{' '}
                        <span className="text-emerald-300">{r.after_timestamp}</span>
                      </td>
                      <td className="py-2 px-2 font-mono">
                        {r.before_protocol} &rarr; <span className="text-emerald-300">{r.after_protocol}</span>
                      </td>
                      <td className="py-2 px-2 font-mono">
                        {r.before_payload} &rarr; <span className="text-emerald-300">{r.after_payload}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* STAGE 2: DATA VALIDATION */}
      {activeStage === 'validation' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Feature Range Validation */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Verifikasi Rentang Fitur (Tabel 4.12 &amp; 4.13)
            </h3>
            <p className="text-xs text-slate-400">
              Memastikan <code className="text-slate-200">port</code> berada dalam batas valid <code className="text-emerald-300">0–65535</code> dan <code className="text-slate-200">payload_size &ge; 0</code>.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">Source IP</th>
                    <th className="py-2 px-2">Port</th>
                    <th className="py-2 px-2">Payload</th>
                    <th className="py-2 px-2">Tindakan Validasi</th>
                  </tr>
                </thead>
                <tbody>
                  {(examples.range_validation_issues || []).map((r, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60 text-slate-200">
                      <td className="py-2 px-2 font-mono">{r.source_ip}</td>
                      <td className="py-2 px-2 font-mono text-rose-300">{r.port}</td>
                      <td className="py-2 px-2 font-mono text-rose-300">{r.payload_size}</td>
                      <td className="py-2 px-2 text-amber-300">{r.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Corrupted Entries Removal */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              Penghapusan Entri Corrupt (Tabel 4.14 &amp; 4.15)
            </h3>
            <p className="text-xs text-slate-400">
              Membuang baris yang rusak akibat kegagalan transmisi/logging seperti <code className="text-rose-300">NULL</code> timestamp, alamat IP <code className="text-rose-300">???</code>, atau port <code className="text-rose-300">NaN</code>.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">Timestamp</th>
                    <th className="py-2 px-2">Source IP</th>
                    <th className="py-2 px-2">Port</th>
                    <th className="py-2 px-2">Alasan Penghapusan</th>
                  </tr>
                </thead>
                <tbody>
                  {(examples.corrupted_removed || []).map((r, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60 text-slate-200">
                      <td className="py-2 px-2 font-mono text-rose-300">{r.timestamp}</td>
                      <td className="py-2 px-2 font-mono text-rose-300">{r.source_ip}</td>
                      <td className="py-2 px-2 font-mono text-rose-300">{r.port}</td>
                      <td className="py-2 px-2 text-amber-300">{r.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* STAGE 3: FEATURE SELECTION & CORRELATION MATRIX */}
      {activeStage === 'features' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-base font-bold text-white mb-3">
              Tabel 4.16 — Fitur Terpilih dan Justifikasi (Feature Selection)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {(featReport.selected_features_table_4_16 || []).map((f, idx) => (
                <div
                  key={idx}
                  className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-1.5"
                >
                  <div className="text-xs font-bold text-indigo-300">{f.feature}</div>
                  <p className="text-xs text-slate-400 leading-relaxed">{f.justification}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4">
              <div>
                <h3 className="text-base font-bold text-white">
                  Matriks Korelasi Antar-Fitur (Correlation Analysis)
                </h3>
                <p className="text-xs text-slate-400">
                  Threshold redundansi: <code className="text-indigo-300">{featReport.correlation_threshold}</code> | Fitur redundan yang dibuang:{' '}
                  <code className="text-emerald-400">
                    {(featReport.dropped_redundant_features || []).length === 0
                      ? 'Tidak ada (Seluruh 9 dimensi vektor dipertahankan)'
                      : featReport.dropped_redundant_features.join(', ')}
                  </code>
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2 text-left">Fitur</th>
                    {corrCols.map((c) => (
                      <th key={c} className="py-2 px-2 text-right font-mono">
                        {c.replace('_encoded', '').replace('protocol_', 'p_').replace('_score', '')}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {corrCols.map((rCol) => (
                    <tr key={rCol} className="border-b border-slate-800/50">
                      <td className="py-2 px-2 font-mono text-slate-300 font-semibold">{rCol}</td>
                      {corrCols.map((cCol) => {
                        const val = corrMatrix[rCol]?.[cCol] ?? 0;
                        const absVal = Math.abs(val);
                        return (
                          <td
                            key={cCol}
                            className={`py-2 px-2 text-right font-mono ${
                              rCol === cCol
                                ? 'text-indigo-400 font-bold'
                                : absVal > 0.6
                                ? 'text-amber-300'
                                : 'text-slate-400'
                            }`}
                          >
                            {val.toFixed(2)}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* STAGE 4: ENCODING & Z-SCORE SCALING */}
      {activeStage === 'encoding' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
              <h3 className="text-sm font-bold text-white">
                Step 2 &amp; 3: Encoding Fitur Kategorikal &amp; Label Target (Bab 4.5)
              </h3>
              <div className="text-xs space-y-2 text-slate-300">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <div className="font-semibold text-indigo-300 mb-1">
                    a. Label Encoding — Attack Type:
                  </div>
                  <div className="flex flex-wrap gap-2 font-mono">
                    {Object.entries(featReport.encoding_maps?.attack_type_label_encoding || {}).map(
                      ([k, v]) => (
                        <span key={k} className="px-2 py-0.5 bg-slate-900 rounded border border-slate-800">
                          {k} &rarr; {v}
                        </span>
                      )
                    )}
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <div className="font-semibold text-indigo-300 mb-1">
                    b. One-Hot Encoding — Protocol:
                  </div>
                  <div className="font-mono text-slate-300">
                    {(featReport.encoding_maps?.protocol_one_hot_encoding || []).join(' | ')}
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <div className="font-semibold text-indigo-300 mb-1">
                    c. Target Class Label (Y):
                  </div>
                  <div className="font-mono text-slate-300">
                    Cyber Threat &rarr; <span className="text-rose-400 font-bold">+1</span> | Benign / No Threat &rarr;{' '}
                    <span className="text-emerald-400 font-bold">-1</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white">
                  Step 5: Feature Scaling / Z-Score Standardization
                </h3>
                <code className="text-xs text-emerald-300 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                  x&apos; = (x - &mu;) / &sigma;
                </code>
              </div>
              <p className="text-xs text-slate-400">
                Parameter Mean (&mu;) dan Standard Deviation (&sigma;) yang dihitung pada dataset untuk menormalisasi skala fitur sebelum masuk ke hyperplane SVM:
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-1.5 px-2">Fitur Numerik</th>
                      <th className="py-1.5 px-2 text-right">Mean (&mu;)</th>
                      <th className="py-1.5 px-2 text-right">Std Dev (&sigma;)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.keys(featReport.scaling_parameters?.means_mu || {}).map((col) => (
                      <tr key={col} className="border-b border-slate-800/50 font-mono">
                        <td className="py-1.5 px-2 text-slate-300">{col}</td>
                        <td className="py-1.5 px-2 text-right text-sky-300">
                          {featReport.scaling_parameters.means_mu[col]}
                        </td>
                        <td className="py-1.5 px-2 text-right text-amber-300">
                          {featReport.scaling_parameters.stds_sigma[col]}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Sample Numerical Feature Vectors */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-sm font-bold text-white mb-3">
              Step 4 &amp; 5: Contoh Transformasi Vektor Fitur X = (x_1, x_2, ..., x_n) Sebelum &amp; Sesudah Z-Score Scaling
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2">Source IP</th>
                    <th className="py-2 px-2">Attack &amp; Proto</th>
                    <th className="py-2 px-2">Vektor Numerik (Sebelum Scaling)</th>
                    <th className="py-2 px-2">Vektor Z-Score x&apos; (Input SVM)</th>
                    <th className="py-2 px-2">Label Y</th>
                  </tr>
                </thead>
                <tbody>
                  {(featReport.sample_numerical_vectors || []).map((row, idx) => (
                    <tr key={idx} className="border-b border-slate-800/60">
                      <td className="py-2 px-2 font-mono text-slate-300">{row.source_ip}</td>
                      <td className="py-2 px-2 text-slate-300">
                        {row.raw_attack_type} ({row.raw_protocol})
                      </td>
                      <td className="py-2 px-2 font-mono text-slate-400">
                        [{Object.values(row.unscaled_vector || {}).join(', ')}]
                      </td>
                      <td className="py-2 px-2 font-mono text-emerald-300">
                        [{Object.values(row.scaled_vector || {}).join(', ')}]
                      </td>
                      <td className="py-2 px-2 font-bold">
                        <span
                          className={`px-2 py-0.5 rounded ${
                            row.label === 1
                              ? 'bg-rose-500/20 text-rose-300'
                              : 'bg-emerald-500/20 text-emerald-300'
                          }`}
                        >
                          {row.label}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
