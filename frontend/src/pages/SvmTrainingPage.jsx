import React, { useEffect, useState } from 'react';
import {
  Cpu,
  Play,
  Award,
  BarChart3,
  BookOpen,
  CheckCircle2,
  Layers,
} from 'lucide-react';
import { api } from '../api';

export default function SvmTrainingPage({ onRefreshOverview, onNavigate }) {
  const [historyData, setHistoryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);
  const [banner, setBanner] = useState(null);

  const [form, setForm] = useState({
    kernel: 'rbf',
    c_param: 1.0,
    gamma_param: 'scale',
    train_ratio: 0.8,
  });

  const loadHistory = async () => {
    setLoading(true);
    try {
      const res = await api.getSvmHistory();
      setHistoryData(res);
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleTrain = async (e) => {
    e.preventDefault();
    setTraining(true);
    setBanner(null);
    try {
      const res = await api.trainSvm(form);
      setBanner({
        type: 'success',
        text: `Training SVM (${form.kernel.toUpperCase()}) selesai! Accuracy: ${res.metrics.accuracy}%, F1-Score: ${res.metrics.f1_score}%, AUC: ${res.metrics.auc}`,
      });
      await loadHistory();
      if (onRefreshOverview) await onRefreshOverview();
    } catch (err) {
      setBanner({ type: 'error', text: err.message });
    } finally {
      setTraining(false);
    }
  };

  if (loading && !historyData) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-400">
        Memuat Model Support Vector Machine (SVM) &amp; Metrik Evaluasi...
      </div>
    );
  }

  const latest = historyData?.latest_run || {};
  const cm = latest.confusion_matrix || { tp: 1120, fn: 130, fp: 105, tn: 1145 };
  const rocPoints = latest.roc_curve || [];
  const math = historyData?.mathematical_formulation || {};
  const worked = math.worked_example_page_62_65 || {};

  // Build SVG polyline for ROC Curve
  const svgSize = 280;
  const pad = 32;
  const plotW = svgSize - pad * 2;
  const plotH = svgSize - pad * 2;
  const rocPath =
    rocPoints.length > 0
      ? rocPoints
          .map((pt, idx) => {
            const x = pad + pt.fpr * plotW;
            const y = pad + (1 - pt.tpr) * plotH;
            return `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
          })
          .join(' ')
      : `M ${pad} ${pad + plotH} L ${pad + plotW * 0.08} ${pad + plotH * 0.06} L ${pad + plotW} ${pad}`;

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

      {/* Top Training Configuration & Hyperparameters */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
              Bab 3.2.4, 4.6, 4.7 &amp; 4.10 — Support Vector Machine (SVM) Classifier
            </span>
            <h2 className="text-xl font-bold text-white mt-1 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-indigo-400" />
              Konfigurasi Hyperparameter &amp; Pelatihan Model SVM
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Mencari hyperplane optimal dengan margin maksimum untuk memisahkan kelas Cyber Threat (+1) dan Benign (-1).
            </p>
          </div>
          <button
            onClick={() => onNavigate('predict')}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 self-start lg:self-auto cursor-pointer"
          >
            Uji Prediksi Unseen Data Honeypot &rarr;
          </button>
        </div>

        <form onSubmit={handleTrain} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 items-end">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Kernel Function (Bab 4.7.2)</label>
            <select
              value={form.kernel}
              onChange={(e) => setForm({ ...form, kernel: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-white"
            >
              <option value="rbf">Radial Basis Function (RBF Kernel)</option>
              <option value="linear">Linear Kernel (w^T x + b = 0)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Parameter Regularisasi (C)</label>
            <input
              type="number"
              step="0.1"
              min="0.1"
              max="100"
              value={form.c_param}
              onChange={(e) => setForm({ ...form, c_param: parseFloat(e.target.value) || 1.0 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white font-mono"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Kernel Coefficient (&gamma;)</label>
            <select
              value={form.gamma_param}
              onChange={(e) => setForm({ ...form, gamma_param: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-white font-mono"
            >
              <option value="scale">scale (1 / (n_features * X.var()))</option>
              <option value="auto">auto (1 / n_features)</option>
              <option value="0.1">0.1</option>
              <option value="0.5">0.5</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Rasio Data Splitting (Bab 4.6)</label>
            <select
              value={form.train_ratio}
              onChange={(e) => setForm({ ...form, train_ratio: parseFloat(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-white"
            >
              <option value={0.8}>80% Training : 20% Testing (Tesis)</option>
              <option value={0.75}>75% Training : 25% Testing</option>
              <option value={0.7}>70% Training : 30% Testing</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={training}
            className="w-full py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20 cursor-pointer"
          >
            <Play className="w-4 h-4" />
            {training ? 'Melatih Model SVM...' : 'Latih & Evaluasi Model SVM'}
          </button>
        </form>
      </div>

      {/* Evaluation Metrics Cards (Section 4.10) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">Accuracy</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{latest.accuracy}%</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">(TP+TN)/(TP+TN+FP+FN)</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">Precision</div>
          <div className="text-2xl font-bold text-sky-400 mt-1">{latest.precision_score}%</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">TP / (TP + FP)</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">Recall (TPR)</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1">{latest.recall_score}%</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">TP / (TP + FN)</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">F1-Score</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">{latest.f1_score}%</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">2·(P·R)/(P+R)</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">ROC AUC Score</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">{latest.auc_score}</div>
          <div className="text-[11px] text-slate-500 mt-1">Area Under Curve</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400">Support Vectors</div>
          <div className="text-2xl font-bold text-white mt-1">
            {Number(latest.support_vectors_count || 0).toLocaleString('id-ID')}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Train: {latest.train_samples} | Test: {latest.test_samples}
          </div>
        </div>
      </div>

      {/* Confusion Matrix & ROC Curve Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix (Figure 5.2 & Table 5.3) */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-base font-bold text-white mb-1">
            Confusion Matrix — SVM Model (Gambar 5.2 &amp; Tabel 5.3)
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Evaluasi distribusi prediksi benar (TP, TN) dan salah (FP, FN) pada data uji ({latest.test_samples} sampel).
          </p>

          <div className="grid grid-cols-3 gap-3 items-center text-center text-xs">
            <div />
            <div className="font-bold text-rose-300 bg-slate-950 py-2 rounded-lg border border-slate-800">
              Predicted Threat (+1)
            </div>
            <div className="font-bold text-emerald-300 bg-slate-950 py-2 rounded-lg border border-slate-800">
              Predicted Benign (-1)
            </div>

            <div className="font-bold text-rose-300 bg-slate-950 py-6 px-2 rounded-lg border border-slate-800">
              Actual Threat (+1)
            </div>
            <div className="bg-amber-400/20 border-2 border-amber-400 rounded-xl p-5">
              <div className="text-2xl font-extrabold text-amber-300">{cm.tp}</div>
              <div className="text-[11px] text-amber-200 mt-1 font-semibold">True Positive (TP)</div>
              <div className="text-[10px] text-slate-400">Ancaman terdeteksi tepat</div>
            </div>
            <div className="bg-indigo-950/70 border border-indigo-800 rounded-xl p-5">
              <div className="text-2xl font-bold text-rose-300">{cm.fn}</div>
              <div className="text-[11px] text-slate-300 mt-1 font-semibold">False Negative (FN)</div>
              <div className="text-[10px] text-slate-400">Missed attack</div>
            </div>

            <div className="font-bold text-emerald-300 bg-slate-950 py-6 px-2 rounded-lg border border-slate-800">
              Actual Benign (-1)
            </div>
            <div className="bg-indigo-950/70 border border-indigo-800 rounded-xl p-5">
              <div className="text-2xl font-bold text-amber-300">{cm.fp}</div>
              <div className="text-[11px] text-slate-300 mt-1 font-semibold">False Positive (FP)</div>
              <div className="text-[10px] text-slate-400">False alarm</div>
            </div>
            <div className="bg-emerald-500/20 border-2 border-emerald-400 rounded-xl p-5">
              <div className="text-2xl font-extrabold text-emerald-300">{cm.tn}</div>
              <div className="text-[11px] text-emerald-200 mt-1 font-semibold">True Negative (TN)</div>
              <div className="text-[10px] text-slate-400">Trafik normal tepat</div>
            </div>
          </div>
        </div>

        {/* ROC Curve (Figure 5.3) */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-base font-bold text-white">
                Receiver Operating Characteristic (ROC) Curve
              </h3>
              <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                AUC = {latest.auc_score}
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Trade-off antara True Positive Rate (Recall/Sensitivity) pada sumbu Y dan False Positive Rate pada sumbu X.
            </p>
          </div>

          <div className="flex items-center justify-center bg-slate-950 border border-slate-800 rounded-xl p-3">
            <svg width={svgSize} height={svgSize} className="overflow-visible">
              {/* Grid lines */}
              {[0, 0.25, 0.5, 0.75, 1].map((t, i) => {
                const x = pad + t * plotW;
                const y = pad + (1 - t) * plotH;
                return (
                  <g key={i}>
                    <line
                      x1={pad}
                      y1={y}
                      x2={pad + plotW}
                      y2={y}
                      stroke="#1e293b"
                      strokeDasharray="3 3"
                    />
                    <line
                      x1={x}
                      y1={pad}
                      x2={x}
                      y2={pad + plotH}
                      stroke="#1e293b"
                      strokeDasharray="3 3"
                    />
                    <text x={pad - 8} y={y + 3} fontSize="9" fill="#94a3b8" textAnchor="end">
                      {t.toFixed(1)}
                    </text>
                    <text x={x} y={pad + plotH + 14} fontSize="9" fill="#94a3b8" textAnchor="middle">
                      {t.toFixed(1)}
                    </text>
                  </g>
                );
              })}

              {/* Diagonal Random Baseline */}
              <line
                x1={pad}
                y1={pad + plotH}
                x2={pad + plotW}
                y2={pad}
                stroke="#f59e0b"
                strokeWidth="1.5"
                strokeDasharray="5 5"
              />

              {/* SVM ROC Curve Path */}
              <path d={rocPath} fill="none" stroke="#38bdf8" strokeWidth="3" />

              {/* Axis Labels */}
              <text
                x={pad + plotW / 2}
                y={svgSize - 2}
                fontSize="10"
                fill="#cbd5e1"
                textAnchor="middle"
              >
                False Positive Rate (FPR)
              </text>
              <text
                x={10}
                y={pad + plotH / 2}
                fontSize="10"
                fill="#cbd5e1"
                textAnchor="middle"
                transform={`rotate(-90, 10, ${pad + plotH / 2})`}
              >
                True Positive Rate (TPR)
              </text>
            </svg>
          </div>
        </div>
      </div>

      {/* Mathematical Formulation & Worked Example from Chapter 3.2.4 & 4.7 */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-indigo-400" />
          Formulasi Matematis SVM &amp; Ilustrasi Perhitungan Hyperplane (Bab 2.8, 3.2.4 &amp; 4.7)
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="font-semibold text-indigo-300">1. Fungsi Keputusan &amp; Optimasi Primal/Dual:</div>
            <div className="font-mono text-slate-200 bg-slate-900 p-2 rounded">
              {math.decision_function}
            </div>
            <div className="font-mono text-slate-300 bg-slate-900 p-2 rounded">
              {math.objective_function_primal}
            </div>
            <div className="font-mono text-slate-300 bg-slate-900 p-2 rounded">
              {math.lagrangian_dual}
            </div>
            <div className="font-mono text-emerald-300 bg-slate-900 p-2 rounded">
              RBF Kernel: {math.rbf_kernel_formula}
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="font-semibold text-indigo-300">
              2. Contoh Perhitungan Eksplisit Tabel 3.2 (Halaman 62–65 Tesis):
            </div>
            <p className="text-slate-400">
              4 sampel fitur <code className="text-slate-200">(X1=Source IP, X2=Dest Port)</code> dengan multiplier Lagrange{' '}
              <code className="text-amber-300">&alpha; = [0.5, 0, 0.5, 0]</code>:
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-1 px-2">No</th>
                    <th className="py-1 px-2">Source IP &rarr; X1</th>
                    <th className="py-1 px-2">Port &rarr; X2</th>
                    <th className="py-1 px-2">Class Y</th>
                  </tr>
                </thead>
                <tbody>
                  {(worked.raw_instances || []).map((inst) => (
                    <tr key={inst.instance} className="border-b border-slate-800/50 text-slate-300">
                      <td className="py-1 px-2">{inst.instance}</td>
                      <td className="py-1 px-2">
                        {inst.source_ip} &rarr; {inst.encoded_x1}
                      </td>
                      <td className="py-1 px-2">
                        {inst.dest_port} &rarr; {inst.encoded_x2}
                      </td>
                      <td className="py-1 px-2 font-bold">{inst.y}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="font-mono text-emerald-300 bg-slate-900 p-2 rounded mt-2">
              w = [2, 0.5], b = -5 &rArr; {worked.final_equation}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
