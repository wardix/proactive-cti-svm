# proactive-cti-svm — Proactive Cyber Security Defense Model (CTI + SVM)

Implementasi kode lengkap dari disertasi PhD:
> **"A Proactive Cyber Security Defense Model to Control Cyber Attacks Through Cyber Threat Intelligence"**
> *Syurahbil, Universiti Utara Malaysia (UUM), 2024*

---

## Arsitektur Sistem (Bab 4.9)

Sistem menggunakan arsitektur tiga lapis (*Three-Tier Architecture*):
1. **Frontend UI (`frontend/` — Port `5173`)**: React.js + Vite + Tailwind CSS dengan 4 menu utama tanpa layar login:
   - **Menu 01 — Overview & Koneksi CTI**: Konfigurasi & tarik data satu arah (*Pull*) dari **MISP**, **Wazuh**, dan **Honeypot (Cowrie / Amun)** (dengan mode Real API maupun Simulasi Tesis otomatis), plus generator 12.500 sampel dataset sesuai Tabel 5.1.
   - **Menu 02 — Pipeline Preprocessing & Validasi Data**: Visualisasi interaktif Bab 4.4 – 4.5 mencakup pembersihan data (Tabel 4.2–4.15), deduplikasi ($D_{\text{clean}} = D - D_{\text{duplicate}}$), imputasi Mean/Mode, validasi rentang port (`0–65535`) & payload, seleksi fitur *Correlation Matrix* (Tabel 4.16), *Label/One-Hot Encoding*, dan *Z-Score Standardization* ($x' = \frac{x - \mu}{\sigma}$, Tabel 4.17–4.18).
   - **Menu 03 — Training & Evaluasi SVM**: Pelatihan model **Support Vector Machine (SVM)** dengan kernel **RBF** dan **Linear** (pembagian data 80% Training : 20% Testing), *Confusion Matrix*, kurva *ROC & AUC*, serta penjabaran matematis hyperplane, margin $\frac{2}{\|w\|}$, dan *Lagrange Duality* (Bab 3.2.4).
   - **Menu 04 — Prediksi Unseen Data (Honeypot) & Ekspor Rule**: Pengujian model SVM terlatih terhadap lalu lintas Honeypot baru (*unseen data* Cowrie/Amun) dan fitur unduh/ekspor manual file **Wazuh Custom Rules (`.xml`)** serta **MISP Threat Feed (`.json`)**.
2. **Backend API (`backend/` — Port `8000`)**: Struktur aplikasi PHP bergaya Laravel (`app/Http/Controllers`, `app/Services`, `routes/api.php`) yang mendukung **SQLite** (aktif otomatis tanpa perlu instalasi server database tambahan) maupun **MySQL** (`database/schema.sql`).
3. **SVM Machine Learning Service (`ml-service/` — Port `8001`)**: Layanan mikro **Python FastAPI + Scikit-Learn + Pandas + NumPy** untuk pemrosesan data dan klasifikasi SVM biner ($\{+1 \text{ Threat}, -1 \text{ Benign}\}$).

---

## Cara Menjalankan Sistem (Satu Perintah)

Jalankan skrip peluncur dari direktori utama proyek:

```bash
./start.sh
```

Atau jalankan masing-masing layanan secara manual di terminal terpisah:

1. **Python FastAPI SVM Service (Port 8001)**
   ```bash
   cd ml-service
   .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001
   ```
2. **PHP Backend API (Port 8000)**
   ```bash
   cd backend
   php -S 127.0.0.1:8000 -t public public/index.php
   ```
3. **React.js Frontend Dashboard (Port 5173)**
   ```bash
   cd frontend
   npm run dev -- --host 127.0.0.1 --port 5173
   ```

Setelah berjalan, buka **`http://127.0.0.1:5173`** di browser.
