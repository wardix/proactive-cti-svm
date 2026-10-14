# Catatan Keputusan Desain & Implementasi (Architecture Decision Record)

**Nama Proyek:** `proactive-cti-svm` (*Proactive CTI-SVM*)  
**Deskripsi:** Implementasi Sistem *A Proactive Cyber Security Defense Model to Control Cyber Attacks Through Cyber Threat Intelligence*  
**Referensi Utama:** Disertasi PhD — Syurahbil (Universiti Utara Malaysia, 2024) ([thesis.pdf](file:///Users/wardix/agy/x/thesis.pdf))  
**Tanggal Sesi:** 14 Oktober 2026  

---

## Ringkasan Keputusan Utama

| No | Aspek | Keputusan yang Dipilih | Alasan / Rasional |
| :--- | :--- | :--- | :--- |
| **1** | **Arsitektur & Tech Stack** | **React.js** (Frontend) + **Laravel PHP** (Backend API) + **Python FastAPI / Scikit-Learn** (SVM Service) + **SQLite / MySQL** | Mengikuti spesifikasi arsitektur tiga lapis pada **Bab 4.9** tesis secara presisi namun tetap ringan dijalankan secara lokal. |
| **2** | **Sumber Data CTI** | **MISP**, **Wazuh**, dan **Honeypot (Cowrie / Amun)** dengan *Real API Connector* + *Simulation Fallback*. **Tanpa OpenCTI**. | Fokus pada 3 sumber utama yang memiliki skema atribut dan tabel sampel eksplisit pada Bab 3 & Bab 4 tesis. |
| **3** | **Arah Integrasi & Feedback Loop** | **Satu arah (*Pull & Predict*)** untuk akuisisi data; pembaruan aturan dilakukan via **ekspor/unduh manual file `.xml` (Wazuh) & `.json` (MISP)** dari dashboard. | Menghindari risiko penulisan otomatis ke sensor produksi sekaligus mempermudah demonstrasi & inspeksi hasil aturan IDS/CTI. |
| **4** | **Ruang Lingkup Machine Learning** | Fokus murni pada **Support Vector Machine (SVM)** dengan kernel **RBF** dan **Linear** (tanpa Random Forest / Gradient Boosting / Hybrid Ensemble). | Menjaga fokus implementasi pada kontribusi inti metodologi di **Bab 3** dan **Bab 4**. |
| **5** | **Antarmuka & Navigasi UI** | **Tanpa layar login** (langsung masuk Dashboard) dengan **4 menu utama** berurutan sesuai tahapan tesis. | Mempercepat alur demonstrasi akademik dari akuisisi data hingga prediksi *unseen data* dan ekspor aturan. |
| **6** | **Kalibrasi Dataset & Database Lokal** | Dataset 12.500 baris (6.800 *Threat* `+1`, 5.700 *Benign* `-1`) dengan ~8,2% *boundary overlap* + dukungan ganda **SQLite** (aktif otomatis) & **MySQL**. | Menghasilkan metrik evaluasi SVM yang realistis (~93–95% akurasi, ~0.97 AUC) sesuai Bab 5 tesis dan memastikan aplikasi langsung berjalan tanpa konfigurasi server tambahan. |

---

## Detail Keputusan per Bagian

### 1. Arsitektur Tiga Lapis (*Three-Tier Architecture* — Bab 4.9)
- **Keputusan:** Memisahkan sistem ke dalam 3 layanan independen:
  1. **Frontend (`frontend/`, Port `5173`)**: React.js + Vite + Tailwind CSS.
  2. **Backend API (`backend/`, Port `8000`)**: Struktur aplikasi PHP Laravel ([api.php](file:///Users/wardix/agy/x/backend/routes/api.php)) sebagai jembatan data, konektor CTI, manajemen database, dan generator file ekspor.
  3. **ML Service (`ml-service/`, Port `8001`)**: Layanan mikro Python FastAPI ([main.py](file:///Users/wardix/agy/x/ml-service/app/main.py)) yang menangani preprocessing Pandas/NumPy dan pemodelan `scikit-learn` (`svm.SVC`).
- **Penyimpanan Data:** Disediakan file DDL MySQL lengkap di [schema.sql](file:///Users/wardix/agy/x/database/schema.sql) serta dukungan penuh SQLite otomatis di [Database.php](file:///Users/wardix/agy/x/backend/app/Support/Database.php) ([database.sqlite](file:///Users/wardix/agy/x/backend/database/database.sqlite)).

### 2. Sumber Data Cyber Threat Intelligence (Bab 4.2 & 4.3)
- **Keputusan:** Hanya menyertakan **MISP**, **Wazuh**, dan **Honeypot (Cowrie / Amun)**, serta **mengecualikan OpenCTI**.
- **Implementasi Konektor Dual-Mode:**
  - [MispConnector.php](file:///Users/wardix/agy/x/backend/app/Services/MispConnector.php): Mendukung `POST /events/restSearch` dengan header API Key MISP asli maupun mode simulasi otomatis.
  - [WazuhConnector.php](file:///Users/wardix/agy/x/backend/app/Services/WazuhConnector.php): Mendukung autentikasi JWT `POST /security/user/authenticate` & `GET /alerts` maupun mode simulasi otomatis.
  - [HoneypotParser.php](file:///Users/wardix/agy/x/backend/app/Services/HoneypotParser.php): Mendukung pemindaian log Cowrie/Amun berformat JSON, JSON Lines (`.jsonl`), dan CSV.

### 3. Mekanisme Akuisisi Satu Arah (*Pull*) & Ekspor Aturan Manual (Bab 3.3 & 4.8)
- **Keputusan:** Sistem bekerja satu arah (*Pull & Predict*) saat mengambil log dari sumber CTI dan Honeypot. Untuk menutup siklus pertahanan proaktif (*proactive defense feedback loop*), pengguna mengunduh hasil deteksi ancaman (`predicted_label = +1`) secara manual dari dashboard dalam dua format standar industri:
  - **Wazuh Custom IDS Rules (`.xml`)** sesuai Gambar 3.6 tesis (memuat `<rule>`, `<srcip>`, `<dstport>`, `<protocol>`, `<mitre>`).
  - **MISP Threat Feed (`.json`)** sesuai Gambar 3.3 tesis (memuat objek `Event` dan `Attribute` `ip-dst`, `port`, `domain`, `datetime` dengan `to_ids: true`).
- **Implementasi:** [ExportController.php](file:///Users/wardix/agy/x/backend/app/Http/Controllers/ExportController.php) dan [PredictionExportPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/PredictionExportPage.jsx).

### 4. Ruang Lingkup Pipeline Preprocessing & Validasi Data (Bab 4.4 & 4.5)
- **Keputusan:** Seluruh tahapan pra-pemrosesan dan tabel contoh di Bab 4 tesis ditampilkan secara eksplisit agar dapat diverifikasi tahap demi tahap:
  - Penghapusan entri rusak (*corrupted records*) — Tabel 4.2 & 4.3.
  - Standardisasi skema lintas platform (`source_ip`, `destination_ip`, `port`, `protocol`, `timestamp`, `attack_type`, `payload_size`) — Tabel 4.4–4.7.
  - Penghapusan duplikat ($D_{\text{clean}} = D - D_{\text{duplicate}}$) — Tabel 4.8 & 4.9.
  - Imputasi nilai kosong (*Mean* untuk numerik, *Mode* untuk kategorikal) — Tabel 4.10 & 4.11.
  - Validasi rentang nilai (`port` dalam `0–65535`, `payload_size >= 0`) — Tabel 4.12 & 4.13.
  - Penyaringan atribut tidak relevan (`user_agent`, `session_id`, `raw_log_hash`) — Tabel 4.14 & 4.15.
  - Seleksi fitur dengan *Correlation Matrix* (Tabel 4.16), *Label/One-Hot Encoding*, dan *Z-Score Standardization* ($x' = \frac{x - \mu}{\sigma}$, Tabel 4.17 & 4.18).
- **Implementasi:** [preprocessing.py](file:///Users/wardix/agy/x/ml-service/app/preprocessing.py), [feature_selection.py](file:///Users/wardix/agy/x/ml-service/app/feature_selection.py), dan [PreprocessingPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/PreprocessingPage.jsx).

### 5. Ruang Lingkup Pemodelan Support Vector Machine (Bab 3.2 & 4.6)
- **Keputusan:** Fokus eksklusif pada algoritma **SVM** tanpa model pembanding ansambel lain dari Bab 5.
- **Detail Konfigurasi SVM:**
  - Pembagian data *stratified* **80% Training : 20% Testing** (dapat diatur di UI).
  - Dukungan penuh untuk perbandingan **RBF Kernel** ($K(x_i, x_j) = \exp(-\gamma \|x_i - x_j\|^2)$) dan **Linear Kernel** ($K(x_i, x_j) = x_i^T x_j$).
  - Visualisasi metrik *Accuracy*, *Precision*, *Recall*, *F1-Score*, *Confusion Matrix* 2×2, kurva *ROC & AUC*, serta kartu penjelasan matematis *Hyperplane*, *Margin*, dan *Lagrange Duality* (Bab 3.2.4).
- **Implementasi:** [svm_model.py](file:///Users/wardix/agy/x/ml-service/app/svm_model.py) dan [SvmTrainingPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/SvmTrainingPage.jsx).

### 6. Struktur 4 Menu Utama Tanpa Layar Login
- **Keputusan:** Menghilangkan halaman autentikasi/login agar aplikasi langsung menampilkan 4 menu fungsional di [App.jsx](file:///Users/wardix/agy/x/frontend/src/App.jsx):
  1. **Menu 01 — Overview & Koneksi CTI** ([OverviewPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/OverviewPage.jsx))
  2. **Menu 02 — Preprocessing & Validasi** ([PreprocessingPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/PreprocessingPage.jsx))
  3. **Menu 03 — Training & Evaluasi SVM** ([SvmTrainingPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/SvmTrainingPage.jsx))
  4. **Menu 04 — Prediksi Honeypot & Ekspor** ([PredictionExportPage.jsx](file:///Users/wardix/agy/x/frontend/src/pages/PredictionExportPage.jsx))
