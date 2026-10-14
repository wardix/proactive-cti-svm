from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .dataset_generator import (
    generate_cti_dataset,
    generate_unseen_honeypot_logs,
    get_thesis_dirty_showcase_records,
)
from .feature_selection import extract_and_encode_features
from .preprocessing import run_preprocessing_pipeline
from .svm_model import (
    get_chapter_3_mathematical_illustration,
    get_saved_model_status,
    predict_unseen_data,
    train_and_evaluate_svm,
)


app = FastAPI(
    title="CTI Proactive Cyber Security Defense - Python SVM ML Service",
    description="Microservice untuk Data Cleaning, Validation, Feature Selection, dan Klasifikasi SVM berdasarkan thesis.pdf (Bab 3 & 4).",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GenerateDatasetRequest(BaseModel):
    total_samples: int = Field(default=12500, ge=20, le=25000)
    include_dirty_samples: bool = Field(default=True)
    source_filter: Optional[str] = Field(default=None)
    seed: int = Field(default=42)


class PreprocessRequest(BaseModel):
    records: Optional[List[Dict[str, Any]]] = None
    correlation_threshold: float = Field(default=0.92, ge=0.5, le=1.0)


class TrainSvmRequest(BaseModel):
    records: Optional[List[Dict[str, Any]]] = None
    total_samples_if_empty: int = Field(default=12500, ge=50, le=25000)
    kernel: str = Field(default="rbf")
    c_param: float = Field(default=1.0, gt=0.0)
    gamma_param: str = Field(default="scale")
    train_ratio: float = Field(default=0.80, ge=0.5, le=0.95)
    correlation_threshold: float = Field(default=0.92, ge=0.5, le=1.0)


class PredictRequest(BaseModel):
    records: List[Dict[str, Any]]


@app.get("/health")
def health_check() -> Dict[str, Any]:
    model_status = get_saved_model_status()
    return {
        "status": "ok",
        "service": "python-svm-ml-service",
        "model_trained": model_status is not None,
        "model_status": model_status,
    }


@app.post("/api/ml/generate-dataset")
def api_generate_dataset(req: GenerateDatasetRequest) -> Dict[str, Any]:
    records = generate_cti_dataset(
        total_samples=req.total_samples,
        include_dirty_samples=req.include_dirty_samples,
        source_filter=req.source_filter,
        seed=req.seed,
    )
    return {
        "total_generated": len(records),
        "records": records,
    }


@app.get("/api/ml/generate-honeypot-logs")
def api_generate_honeypot_logs(count: int = 12) -> Dict[str, Any]:
    logs = generate_unseen_honeypot_logs(count=max(1, min(count, 100)))
    return {
        "count": len(logs),
        "logs": logs,
    }


@app.post("/api/ml/preprocess")
def api_preprocess(req: PreprocessRequest) -> Dict[str, Any]:
    raw_records = req.records
    if not raw_records:
        raw_records = generate_cti_dataset(total_samples=500, include_dirty_samples=True)

    clean_records, preproc_report = run_preprocessing_pipeline(raw_records)
    _, _, _, _, selection_info = extract_and_encode_features(
        clean_records, correlation_threshold=req.correlation_threshold
    )

    return {
        "preprocessing_report": preproc_report,
        "feature_selection_report": selection_info,
        "clean_records_sample": clean_records[:25],
        "total_clean_records": len(clean_records),
    }


@app.post("/api/ml/train")
def api_train_svm(req: TrainSvmRequest) -> Dict[str, Any]:
    raw_records = req.records
    if not raw_records:
        raw_records = generate_cti_dataset(
            total_samples=req.total_samples_if_empty,
            include_dirty_samples=True,
        )

    try:
        result = train_and_evaluate_svm(
            raw_records=raw_records,
            kernel=req.kernel,
            c_param=req.c_param,
            gamma_param=req.gamma_param,
            train_ratio=req.train_ratio,
            correlation_threshold=req.correlation_threshold,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/ml/predict")
def api_predict_svm(req: PredictRequest) -> Dict[str, Any]:
    if not req.records:
        raise HTTPException(status_code=400, detail="Daftar records tidak boleh kosong.")

    # Auto-train default SVM model if not yet trained
    if get_saved_model_status() is None:
        default_data = generate_cti_dataset(total_samples=12500, include_dirty_samples=True)
        train_and_evaluate_svm(raw_records=default_data, kernel="rbf", c_param=1.0, gamma_param="scale")

    try:
        predictions = predict_unseen_data(req.records)
        threat_count = sum(1 for r in predictions if r["predicted_label"] == 1)
        benign_count = sum(1 for r in predictions if r["predicted_label"] == -1)
        return {
            "total": len(predictions),
            "threat_count": threat_count,
            "benign_count": benign_count,
            "predictions": predictions,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/ml/thesis-tables")
def api_thesis_tables() -> Dict[str, Any]:
    """
    Returns the exact Chapter 3 & Chapter 4 step-by-step tables (Table 3.1, 3.2,
    4.2 to 4.17) and mathematical formulation for interactive inspection.
    """
    dirty_showcase = get_thesis_dirty_showcase_records()
    clean_showcase, preproc_report = run_preprocessing_pipeline(dirty_showcase)
    _, _, _, _, selection_info = extract_and_encode_features(clean_showcase)
    return {
        "showcase_raw_records": dirty_showcase,
        "showcase_clean_records": clean_showcase,
        "preprocessing_report": preproc_report,
        "feature_selection_report": selection_info,
        "mathematical_formulation": get_chapter_3_mathematical_illustration(),
    }
