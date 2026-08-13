from fastapi import APIRouter
from backend.app.services.ml_service import analyze_flow

router = APIRouter()


@router.post("/analyze")
def analyze(flow: dict):
    return analyze_flow(flow)