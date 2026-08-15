from typing import Optional

from fastapi import APIRouter, HTTPException

from backend.app.services.ml_service import analyze_flow
from backend.app.services.traffic_collector import (
    DEFAULT_WINDOW_SECONDS,
    collect_flows,
    collect_primary_flow,
    list_interfaces,
)
from backend.app.schemas.flow import TrafficFlow

router = APIRouter()


@router.post("/analyze")
def analyze(flow: TrafficFlow):
    return analyze_flow(flow.model_dump())


@router.get("/interfaces")
def interfaces():
    """Capture-capable NICs. Use the 'name' value as the iface query param."""
    return {"interfaces": list_interfaces()}


@router.get("/collect")
def collect(window: int = DEFAULT_WINDOW_SECONDS, iface: Optional[str] = None):
    """Capture one window and return every observed flow, validated against
    TrafficFlow. Blocks for `window` seconds."""
    flows = collect_flows(iface=iface, window_seconds=window)
    validated = [TrafficFlow(**f).model_dump(mode="json") for f in flows]
    return {"count": len(validated), "window_seconds": window, "flows": validated}


@router.post("/analyze/live")
def analyze_live(window: int = DEFAULT_WINDOW_SECONDS, iface: Optional[str] = None):
    """Capture the busiest flow and score it through the existing detector."""
    raw = collect_primary_flow(iface=iface, window_seconds=window)
    if raw is None:
        raise HTTPException(status_code=404, detail="No traffic observed in capture window.")

    flow = TrafficFlow(**raw)
    return {
        "flow": flow.model_dump(mode="json"),
        "result": analyze_flow(flow.model_dump()),
    }