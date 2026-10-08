from fastapi import APIRouter
from app.models import BatchScanRequest, ScanRequest, ScanResponse, ChatRequest
from app.engine import scan

router = APIRouter()
PROCESSING_CHUNK_SIZE = 250


@router.get("/health")
def health():
    return {"status": "ok", "service": "workex-security-gateway"}


@router.post("/scan", response_model=ScanResponse)
def scan_content(request: ScanRequest):
    return scan(request.content, request.input_type, request.policies)


def summarize(results: list[dict]) -> dict:
    total = len(results)
    actions = {action: sum(row["action"] == action for row in results) for action in ("ALLOW", "SANITIZE", "BLOCK")}
    severities = {severity: sum(row["severity"] == severity for row in results) for severity in ("Critical", "High", "Medium", "Low")}
    threats_detected = sum(bool(row["threat_detected"]) for row in results)
    return {
        "total": total,
        "allowed": actions["ALLOW"],
        "sanitized": actions["SANITIZE"],
        "blocked": actions["BLOCK"],
        "threats_detected": threats_detected,
        "average_risk_score": round(sum(row["risk_score"] for row in results) / total, 1) if total else 0,
        "severity_counts": severities,
        "action_counts": actions,
        "detection_rate": round((threats_detected / total) * 100, 1) if total else 0,
    }


@router.post("/scan/batch")
def scan_batch(request: BatchScanRequest):
    results = []
    # Bound working chunks to keep per-request processing memory predictable.
    for start in range(0, len(request.items), PROCESSING_CHUNK_SIZE):
        for item in request.items[start:start + PROCESSING_CHUNK_SIZE]:
            result = scan(item.content, item.input_type, request.policies)
            results.append({"id": item.id, "content": item.content, **result})
    return {"results": results, "summary": summarize(results)}


@router.post("/chat")
def chat(request: ChatRequest):
    result = scan(request.content, request.input_type, request.policies)
    if result["action"] == "BLOCK":
        return {"blocked": True, "security": result, "response": None}
    safe_content = result["sanitized_content"] if result["action"] == "SANITIZE" else request.content
    return {"blocked": False, "security": result, "response": f"[Demo model] I received your request: {safe_content[:500]}"}
