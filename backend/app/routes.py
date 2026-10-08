from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pypdf import PdfReader
from docx import Document
from app.models import BatchScanRequest, ScanRequest, ScanResponse, ChatRequest
from app.engine import scan
from app.gemini_service import GeminiServiceError, generate_response, get_model_name
from app.security_classifier import SecurityClassifierError, classify_security_input

router = APIRouter()
PROCESSING_CHUNK_SIZE = 250
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_DOCUMENT_CHARACTERS = 50_000
MAX_DOCUMENT_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_DOCUMENT_ARCHIVE_ENTRIES = 2_000
MAX_PDF_PAGES = 200
DOCUMENT_TYPES = {".txt": "text/plain", ".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}


@router.get("/health")
def health():
    return {"status": "ok", "service": "workex-security-gateway"}


@router.post("/scan", response_model=ScanResponse)
def scan_content(request: ScanRequest):
    return scan(request.content, request.input_type, request.policies)


def extract_document_text(filename: str, file_bytes: bytes) -> str:
    """Extract text from supported office documents; never execute file content."""
    suffix = Path(filename).suffix.lower()
    if suffix == ".txt":
        try:
            return file_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="TXT file must contain valid UTF-8 text.") from exc
    if suffix == ".pdf":
        try:
            reader = PdfReader(BytesIO(file_bytes), strict=True)
            if len(reader.pages) > MAX_PDF_PAGES:
                raise HTTPException(status_code=413, detail="PDF exceeds the 200 page scan limit.")
            blocks = []
            extracted_characters = 0
            for page in reader.pages:
                text = page.extract_text() or ""
                extracted_characters += len(text)
                if extracted_characters > MAX_DOCUMENT_CHARACTERS:
                    raise HTTPException(status_code=413, detail="Extracted text exceeds the 50,000 character scan limit.")
                blocks.append(text)
            return "\n".join(blocks)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=422, detail="PDF could not be safely parsed or text extraction failed.") from exc
    if suffix == ".docx":
        try:
            with ZipFile(BytesIO(file_bytes)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_DOCUMENT_ARCHIVE_ENTRIES or sum(item.file_size for item in entries) > MAX_DOCUMENT_ARCHIVE_BYTES:
                    raise HTTPException(status_code=413, detail="DOCX expands beyond the safe extraction limit.")
            document = Document(BytesIO(file_bytes))
            blocks = [paragraph.text for paragraph in document.paragraphs]
            for table in document.tables:
                blocks.extend("\t".join(cell.text for cell in row.cells) for row in table.rows)
            return "\n".join(blocks)
        except HTTPException:
            raise
        except BadZipFile as exc:
            raise HTTPException(status_code=422, detail="DOCX could not be safely parsed or text extraction failed.") from exc
        except Exception as exc:
            raise HTTPException(status_code=422, detail="DOCX could not be safely parsed or text extraction failed.") from exc
    raise HTTPException(status_code=415, detail="Unsupported file type. Upload a .txt, .pdf, or .docx file.")


@router.post("/scan-document")
async def scan_document(file: UploadFile = File(...)):
    """Extract and scan an uploaded document using the existing local Workex engine."""
    filename = Path(file.filename or "").name
    suffix = Path(filename).suffix.lower()
    if suffix not in DOCUMENT_TYPES:
        raise HTTPException(status_code=415, detail="Unsupported file type. Upload a .txt, .pdf, or .docx file.")
    content_type = (file.content_type or "").lower()
    expected_type = DOCUMENT_TYPES[suffix]
    if content_type not in {expected_type, "application/octet-stream", ""}:
        raise HTTPException(status_code=415, detail="File extension and content type do not match a supported document type.")

    file_bytes = await file.read(MAX_DOCUMENT_BYTES + 1)
    await file.close()
    if len(file_bytes) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413, detail="Document exceeds the 10 MB upload limit.")
    if not file_bytes:
        raise HTTPException(status_code=422, detail="Uploaded file is empty.")

    extracted = extract_document_text(filename, file_bytes)
    if not extracted.strip():
        raise HTTPException(status_code=422, detail="No readable text was found in the document.")
    if len(extracted) > MAX_DOCUMENT_CHARACTERS:
        raise HTTPException(status_code=413, detail="Extracted text exceeds the 50,000 character scan limit.")
    result = scan(extracted, "document")
    return {
        "filename": filename,
        "file_type": suffix[1:],
        "extracted_characters": len(extracted),
        "threat_detected": result["threat_detected"],
        "threat_type": result["threat_type"],
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "action": result["action"],
        "reasons": result["reasons"],
        "sanitized_content": result.get("sanitized_content"),
        "extraction_success": True,
        "detections": result.get("detections", []),
        "risk_breakdown": result.get("risk_breakdown", []),
        "explanation": result.get("explanation", ""),
    }


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
    model_result = {
        "provider": "gemini",
        "model": get_model_name(),
        "called": False,
        "response": None,
        "error": None,
    }
    local_classification = (
        "CLEAR_THREAT" if result["action"] == "BLOCK" else
        "CLEAR_SENSITIVE" if result["action"] == "SANITIZE" else
        "CLEAR_SAFE" if result["risk_score"] == 0 else
        "UNCERTAIN"
    )
    assessment = {
        "used": False,
        "status": "skipped",
        "local_classification": local_classification,
        "classification": None,
        "confidence": None,
        "threat_type": None,
        "reason": "The local Workex engine made a clear decision; the classifier was not needed.",
        "latency_ms": None,
    }
    decision = {"action": result["action"], "reason": "Workex local security engine decision."}
    if result["action"] == "BLOCK":
        assessment["reason"] = "The local engine blocked this input; it was not sent to the AI classifier."
        return {
            "blocked": True,
            "security": result,
            "decision": decision,
            "security_assessment": assessment,
            "model": model_result,
        }

    # The current engine blocks scores of 30 or more. Its non-zero ALLOW scores
    # below that boundary represent weak signals (for example, social engineering)
    # and are the only inputs eligible for a second opinion. SANITIZE results are
    # deliberately excluded so detected personal data/secrets are not sent again.
    sensitive_detected = any(
        row["signal"] == "sensitive_information" and row["detected"]
        for row in result["risk_breakdown"]
    )
    uncertain = (
        result["action"] == "ALLOW"
        and 0 < result["risk_score"] < 30
        and not sensitive_detected
    )
    if uncertain:
        assessment.update(
            used=True,
            status="completed",
            reason="A non-zero local risk signal was below the deterministic block threshold; a second opinion was requested.",
        )
        context = {
            "risk_score": result["risk_score"],
            "local_action": result["action"],
            "signals": [
                {"signal": row["signal"], "score": row["score"]}
                for row in result["risk_breakdown"]
                if row["detected"]
            ],
        }
        try:
            classifier = classify_security_input(request.content, request.input_type, context)
        except SecurityClassifierError as exc:
            assessment.update(
                status="unavailable",
                reason=exc.public_message,
                latency_ms=exc.latency_ms,
            )
            decision = {
                "action": "BLOCK",
                "reason": "AI security second opinion unavailable; uncertain input blocked conservatively.",
            }
            assessment["final_action"] = "BLOCK"
            return {
                "blocked": True,
                "security": result,
                "decision": decision,
                "security_assessment": assessment,
                "model": model_result,
            }

        assessment.update(classifier)
        if classifier["classification"] == "MALICIOUS" and classifier["confidence"] >= 80:
            decision = {
                "action": "BLOCK",
                "reason": "The AI security second opinion identified a high-confidence threat.",
            }
            assessment["final_action"] = "BLOCK"
            return {
                "blocked": True,
                "security": result,
                "decision": decision,
                "security_assessment": assessment,
                "model": model_result,
            }
        assessment["final_action"] = "ALLOW"
        decision = {
            "action": "ALLOW",
            "reason": "The AI security second opinion did not find a sufficiently confident threat.",
        }
    elif result["action"] == "SANITIZE":
        assessment["reason"] = "Sensitive content was handled by the local sanitization policy; it was not sent to the classifier."
    elif sensitive_detected:
        assessment["reason"] = "The local engine detected sensitive information; it was not sent to the classifier."

    prompt_for_model = (
        result["sanitized_content"]
        if result["action"] == "SANITIZE"
        else request.content
    )
    try:
        response = generate_response(prompt_for_model)
    except GeminiServiceError as exc:
        model_result["called"] = exc.request_attempted
        model_result["error"] = exc.public_message
        return JSONResponse(
            status_code=503,
            content={
                "blocked": False,
                "security": result,
                "decision": decision,
                "security_assessment": assessment,
                "model": model_result,
            },
        )

    model_result.update(called=True, response=response)
    return {
        "blocked": False,
        "security": result,
        "decision": decision,
        "security_assessment": assessment,
        "model": model_result,
    }
