
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.services.privacy_engine import PrivacyEngine


# Initialize FastAPI
app = FastAPI(
    title="DataRakshak API",
    description="Indian PII-aware Privacy Firewall for LLM and RAG applications",
    version="1.0.0"
)

# Initialize Privacy Engine
engine = PrivacyEngine()


# Request schema
class PrivacyRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Text to be processed"
    )

    action: Literal["allow", "redact", "block", "tokenize"] = Field(
        default="redact",
        description="Privacy action to perform"
    )


# Health check endpoint
@app.get("/")
def home():
    return {
        "message": "Welcome to DataRakshak API",
        "status": "running"
    }


# Process text endpoint
@app.post("/api/v1/process")
def process_text(request: PrivacyRequest):

    try:
        result = engine.process(
            text=request.text,
            action=request.action
        )

        return {
            "project": "DataRakshak",
            "status": result["status"],
            "action": request.action,
            "protected_text": result["text"],
            "detections": result["detections"],
            "detection_count": len(result["detections"]),
            "token_count": result.get("token_count", 0)
        }

    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
