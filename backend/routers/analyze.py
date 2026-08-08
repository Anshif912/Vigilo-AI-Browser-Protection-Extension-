from fastapi import APIRouter, BackgroundTasks
from models.request import AnalyzeRequest
from models.response import AnalyzeResponse
from services.url_analyzer import UniversalURLAnalyzer
from services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(prefix="/api/analyze-url", tags=["Real-Time AI URL Protection"])

@router.post("", response_model=AnalyzeResponse)
def analyze_url(request: AnalyzeRequest, background_tasks: BackgroundTasks) -> AnalyzeResponse:
    # Perform Universal AI URL Intelligence Analysis
    analysis = UniversalURLAnalyzer.analyze_url(
        request.url,
        request.html_content,
        request.dom_title,
        request.dom_text
    )

    # Asynchronously trigger Threat Intelligence Enrichment Pipeline if threat detected
    if analysis.status != "Safe" and analysis.threat_score >= 51:
        background_tasks.add_task(
            ThreatIntelligenceService.process_and_store_threat,
            analysis
        )

    return analysis
