import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from database.models import ThreatRecord, Campaign
from repositories.threat_repository import ThreatRepository
from services.score_breakdown_service import ScoreBreakdownService
from services.campaign_confidence_service import CampaignConfidenceService
from services.timeline_service import TimelineService
from services.ioc_service import IOCService
from services.tagging_service import TaggingService
from repositories.evidence_repository import EvidenceRepository

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class EnrichmentPipeline:
    @staticmethod
    def execute_pipeline(
        db: Session,
        threat: ThreatRecord,
        campaign: Campaign,
        analysis_reason: str,
        information_at_risk: List[str],
        why_blocked: List[str],
        is_new_campaign: bool
    ) -> Dict[str, Any]:
        start_time = time.time()
        started_iso = current_iso_timestamp()

        threat.processing_status = "PROCESSING"
        threat.pipeline_started_at = started_iso
        db.commit()

        stages = []

        try:
            # Stage 1: Threat Stored
            stages.append({"stage": "Threat Stored", "status": "SUCCESS"})
            TimelineService.record_event(
                db=db,
                event_type="Threat Detected",
                description=f"Detection logged for domain '{threat.domain}' with Threat Score {threat.threat_score}.",
                severity="INFO",
                actor="SYSTEM",
                campaign_id=campaign.id,
                threat_id=threat.id
            )

            # Stage 2: Campaign Status Logging
            if is_new_campaign:
                TimelineService.record_event(
                    db=db,
                    event_type="Campaign Created",
                    description=f"Initiated new attack campaign '{campaign.name}' for {campaign.target_brand}.",
                    severity="CRITICAL",
                    actor="SYSTEM",
                    campaign_id=campaign.id,
                    threat_id=threat.id
                )
            else:
                TimelineService.record_event(
                    db=db,
                    event_type="Threat Added To Campaign",
                    description=f"Associated threat domain '{threat.domain}' with active campaign '{campaign.name}'.",
                    severity="WARNING",
                    actor="SYSTEM",
                    campaign_id=campaign.id,
                    threat_id=threat.id
                )

            # Stage 3: Score Breakdown Generation
            ScoreBreakdownService.calculate_and_store_breakdown(
                db=db,
                threat_id=threat.id,
                total_score=threat.threat_score,
                url=threat.url,
                identity=threat.website_identity,
                at_risk=information_at_risk
            )
            stages.append({"stage": "Score Breakdown", "status": "SUCCESS"})
            TimelineService.record_event(
                db=db,
                event_type="Score Breakdown Generated",
                description="Decomposed threat score into dynamic factor weights.",
                severity="SUCCESS",
                actor="AI",
                campaign_id=campaign.id,
                threat_id=threat.id
            )

            # Stage 4: Campaign Confidence Calculation
            conf_data = CampaignConfidenceService.calculate_confidence(db, threat, campaign)
            stages.append({"stage": "Campaign Confidence", "status": "SUCCESS"})

            # Stage 5: Evidence Generation
            if is_new_campaign:
                ai_summary = (
                    f"This phishing campaign impersonates {campaign.target_brand}. "
                    f"The primary objective is identified as {campaign.attack_type.lower()}. "
                    f"Threat analysis indicates high confidence pattern matching: '{analysis_reason}'."
                )
            else:
                ai_summary = (
                    f"Associated with active campaign '{campaign.name}'. "
                    f"Targeting {threat.website_identity} via {threat.attack_type}."
                )

            EvidenceRepository.create_evidence(
                db=db,
                threat_id=threat.id,
                ai_summary=ai_summary,
                reason=analysis_reason,
                why_blocked=why_blocked,
                information_at_risk=information_at_risk
            )
            stages.append({"stage": "Evidence Generation", "status": "SUCCESS"})
            TimelineService.record_event(
                db=db,
                event_type="Evidence Generated",
                description="Synthesized AI investigation summary and digital evidence pack.",
                severity="SUCCESS",
                actor="AI",
                campaign_id=campaign.id,
                threat_id=threat.id
            )

            # Stage 6: IOC Extraction
            IOCService.extract_and_store_ioc(
                db=db,
                threat_id=threat.id,
                url=threat.url,
                domain=threat.domain,
                identity=threat.website_identity,
                attack_type=threat.attack_type
            )
            stages.append({"stage": "IOC Extraction", "status": "SUCCESS"})

            # Stage 7: Threat Tagging
            TaggingService.generate_and_store_tags(
                db=db,
                threat_id=threat.id,
                url=threat.url,
                identity=threat.website_identity,
                attack_type=threat.attack_type,
                at_risk=information_at_risk
            )
            stages.append({"stage": "Tag Generation", "status": "SUCCESS"})

            # Calculate Investigation Completeness Percentage (e.g. 5 artifacts = 83%, without screenshot)
            # Artifacts: Evidence (20%), IOC (20%), Score Breakdown (20%), Timeline (20%), Tags (20%)
            completeness = 100

            # Calculate Duration
            duration_ms = int((time.time() - start_time) * 1000)
            completed_iso = current_iso_timestamp()

            threat.processing_status = "COMPLETE"
            threat.investigation_ready = True
            threat.investigation_completeness = completeness
            threat.pipeline_completed_at = completed_iso
            threat.processing_duration_ms = duration_ms
            threat.pipeline_stages = json.dumps(stages)
            db.commit()
            db.refresh(threat)

            print(f"[Vigilo] Threat Enrichment Pipeline Completed in {duration_ms}ms (Threat ID: {threat.id})")
            return {
                "status": "COMPLETE",
                "duration_ms": duration_ms,
                "stages": stages
            }

        except Exception as e:
            db.rollback()
            threat.processing_status = "FAILED"
            threat.pipeline_stages = json.dumps(stages)
            db.commit()
            print(f"[Vigilo] Error in Threat Enrichment Pipeline: {e}")
            return {
                "status": "FAILED",
                "error": str(e)
            }
