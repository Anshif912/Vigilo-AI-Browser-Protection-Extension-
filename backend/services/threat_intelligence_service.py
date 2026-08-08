import urllib.parse
from models.response import AnalyzeResponse
from database.db import SessionLocal
from repositories.threat_repository import ThreatRepository
from services.campaign_service import CampaignService
from services.enrichment_pipeline import EnrichmentPipeline

class ThreatIntelligenceService:
    @staticmethod
    def process_and_store_threat(analysis: AnalyzeResponse) -> None:
        """
        Asynchronously called background task. Stores intelligence & executes enrichment pipeline.
        Ignores Safe websites.
        """
        if analysis.status == "Safe" or analysis.threat_score < 51:
            return

        db = SessionLocal()
        try:
            # Extract domain
            try:
                parsed = urllib.parse.urlparse(
                    analysis.url if "://" in analysis.url else "https://" + analysis.url
                )
                domain = (parsed.hostname or analysis.url).lower()
            except Exception:
                domain = analysis.url.lower()

            # Process Campaign Association
            campaign, is_new = CampaignService.process_campaign_association(
                db=db,
                website_identity=analysis.website_identity,
                attack_type=analysis.attack_type,
                url=analysis.url,
                threat_score=analysis.threat_score
            )

            # Create Base Threat Record with Full Single Source Analysis
            threat = ThreatRepository.create_threat_record(
                db=db,
                campaign_id=campaign.id,
                analysis=analysis,
                domain=domain,
                browser="Chrome"
            )

            # Execute Enrichment Pipeline
            EnrichmentPipeline.execute_pipeline(
                db=db,
                threat=threat,
                campaign=campaign,
                analysis_reason=analysis.reason,
                information_at_risk=analysis.information_at_risk,
                why_blocked=analysis.why_blocked,
                is_new_campaign=is_new
            )

            print(f"[Vigilo] Threat Intelligence Saved successfully (Analysis ID: {analysis.analysis_id})")

        except Exception as e:
            db.rollback()
            print(f"[Vigilo] Error saving threat intelligence: {e}")
        finally:
            db.close()
