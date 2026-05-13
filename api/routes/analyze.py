import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from loguru import logger
from datetime import datetime

from api.models import AnalyzeRequest, ReportResponse, FindingResponse
from collectors.orchestrator import CollectionOrchestrator
from processors.pipeline import NLPPipeline
from inference.engine import InferenceEngine
from urllib.parse import urlparse


router = APIRouter()

# In-memory store for reports (we'll persist to DB later)
reports_store: dict = {}

def normalize_target(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host


@router.post("/analyze", response_model=ReportResponse)
async def analyze(request: AnalyzeRequest):
    """
    Run the full ChaturDrishti pipeline on a target domain.
    Collects OSINT, runs NLP, generates inference report.
    """
    target = normalize_target(request.target_org)
    logger.info(f"📡 API: Starting analysis for {target}")

    try:
        # Step 1: Collect signals
        if request.run_collectors:
            logger.info("  Running collectors...")
            orchestrator = CollectionOrchestrator(target_org=target)
            signals = await orchestrator.run()
        else:
            signals = []

        # Step 2: NLP pipeline
        if request.run_nlp and signals:
            logger.info("  Running NLP pipeline...")
            pipeline = NLPPipeline()
            signals = pipeline.process_and_store(signals)

        # Step 3: Inference
        if request.run_inference:
            logger.info("  Running inference engine...")
            engine = InferenceEngine(model="llama3.1:8b")
            report = engine.analyze(target)
        else:
            raise HTTPException(
                status_code=400,
                detail="Inference must be enabled"
            )

        # Step 4: Correlation — build the attack surface from the graph
        logger.info("  Running correlation engine...")
        from intelligence.correlation import CorrelationEngine
        from api.models import (
            AttackSurfaceResponse,
            ConfirmedHostResponse,
            PersonProfileResponse,
        )

        correlation_engine = CorrelationEngine()
        surface = correlation_engine.build_attack_surface(target)

        attack_surface = AttackSurfaceResponse(
            confirmed_hosts=[
                ConfirmedHostResponse(**h.model_dump())
                for h in surface.confirmed_hosts
            ],
            sensitive_hosts=[
                ConfirmedHostResponse(**h.model_dump())
                for h in surface.sensitive_hosts
            ],
            technology_stack=surface.technology_stack,
            cloud_profile=surface.cloud_profile,
            people_profiles=[
                PersonProfileResponse(**p.model_dump())
                for p in surface.people_profiles
            ],
            saas_services=surface.saas_services,
            exposed_ports=surface.exposed_ports,
            cves_found=surface.cves_found,
            secrets_found=surface.secrets_found,
            correlation_risk_score=surface.risk_score,
            summary_stats=surface.summary_stats,
        )
        logger.info(
            f"  Correlation complete: "
            f"{len(attack_surface.confirmed_hosts)} confirmed, "
            f"{len(attack_surface.sensitive_hosts)} sensitive, "
            f"{len(attack_surface.people_profiles)} people"
        )

        # Build response
        findings = [
            FindingResponse(
                title=f.title,
                inference=f.inference,
                evidence=f.evidence,
                attacker_value=f.attacker_value,
                risk_level=f.risk_level,
                mitigations=f.mitigations
            )
            for f in report.findings
        ]

        response = ReportResponse(
            target_org=target,
            summary=report.summary,
            findings=findings,
            total_signals=report.total_signals,
            risk_score=report.risk_score,
            attack_surface=attack_surface,
            generated_at=datetime.utcnow()
        )

        # Cache the report
        reports_store[target] = response
        logger.success(f"✅ Analysis complete for {target}")
        return response

    except Exception as e:
        logger.error(f"❌ Analysis failed for {target}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{domain}", response_model=ReportResponse)
async def get_report(domain: str):
    """Retrieve the latest cached report for a domain."""
    domain = normalize_target(domain)

    if domain not in reports_store:
        raise HTTPException(
            status_code=404,
            detail=f"No report found for {domain}. Run /analyze first."
        )

    return reports_store[domain]