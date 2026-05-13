import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from fastapi import APIRouter, HTTPException
from loguru import logger
from api.models import GraphResponse, GraphNode, GraphEdge
from graph.ingestion import Neo4jConnection

router = APIRouter()


@router.get("/graph/{domain}", response_model=GraphResponse)
async def get_graph(domain: str):
    """
    Retrieve knowledge graph data for a domain.
    Returns nodes and edges for frontend visualization.
    """
    domain = domain.strip().lower()
    logger.info(f"📊 API: Fetching graph for {domain}")

    try:
        with Neo4jConnection() as conn:
            # Fetch nodes
            node_result = conn.run("""
                MATCH (o:Organization {domain: $domain})
                OPTIONAL MATCH (o)-[:EXPOSES]->(e:Entity)
                OPTIONAL MATCH (s:Signal {target_org: $domain})
                RETURN
                    o,
                    collect(DISTINCT e) as entities,
                    collect(DISTINCT s) as signals
            """, {"domain": domain})

            if not node_result:
                raise HTTPException(
                    status_code=404,
                    detail=f"No graph data found for {domain}"
                )

            record = node_result[0]
            nodes = []
            edges = []
            seen_ids = set()

            # Organization node
            org = dict(record["o"])
            org_id = f"org_{domain}"
            nodes.append(GraphNode(
                id=org_id,
                label="Organization",
                properties=org
            ))
            seen_ids.add(org_id)

            # Entity nodes
            for entity in record["entities"]:
                if entity is None:
                    continue
                e = dict(entity)
                entity_id = f"entity_{e.get('name', '')}_{e.get('entity_type', '')}"
                if entity_id not in seen_ids:
                    nodes.append(GraphNode(
                        id=entity_id,
                        label=e.get("entity_type", "Entity"),
                        properties=e
                    ))
                    edges.append(GraphEdge(
                        source=org_id,
                        target=entity_id,
                        relationship="EXPOSES"
                    ))
                    seen_ids.add(entity_id)

            # Signal nodes (limited to 50 for performance)
            for signal in record["signals"][:50]:
                if signal is None:
                    continue
                s = dict(signal)
                signal_id = f"signal_{s.get('id', '')[:8]}"
                if signal_id not in seen_ids:
                    nodes.append(GraphNode(
                        id=signal_id,
                        label="Signal",
                        properties={
                            "source_type": s.get("source_type", ""),
                            "sensitivity": s.get("sensitivity", ""),
                            "raw_content": s.get("raw_content", "")[:100]
                        }
                    ))
                    edges.append(GraphEdge(
                        source=signal_id,
                        target=org_id,
                        relationship="COLLECTED_FROM"
                    ))
                    seen_ids.add(signal_id)

        return GraphResponse(
            target_org=domain,
            nodes=nodes,
            edges=edges,
            total_nodes=len(nodes),
            total_edges=len(edges)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Graph fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))