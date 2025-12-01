"""
ai/pipeline.py (OPTIMIZADO)

AI Pipeline orchestration with sequential processing for memory optimization.
Optimized for Raspberry Pi Zero 2W (464 MB RAM).
"""

from __future__ import annotations

import logging
import gc
import time
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from ai.classifier import classifier_manager
from ai.embeddings import embedding_manager
from ai.dialogue import dialogue_manager
from worker.db import SessionLocal, Job

logger = logging.getLogger(__name__)

class AIPipeline:
    """
    Orchestrates AI tasks (classification, embedding) sequentially to minimize memory usage.
    Ensures only one model is loaded at a time.
    """

    def __init__(self):
        self.classifier = classifier_manager
        self.embedder = embedding_manager
        logger.info("AIPipeline initialized (sequential processing enabled)")

    def process_object(self, object_type: str, object_id: int, text: str, session: Session = None) -> Dict[str, bool]:
        """
        Process an object through the full AI pipeline (classify then embed).
        Ensures sequential execution and memory cleanup between steps.
        
        Args:
            object_type: Type of object ("job", "run", "vulnerability", "audit_data")
            object_id: ID of the object
            text: Text content to process
            session: Database session (optional)
        
        Returns:
            Dictionary with status of each step
        """
        if not text or not text.strip():
            logger.warning(f"Skipping empty text for {object_type}:{object_id}")
            return {'classification': False, 'embedding': False}

        use_local_session = session is None
        if use_local_session:
            session = SessionLocal()

        results = {
            'classification': False,
            'embedding': False
        }

        try:
            logger.info(f"🚀 Starting AI pipeline for {object_type}:{object_id}")
            
            # STEP 1: Classification
            # This will load classifiers one by one and unload them
            logger.info(f"Step 1/2: Classification for {object_type}:{object_id}")
            results['classification'] = self.classifier.label_object(
                object_type, object_id, text, session
            )
            
            # Explicit cleanup between steps
            gc.collect()
            time.sleep(0.1)  # Brief pause to let system settle
            
            # STEP 2: Embedding
            # This will load embedding model and unload it
            logger.info(f"Step 2/2: Embedding for {object_type}:{object_id}")
            results['embedding'] = self.embedder.embed_object(
                object_type, object_id, text, session
            )
            
            # Final cleanup
            gc.collect()
            
            logger.info(f"✅ AI pipeline completed for {object_type}:{object_id}: {results}")
            return results
            
        except Exception as e:
            logger.error(f"❌ AI pipeline failed for {object_type}:{object_id}: {e}")
            return results
        finally:
            if use_local_session:
                session.close()

    def process_batch(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Process a batch of items sequentially.
        Args:
            items: List of dicts with keys 'object_type', 'object_id', 'text'
        Returns:
            Statistics of processing
        """
        stats = {
            'total': len(items),
            'success': 0,
            'failed': 0,
            'classification_success': 0,
            'embedding_success': 0
        }
        
        logger.info(f"📦 Processing batch of {len(items)} items...")
        
        session = SessionLocal()
        try:
            for i, item in enumerate(items):
                logger.info(f"Processing item {i+1}/{len(items)}")
                
                result = self.process_object(
                    item['object_type'], 
                    item['object_id'], 
                    item['text'], 
                    session
                )
                
                if result['classification'] or result['embedding']:
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                    
                if result['classification']:
                    stats['classification_success'] += 1
                if result['embedding']:
                    stats['embedding_success'] += 1
                    
                # Commit periodically if needed, though process_object handles its own commits
                
        finally:
            session.close()
            
        logger.info(f"✅ Batch processing completed: {stats}")
        return stats

    def optimize_memory(self):
        """Force unload all models and run garbage collection."""
        self.classifier.unload_all_classifiers()
        self.embedder.unload_model()
        gc.collect()
        logger.info("🧹 Memory optimization completed")

    def generate_dialogue_response(
        self,
        context: Optional[str] = None,
        emotion: Optional[str] = None,
        speaker: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a dialogue response based on context.
        Delegates to dialogue_manager.
        """
        return dialogue_manager.get_dialogue(context, speaker, emotion)

    def generate_conversation(
        self,
        context: str,
        length: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Generate a conversation sequence.
        Delegates to dialogue_manager.
        """
        return dialogue_manager.get_conversation(context, length)

    def enhance_response_with_dialogue(
        self,
        response: Dict[str, Any],
        context: str
    ) -> Dict[str, Any]:
        """
        Enhance an AI response with a character dialogue.
        """
        # Determine emotion based on content if possible
        emotion = "neutral"
        if response.get("similar_findings_count", 0) > 0:
            emotion = "analytical"
        
        # Get a dialogue
        dialogue = self.generate_dialogue_response(context=context, emotion=emotion)
        
        if dialogue:
            response["dialogue"] = dialogue["text"]
            response["character_response"] = True
            response["character_speaker"] = dialogue["speaker"]
            response["character_emotion"] = dialogue["emotion"]
            
            # Add personality traits
            if dialogue["speaker"] == "subzero":
                response["personality"] = "Cold, precise, warning-focused"
                response["style"] = "Cyberpunk, analytical, serious"
            else:
                response["personality"] = "Energetic, sarcastic, dynamic"
                response["style"] = "Cyberpunk, rebellious, fast-paced"
                
        return response

# Global instance
ai_pipeline = AIPipeline()

# Convenience function
def process_ai_tasks(object_type: str, object_id: int, text: str):
    return ai_pipeline.process_object(object_type, object_id, text)

def process_job_completion(job_id: int, session: Session) -> bool:
    """
    Process a completed job and its related data through the AI pipeline.
    Extracts text from Job, Runs, Vulnerabilities, and AuditData.
    """
    job = session.query(Job).filter(Job.id == job_id).first()
    if not job:
        logger.error(f"Job {job_id} not found")
        return False

    success = True
    
    # 1. Process Job itself (using params or type as text)
    job_text = f"Job Type: {job.type}. Profile: {job.profile}. Params: {job.params}"
    res = ai_pipeline.process_object("job", job.id, job_text, session)
    if not (res['classification'] or res['embedding']):
        success = False

    # 2. Process Runs (stdout/stderr)
    for run in job.runs:
        run_text = f"Module: {run.module}. Exit Code: {run.exit_code}.\nStdout: {run.stdout}\nStderr: {run.stderr}"
        # Truncate to avoid token limit issues (simple truncation)
        run_text = run_text[:2000] 
        ai_pipeline.process_object("run", run.id, run_text, session)

    # 3. Process Vulnerabilities
    for vuln in job.vulnerabilities:
        vuln_text = f"{vuln.vuln_type} ({vuln.severity}): {vuln.description}. {vuln.details}"
        ai_pipeline.process_object("vulnerability", vuln.id, vuln_text, session)

    # 4. Process AuditData
    for audit in job.audit_data:
        audit_text = f"{audit.data_type}: {audit.data}"
        audit_text = audit_text[:2000]
        ai_pipeline.process_object("audit_data", audit.id, audit_text, session)

    return success

# Backward compatibility aliases
def enrich_finding_offline(object_type: str, object_id: int, text: str):
    """Alias for process_ai_tasks for backward compatibility."""
    return process_ai_tasks(object_type, object_id, text)

def build_context_for_question(question: str, limit: int = 5) -> str:
    """
    Build context for a question using semantic search.
    """
    results = embedding_manager.find_similar(question, limit=limit)
    context = []
    for res in results:
        # In a real implementation, we would fetch the actual text content from the DB
        # based on object_type and object_id.
        # For now, we'll just return the metadata.
        context.append(f"Related {res['object_type']} (ID: {res['object_id']}) - Score: {res['score']:.2f}")
    
    return "\n".join(context)

def get_ai_stats() -> Dict[str, Any]:
    """Get statistics about the AI pipeline."""
    return {
        'classifier_memory': classifier_manager.get_memory_status(),
        'embedding_loaded': embedding_manager.is_loaded()
    }
