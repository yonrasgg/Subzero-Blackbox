"""
ai/pipeline.py

AI pipeline orchestration for offline-first intelligence in Subzero-Blackbox.
Coordinates embeddings, classification, and optional online AI enhancement.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from sqlalchemy.orm import Session

from .embeddings import embedding_manager, index_object as embed_object, search_similar
from .classifier import classifier_manager, label_object as classify_object, get_labels_for_object
from .dialogue import dialogue_manager, get_dialogue, get_conversation
from worker.db import Vulnerability, AuditData, Job, Run

logger = logging.getLogger(__name__)


@dataclass
class AIContext:
    """Structured context for AI operations."""
    object_type: str
    object_id: int
    text_content: str
    embeddings: Optional[List[float]] = None
    labels: Optional[List[Dict[str, Any]]] = None
    similar_objects: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None


class AIPipeline:
    """
    Orchestrates AI operations for offline intelligence and online enhancement.
    """

    def __init__(self):
        """Initialize the AI pipeline."""
        self.embeddings_available = embedding_manager.is_available()
        self.classification_available = len(classifier_manager.classifiers) > 0

        logger.info(f"AI Pipeline initialized - Embeddings: {self.embeddings_available}, "
                   f"Classification: {self.classification_available}")

    def generate_dialogue_response(self, context: str, emotion: Optional[str] = None,
                                 speaker: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Generate a dialogue response in Subzero/Rayden style.

        Args:
            context: Context for the dialogue (e.g., 'wifi_audit', 'success', 'error')
            emotion: Specific emotion to use, or None for context-appropriate
            speaker: Specific speaker ('subzero' or 'rayden'), or None for random

        Returns:
            Dialogue dict with speaker, emotion, text, etc.
        """
        try:
            dialogue = get_dialogue(context=context, speaker=speaker, emotion=emotion)
            if dialogue:
                logger.debug(f"Generated dialogue: {dialogue['speaker']} - {dialogue['emotion']} - {context}")
            return dialogue
        except Exception as e:
            logger.error(f"Error generating dialogue response: {e}")
            return None

    def generate_conversation(self, context: str, length: int = 2) -> List[Dict[str, Any]]:
        """
        Generate a conversation sequence for a context.

        Args:
            context: Context for the conversation
            length: Number of dialogue exchanges

        Returns:
            List of dialogue dicts forming a conversation
        """
        try:
            conversation = get_conversation(context, length)
            logger.debug(f"Generated conversation with {len(conversation)} exchanges for context: {context}")
            return conversation
        except Exception as e:
            logger.error(f"Error generating conversation: {e}")
            return []

    def enhance_response_with_dialogue(self, response: Dict[str, Any], context: str) -> Dict[str, Any]:
        """
        Enhance an AI response with contextual dialogue from Subzero/Rayden.

        Args:
            response: Original response dict
            context: Context for dialogue generation

        Returns:
            Enhanced response with dialogue elements
        """
        try:
            # Generate a contextual dialogue
            dialogue = self.generate_dialogue_response(context)

            if dialogue:
                response['dialogue'] = dialogue
                response['character_response'] = dialogue['text']
                response['character_speaker'] = dialogue['speaker']
                response['character_emotion'] = dialogue['emotion']

                # Add some personality based on speaker
                if dialogue['speaker'] == 'subzero':
                    response['personality'] = 'cold_precision'
                    response['style'] = 'methodical'
                elif dialogue['speaker'] == 'rayden':
                    response['personality'] = 'electric_energy'
                    response['style'] = 'dynamic'

            return response

        except Exception as e:
            logger.error(f"Error enhancing response with dialogue: {e}")
            return response

    def enrich_finding_offline(self, finding: Any, session: Session) -> bool:
        """
        Enrich a finding with offline AI processing.

        Args:
            finding: Vulnerability, AuditData, or similar object
            session: Database session

        Returns:
            True if successfully enriched, False otherwise
        """
        try:
            # Determine object type and extract text content
            if isinstance(finding, Vulnerability):
                object_type = "vulnerability"
                object_id = finding.id
                text_content = finding.description or ""
                if finding.details:
                    # Add technical details if available
                    import json
                    try:
                        details_str = json.dumps(finding.details)
                        text_content += f" {details_str}"
                    except (TypeError, ValueError):
                        pass

            elif isinstance(finding, AuditData):
                object_type = "audit_data"
                object_id = finding.id
                text_content = ""
                if finding.data:
                    # Convert data dict to searchable text
                    import json
                    try:
                        text_content = json.dumps(finding.data)
                    except (TypeError, ValueError):
                        text_content = str(finding.data)

            elif isinstance(finding, Job):
                object_type = "job"
                object_id = finding.id
                text_content = f"{finding.type} {finding.profile or ''} {finding.params or ''}"

            elif isinstance(finding, Run):
                object_type = "run"
                object_id = finding.id
                text_content = f"{finding.module} {finding.stdout or ''} {finding.stderr or ''}"

            else:
                logger.warning(f"Unsupported finding type: {type(finding)}")
                return False

            if not text_content.strip():
                logger.warning(f"No text content found for {object_type}:{object_id}")
                return False

            # Generate embeddings
            if self.embeddings_available:
                embed_success = embed_object(object_type, object_id, text_content, session)
                if not embed_success:
                    logger.warning(f"Failed to generate embeddings for {object_type}:{object_id}")

            # Generate classifications
            if self.classification_available:
                classify_success = classify_object(object_type, object_id, text_content, session)
                if not classify_success:
                    logger.warning(f"Failed to generate labels for {object_type}:{object_id}")

            logger.info(f"Successfully enriched {object_type}:{object_id} with offline AI")
            return True

        except Exception as e:
            logger.error(f"Error enriching finding {type(finding)}:{getattr(finding, 'id', 'unknown')}: {e}")
            return False

    def build_context_for_question(self, question: str, session: Session,
                                 top_k: int = 5, object_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Build AI context for answering a question using offline intelligence.

        Args:
            question: User's question
            session: Database session
            top_k: Number of similar objects to retrieve
            object_types: Types of objects to search in

        Returns:
            Dictionary with context information
        """
        context = {
            'question': question,
            'similar_findings': [],
            'labels_summary': {},
            'ai_available': {
                'embeddings': self.embeddings_available,
                'classification': self.classification_available
            }
        }

        if not self.embeddings_available:
            logger.warning("Embeddings not available for context building")
            return context

        try:
            # Find similar objects using embeddings
            similar_objects = search_similar(
                question,
                top_k=top_k,
                object_types=object_types or ['vulnerability', 'audit_data', 'job'],
                session=session
            )

            context['similar_findings'] = similar_objects

            # Get labels for the most similar objects
            labels_summary = {}
            for obj in similar_objects[:3]:  # Get labels for top 3 results
                labels = get_labels_for_object(obj['object_type'], obj['object_id'], session)
                if labels:
                    key = f"{obj['object_type']}:{obj['object_id']}"
                    labels_summary[key] = labels

            context['labels_summary'] = labels_summary

            # Build a structured context summary
            context['context_summary'] = self._build_context_summary(similar_objects, labels_summary)

        except Exception as e:
            logger.error(f"Error building context for question: {e}")
            context['error'] = str(e)

        return context

    def _build_context_summary(self, similar_objects: List[Dict[str, Any]],
                              labels_summary: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Build a human-readable context summary.

        Args:
            similar_objects: List of similar objects from embedding search
            labels_summary: Labels for the similar objects

        Returns:
            Formatted context summary string
        """
        if not similar_objects:
            return "No similar findings found in the audit database."

        summary_parts = ["Similar findings from audit database:"]

        for obj in similar_objects:
            obj_type = obj['object_type']
            obj_id = obj['object_id']
            similarity = obj['similarity']

            summary_parts.append(f"- {obj_type.upper()} #{obj_id} (similarity: {similarity:.2f})")

            # Add labels if available
            labels_key = f"{obj_type}:{obj_id}"
            if labels_key in labels_summary:
                labels = labels_summary[labels_key]
                for label in labels:
                    if label['score'] > 0.5:  # Only include high-confidence labels
                        summary_parts.append(f"  • {label['label_type']}: {label['label_value']} "
                                           f"(confidence: {label['score']:.2f})")

        return "\n".join(summary_parts)

    def get_ai_stats(self, session: Session = None) -> Dict[str, Any]:
        """
        Get comprehensive AI statistics.

        Args:
            session: Database session

        Returns:
            Dictionary with AI system statistics
        """
        from .embeddings import get_embedding_stats
        from .classifier import get_classifier_stats

        stats = {
            'pipeline_status': {
                'embeddings_available': self.embeddings_available,
                'classification_available': self.classification_available,
                'dialogue_available': True  # Dialogue system is always available
            }
        }

        # Get embedding stats
        if self.embeddings_available:
            stats['embeddings'] = get_embedding_stats(session)

        # Get classifier stats
        if self.classification_available:
            stats['classification'] = get_classifier_stats(session)

        # Get dialogue stats
        stats['dialogue'] = dialogue_manager.get_stats()

        return stats

    def process_job_completion(self, job_id: int, session: Session) -> bool:
        """
        Process AI enrichment when a job is completed.

        Args:
            job_id: ID of the completed job
            session: Database session

        Returns:
            True if processing successful, False otherwise
        """
        try:
            # Get the job
            job = session.query(Job).filter(Job.id == job_id).first()
            if not job:
                logger.error(f"Job {job_id} not found for AI processing")
                return False

            # Enrich the job itself
            self.enrich_finding_offline(job, session)

            # Enrich related runs
            runs = session.query(Run).filter(Run.job_id == job_id).all()
            for run in runs:
                self.enrich_finding_offline(run, session)

            # Enrich related vulnerabilities
            vulnerabilities = session.query(Vulnerability).filter(Vulnerability.job_id == job_id).all()
            for vuln in vulnerabilities:
                self.enrich_finding_offline(vuln, session)

            # Enrich related audit data
            audit_data = session.query(AuditData).filter(AuditData.job_id == job_id).all()
            for data in audit_data:
                self.enrich_finding_offline(data, session)

            logger.info(f"Completed AI processing for job {job_id}")
            return True

        except Exception as e:
            logger.error(f"Error processing job {job_id} completion: {e}")
            return False


# Global instance
ai_pipeline = AIPipeline()


# Convenience functions
def enrich_finding_offline(finding: Any, session: Session) -> bool:
    """Enrich a finding with offline AI processing."""
    return ai_pipeline.enrich_finding_offline(finding, session)


def build_context_for_question(question: str, session: Session,
                             top_k: int = 5, object_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """Build AI context for answering questions."""
    return ai_pipeline.build_context_for_question(question, session, top_k, object_types)


def process_job_completion(job_id: int, session: Session) -> bool:
    """Process AI enrichment for completed jobs."""
    return ai_pipeline.process_job_completion(job_id, session)


def get_ai_stats(session: Session = None) -> Dict[str, Any]:
    """Get AI system statistics."""
    return ai_pipeline.get_ai_stats(session)