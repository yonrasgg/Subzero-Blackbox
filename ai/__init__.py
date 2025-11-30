"""
ai/__init__.py

AI Indexing & Intelligence Layer for Subzero-Blackbox.
Provides offline-first AI capabilities with optional online enhancement.
"""

from .pipeline import ai_pipeline, enrich_finding_offline, build_context_for_question, process_job_completion, get_ai_stats
from .embeddings import embedding_manager, embed_text, index_object, search_similar, get_embedding_stats
from .classifier import classifier_manager, classify_vulnerability, label_object, get_labels_for_object, get_classifier_stats

__all__ = [
    # Pipeline
    'ai_pipeline',
    'enrich_finding_offline',
    'build_context_for_question',
    'process_job_completion',
    'get_ai_stats',

    # Embeddings
    'embedding_manager',
    'embed_text',
    'index_object',
    'search_similar',
    'get_embedding_stats',

    # Classification
    'classifier_manager',
    'classify_vulnerability',
    'label_object',
    'get_labels_for_object',
    'get_classifier_stats',
]