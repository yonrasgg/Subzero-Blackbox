"""
ai/embeddings.py

MiniLM-L6 embeddings module for offline semantic search and similarity matching.
Provides vector embeddings for jobs, vulnerabilities, and audit data.
"""

from __future__ import annotations

import hashlib
import logging
from typing import List, Optional, Any, Dict
import numpy as np

from sqlalchemy.orm import Session

from worker.db import AIEmbedding, SessionLocal

logger = logging.getLogger(__name__)

# Try to import sentence-transformers, fallback gracefully if not available
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available. Install with: pip install sentence-transformers")


class EmbeddingManager:
    """
    Manages MiniLM-L6 embeddings for semantic search and similarity matching.
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """
        Initialize the embedding manager.

        Args:
            model_name: HuggingFace model name for embeddings
        """
        self.model_name = model_name
        self.model = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the MiniLM model if available."""
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.error("Cannot load embedding model: sentence-transformers not installed")
            return

        try:
            # Load quantized version for efficiency on lowspec hardware
            self.model = SentenceTransformer(self.model_name, device='cpu')
            logger.info(f"Loaded embedding model: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to load embedding model {self.model_name}: {e}")
            self.model = None

    def is_available(self) -> bool:
        """Check if the embedding model is available and loaded."""
        return self.model is not None

    def embed_text(self, text: str) -> Optional[List[float]]:
        """
        Generate embeddings for a text string.

        Args:
            text: Input text to embed

        Returns:
            List of float values representing the embedding vector, or None if failed
        """
        if not self.is_available():
            logger.warning("Embedding model not available")
            return None

        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return None

        try:
            # Generate embedding
            embedding = self.model.encode(text, convert_to_numpy=True)
            # Convert to list for JSON serialization
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to generate embedding for text: {e}")
            return None

    def index_object(self, object_type: str, object_id: int, text: str, session: Session) -> bool:
        """
        Index an object by generating and storing its embedding.

        Args:
            object_type: Type of object ("job", "run", "vulnerability", "audit_data")
            object_id: ID of the object in its source table
            text: Text content to embed
            session: Database session

        Returns:
            True if successfully indexed, False otherwise
        """
        if not self.is_available():
            logger.warning("Embedding model not available for indexing")
            return False

        # Generate content hash for deduplication
        content_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()

        # Check if this object is already indexed
        existing = session.query(AIEmbedding).filter(
            AIEmbedding.object_type == object_type,
            AIEmbedding.object_id == object_id,
            AIEmbedding.model_name == self.model_name
        ).first()

        if existing:
            # Check if content changed
            if existing.content_hash == content_hash:
                logger.debug(f"Object {object_type}:{object_id} already indexed with same content")
                return True
            else:
                # Update existing embedding
                embedding_vector = self.embed_text(text)
                if embedding_vector:
                    existing.vector = embedding_vector
                    existing.content_hash = content_hash
                    session.commit()
                    logger.info(f"Updated embedding for {object_type}:{object_id}")
                    return True
                else:
                    logger.error(f"Failed to generate embedding for {object_type}:{object_id}")
                    return False

        # Create new embedding
        embedding_vector = self.embed_text(text)
        if not embedding_vector:
            logger.error(f"Failed to generate embedding for {object_type}:{object_id}")
            return False

        embedding = AIEmbedding(
            object_type=object_type,
            object_id=object_id,
            model_name=self.model_name,
            vector=embedding_vector,
            content_hash=content_hash
        )

        session.add(embedding)
        session.commit()
        logger.info(f"Indexed {object_type}:{object_id} with embedding")
        return True

    def search_similar(self, query_text: str, top_k: int = 5, object_types: Optional[List[str]] = None,
                      session: Session = None) -> List[Dict[str, Any]]:
        """
        Search for objects similar to the query text using embeddings.

        Args:
            query_text: Query text to search for
            top_k: Number of top results to return
            object_types: Optional list of object types to search in
            session: Database session (creates one if not provided)

        Returns:
            List of dictionaries with object info and similarity scores
        """
        if not self.is_available():
            logger.warning("Embedding model not available for search")
            return []

        # Create session if not provided
        if session is None:
            session = SessionLocal()
            close_session = True
        else:
            close_session = False

        try:
            # Generate query embedding
            query_embedding = self.embed_text(query_text)
            if not query_embedding:
                logger.error("Failed to generate embedding for query")
                return []

            # Build query
            q = session.query(AIEmbedding)
            if object_types:
                q = q.filter(AIEmbedding.object_type.in_(object_types))

            # Get all embeddings
            embeddings = q.all()

            if not embeddings:
                logger.info("No embeddings found in database")
                return []

            # Calculate similarities
            results = []
            query_vec = np.array(query_embedding)

            for emb in embeddings:
                emb_vec = np.array(emb.vector)
                # Cosine similarity
                similarity = np.dot(query_vec, emb_vec) / (np.linalg.norm(query_vec) * np.linalg.norm(emb_vec))

                results.append({
                    'object_type': emb.object_type,
                    'object_id': emb.object_id,
                    'similarity': float(similarity),
                    'model_name': emb.model_name,
                    'created_at': emb.created_at
                })

            # Sort by similarity (descending) and return top_k
            results.sort(key=lambda x: x['similarity'], reverse=True)
            return results[:top_k]

        except Exception as e:
            logger.error(f"Error during similarity search: {e}")
            return []
        finally:
            if close_session:
                session.close()

    def get_embedding_stats(self, session: Session = None) -> Dict[str, Any]:
        """
        Get statistics about stored embeddings.

        Args:
            session: Database session (creates one if not provided)

        Returns:
            Dictionary with embedding statistics
        """
        if session is None:
            session = SessionLocal()
            close_session = True
        else:
            close_session = False

        try:
            total_embeddings = session.query(AIEmbedding).count()

            # Count by object type
            from sqlalchemy import func
            type_counts = session.query(
                AIEmbedding.object_type,
                func.count(AIEmbedding.id).label('count')
            ).group_by(AIEmbedding.object_type).all()

            # Count by model
            model_counts = session.query(
                AIEmbedding.model_name,
                func.count(AIEmbedding.id).label('count')
            ).group_by(AIEmbedding.model_name).all()

            return {
                'total_embeddings': total_embeddings,
                'by_object_type': {row.object_type: row.count for row in type_counts},
                'by_model': {row.model_name: row.count for row in model_counts},
                'model_available': self.is_available(),
                'current_model': self.model_name if self.is_available() else None
            }

        except Exception as e:
            logger.error(f"Error getting embedding stats: {e}")
            return {'error': str(e)}
        finally:
            if close_session:
                session.close()


# Global instance
embedding_manager = EmbeddingManager()


def embed_text(text: str) -> Optional[List[float]]:
    """Convenience function to generate embeddings."""
    return embedding_manager.embed_text(text)


def index_object(object_type: str, object_id: int, text: str, session: Session) -> bool:
    """Convenience function to index objects."""
    return embedding_manager.index_object(object_type, object_id, text, session)


def search_similar(query_text: str, top_k: int = 5, object_types: Optional[List[str]] = None,
                  session: Session = None) -> List[Dict[str, Any]]:
    """Convenience function for similarity search."""
    return embedding_manager.search_similar(query_text, top_k, object_types, session)


def get_embedding_stats(session: Session = None) -> Dict[str, Any]:
    """Convenience function to get embedding statistics."""
    return embedding_manager.get_embedding_stats(session)