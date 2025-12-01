"""
ai/embeddings.py (OPTIMIZADO)

MiniLM-L6 embedding module with lazy loading for memory optimization.
Optimized for Raspberry Pi Zero 2W (464 MB RAM).
"""

from __future__ import annotations

import logging
import gc
import json
import numpy as np
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from worker.db import AIEmbedding, SessionLocal

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available. Install with: pip install sentence-transformers")

class EmbeddingManager:
    """
    Manages MiniLM-L6 embedding model with lazy loading for memory optimization.
    Model is loaded on-demand and can be unloaded to free memory.
    """

    def __init__(self):
        """Initialize the embedding manager (no model loaded yet)."""
        self.model = None
        self.model_name = 'all-MiniLM-L6-v2'
        self._is_loaded = False
        logger.info("EmbeddingManager initialized (lazy loading enabled)")

    def _load_model(self) -> bool:
        """
        Load the embedding model on-demand (lazy loading).
        Returns:
            True if loaded successfully, False otherwise
        """
        if self._is_loaded and self.model is not None:
            logger.debug("Embedding model already loaded")
            return True

        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.error("Cannot load embedding model: sentence-transformers not installed")
            return False

        try:
            logger.info(f"🔄 Loading embedding model {self.model_name}...")
            
            # Load model on CPU
            self.model = SentenceTransformer(self.model_name, device='cpu')
            
            self._is_loaded = True
            logger.info(f"✅ Embedding model {self.model_name} loaded successfully")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to load embedding model {self.model_name}: {e}")
            return False

    def unload_model(self) -> bool:
        """
        Unload the embedding model to free memory.
        Returns:
            True if unloaded successfully, False otherwise
        """
        if not self._is_loaded:
            logger.debug("Embedding model not loaded, nothing to unload")
            return True

        try:
            logger.info("🗑️ Unloading embedding model...")
            
            # Delete the model
            del self.model
            self.model = None
            self._is_loaded = False
            
            # Force garbage collection
            gc.collect()
            logger.info("✅ Embedding model unloaded, memory freed")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to unload embedding model: {e}")
            return False

    def is_loaded(self) -> bool:
        """Check if the embedding model is currently loaded in memory."""
        return self._is_loaded

    def generate_embedding(self, text: str, auto_unload: bool = True) -> Optional[List[float]]:
        """
        Generate embedding for a text (with lazy loading).
        Args:
            text: Text to embed
            auto_unload: If True, unload model after use to free memory
        Returns:
            List of floats representing the embedding, or None if failed
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return None

        # Load model if not already loaded (lazy loading)
        if not self.is_loaded():
            if not self._load_model():
                return None

        try:
            # Generate embedding
            embedding = self.model.encode(text)
            
            # Convert to list for JSON serialization
            if isinstance(embedding, np.ndarray):
                embedding_list = embedding.tolist()
            else:
                embedding_list = list(embedding)
            
            # Auto-unload to free memory if requested
            if auto_unload:
                self.unload_model()
                
            return embedding_list
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            # Unload on error to free memory
            if auto_unload:
                self.unload_model()
            return None

    def embed_object(self, object_type: str, object_id: int, text: str, session: Session) -> bool:
        """
        Generate and store embedding for an object.
        Args:
            object_type: Type of object ("job", "run", "vulnerability", "audit_data")
            object_id: ID of the object in its source table
            text: Text content to embed
            session: Database session
        Returns:
            True if successfully embedded, False otherwise
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return False

        # Generate embedding (model loaded/unloaded automatically)
        embedding_vector = self.generate_embedding(text, auto_unload=True)
        
        if not embedding_vector:
            logger.warning(f"No embedding generated for {object_type}:{object_id}")
            return False

        # Store embedding in database
        try:
            existing = session.query(AIEmbedding).filter(
                AIEmbedding.object_type == object_type,
                AIEmbedding.object_id == object_id,
                AIEmbedding.model_name == self.model_name
            ).first()

            if existing:
                existing.vector = json.dumps(embedding_vector)
            else:
                embedding = AIEmbedding(
                    object_type=object_type,
                    object_id=object_id,
                    model_name=self.model_name,
                    vector=json.dumps(embedding_vector)
                )
                session.add(embedding)
            
            session.commit()
            logger.info(f"✅ Embedded {object_type}:{object_id}")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Failed to store embedding for {object_type}:{object_id}: {e}")
            return False

    def find_similar(self, text: str, object_type: Optional[str] = None, limit: int = 5, session: Session = None) -> List[Dict[str, Any]]:
        """
        Find similar objects using vector similarity.
        Args:
            text: Query text
            object_type: Optional filter by object type
            limit: Max number of results
            session: Database session
        Returns:
            List of similar objects with scores
        """
        if not session:
            session = SessionLocal()
            close_session = True
        else:
            close_session = False

        try:
            # Generate query embedding
            query_embedding = self.generate_embedding(text, auto_unload=True)
            if not query_embedding:
                return []

            # Fetch all embeddings (naive implementation, inefficient for large DBs)
            # For Pi Zero with small DB, this is acceptable. For larger DBs, use pgvector or similar.
            query = session.query(AIEmbedding)
            if object_type:
                query = query.filter(AIEmbedding.object_type == object_type)
            
            stored_embeddings = query.all()
            
            results = []
            query_vec = np.array(query_embedding)
            
            for item in stored_embeddings:
                try:
                    item_vec = np.array(json.loads(item.vector))
                    
                    # Cosine similarity
                    similarity = np.dot(query_vec, item_vec) / (np.linalg.norm(query_vec) * np.linalg.norm(item_vec))
                    
                    results.append({
                        'object_type': item.object_type,
                        'object_id': item.object_id,
                        'score': float(similarity),
                        'model_name': item.model_name
                    })
                except Exception as e:
                    logger.warning(f"Error calculating similarity for {item.id}: {e}")
                    continue
            
            # Sort by similarity (descending)
            results.sort(key=lambda x: x['score'], reverse=True)
            
            return results[:limit]
        finally:
            if close_session:
                session.close()

# Global instance
embedding_manager = EmbeddingManager()

# Convenience functions (backward compatible)
def generate_embedding(text: str) -> Optional[List[float]]:
    return embedding_manager.generate_embedding(text)

# Backward compatibility aliases
def embed_text(text: str) -> Optional[List[float]]:
    """Generate embedding for text."""
    return embedding_manager.generate_embedding(text)

def index_object(object_type: str, object_id: int, text: str, session: Session) -> bool:
    """Generate and store embedding for an object."""
    return embedding_manager.embed_object(object_type, object_id, text, session)

def search_similar(text: str, object_type: Optional[str] = None, limit: int = 5, session: Session = None) -> List[Dict[str, Any]]:
    """Find similar objects."""
    return embedding_manager.find_similar(text, object_type, limit, session)

def get_embedding_stats() -> Dict[str, Any]:
    """Get statistics about the embedding model."""
    return {
        'is_loaded': embedding_manager.is_loaded(),
        'model_name': embedding_manager.model_name
    }
