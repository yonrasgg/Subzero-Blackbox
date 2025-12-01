"""
ai/classifier.py (OPTIMIZADO)

ALBERT-tiny classification module with lazy loading for memory optimization.
Optimized for Raspberry Pi Zero 2W (464 MB RAM).
"""

from __future__ import annotations

import logging
import gc
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from worker.db import AILabel

logger = logging.getLogger(__name__)

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers not available. Install with: pip install transformers torch")

class ClassifierManager:
    """
    Manages ALBERT-tiny classifiers with lazy loading for memory optimization.
    Models are loaded on-demand and can be unloaded to free memory.
    """

    def __init__(self):
        """Initialize the classifier manager (no models loaded yet)."""
        self.classifiers = {}
        self._loaded_classifiers = set()  # Track which classifiers are loaded

        # Define classifier configurations (metadata only, no loading)
        self.classifier_configs = {
            'vuln_type': {
                'model': 'albert-base-v2',
                'labels': ['sql_injection', 'xss', 'csrf', 'rce', 'lfi', 'xxe', 'ssrf',
                          'weak_crypto', 'default_creds', 'misconfig', 'open_port', 'weak_auth',
                          'wifi_vuln', 'bt_vuln', 'usb_vuln', 'other']
            },
            'attack_family': {
                'model': 'albert-base-v2',
                'labels': ['injection', 'broken_access', 'misconfig', 'crypto_weakness',
                          'identification', 'data_validation', 'function_level', 'service_level',
                          'network_attack', 'physical_attack', 'social_engineering', 'other']
            },
            'domain': {
                'model': 'albert-base-v2',
                'labels': ['web', 'network', 'wireless', 'bluetooth', 'usb', 'system', 'database',
                          'api', 'mobile', 'cloud', 'iot', 'other']
            },
            'severity': {
                'model': 'albert-base-v2',
                'labels': ['info', 'low', 'medium', 'high', 'critical']
            }
        }
        logger.info("ClassifierManager initialized (lazy loading enabled)")

    def _load_classifier(self, classifier_type: str) -> bool:
        """
        Load a specific classifier on-demand (lazy loading).
        Args:
            classifier_type: Type of classifier to load
        Returns:
            True if loaded successfully, False otherwise
        """
        if classifier_type in self._loaded_classifiers:
            logger.debug(f"Classifier {classifier_type} already loaded")
            return True

        if not TRANSFORMERS_AVAILABLE:
            logger.error("Cannot load classifier: transformers not installed")
            return False

        if classifier_type not in self.classifier_configs:
            logger.error(f"Unknown classifier type: {classifier_type}")
            return False

        try:
            config = self.classifier_configs[classifier_type]
            model_name = config['model']
            labels = config['labels']
            
            logger.info(f"🔄 Loading classifier {classifier_type} ({model_name})...")
            
            # Create text classification pipeline
            classifier = pipeline(
                "text-classification",
                model=model_name,
                tokenizer=model_name,
                return_all_scores=True,
                device=-1  # CPU only (important for Pi)
            )
            
            self.classifiers[classifier_type] = {
                'pipeline': classifier,
                'labels': labels,
                'model_name': model_name
            }
            self._loaded_classifiers.add(classifier_type)
            logger.info(f"✅ Classifier {classifier_type} loaded successfully")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to load classifier {classifier_type}: {e}")
            return False

    def unload_classifier(self, classifier_type: str) -> bool:
        """
        Unload a specific classifier to free memory.
        Args:
            classifier_type: Type of classifier to unload
        Returns:
            True if unloaded successfully, False otherwise
        """
        if classifier_type not in self._loaded_classifiers:
            logger.debug(f"Classifier {classifier_type} not loaded, nothing to unload")
            return True

        try:
            logger.info(f"🗑️ Unloading classifier {classifier_type}...")
            
            # Delete the classifier
            if classifier_type in self.classifiers:
                del self.classifiers[classifier_type]
            
            self._loaded_classifiers.discard(classifier_type)
            
            # Force garbage collection
            gc.collect()
            logger.info(f"✅ Classifier {classifier_type} unloaded, memory freed")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to unload classifier {classifier_type}: {e}")
            return False

    def unload_all_classifiers(self) -> None:
        """Unload all loaded classifiers to free memory."""
        logger.info("🗑️ Unloading all classifiers...")
        for classifier_type in list(self._loaded_classifiers):
            self.unload_classifier(classifier_type)
        gc.collect()
        logger.info("✅ All classifiers unloaded")

    def is_available(self, classifier_type: str = 'vuln_type') -> bool:
        """Check if a specific classifier is available (can be loaded)."""
        return classifier_type in self.classifier_configs

    def is_loaded(self, classifier_type: str) -> bool:
        """Check if a specific classifier is currently loaded in memory."""
        return classifier_type in self._loaded_classifiers

    def classify_text(self, text: str, classifier_type: str, auto_unload: bool = True) -> Optional[Dict[str, Any]]:
        """
        Classify text using the specified classifier (with lazy loading).
        Args:
            text: Text to classify
            classifier_type: Type of classifier ('vuln_type', 'attack_family', 'domain', 'severity')
            auto_unload: If True, unload classifier after use to free memory
        Returns:
            Dictionary with classification results, or None if failed
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for classification")
            return None

        # Load classifier if not already loaded (lazy loading)
        if not self.is_loaded(classifier_type):
            if not self._load_classifier(classifier_type):
                return None

        try:
            classifier = self.classifiers[classifier_type]
            pipeline = classifier['pipeline']
            
            # Run classification
            results = pipeline(text)
            
            if not results or len(results) == 0:
                logger.warning(f"No classification results for {classifier_type}")
                return None
            
            # Handle pipeline output format (list of lists vs list of dicts)
            if isinstance(results[0], list):
                results = results[0]

            top_result = max(results, key=lambda x: x['score'])
            
            result = {
                'label_type': classifier_type,
                'label_value': top_result['label'],
                'score': top_result['score'],
                'model_name': classifier['model_name'],
                'all_scores': results
            }
            
            # Auto-unload to free memory if requested
            if auto_unload:
                self.unload_classifier(classifier_type)
                
            return result
        except Exception as e:
            logger.error(f"Failed to classify text with {classifier_type}: {e}")
            # Unload on error to free memory
            if auto_unload:
                self.unload_classifier(classifier_type)
            return None

    def classify_vulnerability(self, description: str, technical_details: Optional[str] = None) -> Dict[str, Any]:
        """
        Classify a vulnerability using multiple classifiers (sequential loading).
        Args:
            description: Vulnerability description
            technical_details: Optional technical details
        Returns:
            Dictionary with all classifications
        """
        text = description
        if technical_details:
            text += f" {technical_details}"
            
        results = {}
        
        # Classify with all available classifiers (one at a time)
        for classifier_type in ['vuln_type', 'attack_family', 'domain', 'severity']:
            # Each classifier is loaded, used, and unloaded sequentially
            classification = self.classify_text(text, classifier_type, auto_unload=True)
            if classification:
                results[classifier_type] = classification
                
        return results

    def label_object(self, object_type: str, object_id: int, text: str, session: Session) -> bool:
        """
        Generate and store labels for an object (with sequential classifier loading).
        Args:
            object_type: Type of object ("job", "run", "vulnerability", "audit_data")
            object_id: ID of the object in its source table
            text: Text content to classify
            session: Database session
        Returns:
            True if successfully labeled, False otherwise
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for labeling")
            return False

        # Get classifications (classifiers loaded/unloaded sequentially)
        if object_type == 'vulnerability':
            classifications = self.classify_vulnerability(text)
        else:
            classifications = {}
            for classifier_type in self.classifier_configs.keys():
                classification = self.classify_text(text, classifier_type, auto_unload=True)
                if classification:
                    classifications[classifier_type] = classification

        if not classifications:
            logger.warning(f"No classifications generated for {object_type}:{object_id}")
            return False

        # Store labels in database
        try:
            for label_type, classification in classifications.items():
                existing = session.query(AILabel).filter(
                    AILabel.object_type == object_type,
                    AILabel.object_id == object_id,
                    AILabel.label_type == label_type,
                    AILabel.model_name == classification['model_name']
                ).first()

                if existing:
                    existing.label_value = classification['label_value']
                    existing.score = classification['score']
                    existing.metadata = classification.get('all_scores')
                else:
                    label = AILabel(
                        object_type=object_type,
                        object_id=object_id,
                        label_type=label_type,
                        label_value=classification['label_value'],
                        score=classification['score'],
                        model_name=classification['model_name'],
                        classification_metadata=classification.get('all_scores')
                    )
                    session.add(label)
            
            session.commit()
            logger.info(f"✅ Labeled {object_type}:{object_id} with {len(classifications)} classifications")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Failed to store labels for {object_type}:{object_id}: {e}")
            return False

    def get_memory_status(self) -> Dict[str, Any]:
        """Get current memory status of classifiers."""
        return {
            'loaded_classifiers': list(self._loaded_classifiers),
            'available_classifiers': list(self.classifier_configs.keys()),
            'total_loaded': len(self._loaded_classifiers),
            'total_available': len(self.classifier_configs)
        }
    
    def get_labels_for_object(self, object_type: str, object_id: int, session: Session) -> List[Dict[str, Any]]:
        """Get existing labels for an object."""
        labels = session.query(AILabel).filter(
            AILabel.object_type == object_type,
            AILabel.object_id == object_id
        ).all()
        
        return [{
            'label_type': label.label_type,
            'label_value': label.label_value,
            'score': label.score,
            'model_name': label.model_name
        } for label in labels]

# Global instance
classifier_manager = ClassifierManager()

# Convenience functions (backward compatible)
def classify_vulnerability(description: str, technical_details: Optional[str] = None) -> Dict[str, Any]:
    return classifier_manager.classify_vulnerability(description, technical_details)

# Backward compatibility aliases
def label_object(object_type: str, object_id: int, text: str, session: Session) -> bool:
    """Generate and store labels for an object."""
    return classifier_manager.label_object(object_type, object_id, text, session)

def get_labels_for_object(object_type: str, object_id: int, session: Session) -> List[Dict[str, Any]]:
    """Get existing labels for an object."""
    return classifier_manager.get_labels_for_object(object_type, object_id, session)

def get_classifier_stats() -> Dict[str, Any]:
    """Get statistics about the classifiers."""
    return classifier_manager.get_memory_status()
