"""
ai/classifier.py

ALBERT-tiny classification module for offline vulnerability and attack categorization.
Provides discrete classification for security findings and audit data.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any

from sqlalchemy.orm import Session

from worker.db import AILabel, SessionLocal

logger = logging.getLogger(__name__)

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers not available. Install with: pip install transformers torch")


class ClassifierManager:
    """
    Manages ALBERT-tiny and other classifiers for offline categorization.
    """

    def __init__(self):
        """Initialize the classifier manager."""
        self.classifiers = {}
        self._load_classifiers()

    def _load_classifiers(self) -> None:
        """Load available classifiers."""
        if not TRANSFORMERS_AVAILABLE:
            logger.error("Cannot load classifiers: transformers not installed")
            return

        # Define classifier configurations
        configs = {
            'vuln_type': {
                'model': 'albert-base-v2',  # Using base ALBERT as tiny might not be available
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

        for classifier_type, config in configs.items():
            try:
                # Load model and tokenizer
                model_name = config['model']
                labels = config['labels']

                # Create a simple text classification pipeline
                # In production, you'd want fine-tuned models for each category
                classifier = pipeline(
                    "text-classification",
                    model=model_name,
                    tokenizer=model_name,
                    return_all_scores=True
                )

                self.classifiers[classifier_type] = {
                    'pipeline': classifier,
                    'labels': labels,
                    'model_name': model_name
                }

                logger.info(f"Loaded classifier for {classifier_type}: {model_name}")

            except Exception as e:
                logger.error(f"Failed to load classifier for {classifier_type}: {e}")

    def is_available(self, classifier_type: str = 'vuln_type') -> bool:
        """Check if a specific classifier is available."""
        return classifier_type in self.classifiers

    def classify_text(self, text: str, classifier_type: str) -> Optional[Dict[str, Any]]:
        """
        Classify text using the specified classifier.

        Args:
            text: Text to classify
            classifier_type: Type of classifier ('vuln_type', 'attack_family', 'domain', 'severity')

        Returns:
            Dictionary with classification results, or None if failed
        """
        if not self.is_available(classifier_type):
            logger.warning(f"Classifier {classifier_type} not available")
            return None

        if not text or not text.strip():
            logger.warning("Empty text provided for classification")
            return None

        try:
            classifier = self.classifiers[classifier_type]
            pipeline = classifier['pipeline']

            # Run classification
            results = pipeline(text)

            if not results or len(results) == 0:
                logger.warning(f"No classification results for {classifier_type}")
                return None

            # Get the top result
            top_result = max(results[0], key=lambda x: x['score'])

            return {
                'label_type': classifier_type,
                'label_value': top_result['label'],
                'score': top_result['score'],
                'model_name': classifier['model_name'],
                'all_scores': results[0]  # Include all scores for transparency
            }

        except Exception as e:
            logger.error(f"Failed to classify text with {classifier_type}: {e}")
            return None

    def classify_vulnerability(self, description: str, technical_details: Optional[str] = None) -> Dict[str, Any]:
        """
        Classify a vulnerability using multiple classifiers.

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

        # Classify with all available classifiers
        for classifier_type in ['vuln_type', 'attack_family', 'domain', 'severity']:
            classification = self.classify_text(text, classifier_type)
            if classification:
                results[classifier_type] = classification

        return results

    def label_object(self, object_type: str, object_id: int, text: str, session: Session) -> bool:
        """
        Generate and store labels for an object.

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

        # Get classifications
        if object_type == 'vulnerability':
            # For vulnerabilities, use specialized classification
            classifications = self.classify_vulnerability(text)
        else:
            # For other objects, classify with available classifiers
            classifications = {}
            for classifier_type in self.classifiers.keys():
                classification = self.classify_text(text, classifier_type)
                if classification:
                    classifications[classifier_type] = classification

        if not classifications:
            logger.warning(f"No classifications generated for {object_type}:{object_id}")
            return False

        # Store labels in database
        try:
            for label_type, classification in classifications.items():
                # Check if label already exists
                existing = session.query(AILabel).filter(
                    AILabel.object_type == object_type,
                    AILabel.object_id == object_id,
                    AILabel.label_type == label_type,
                    AILabel.model_name == classification['model_name']
                ).first()

                if existing:
                    # Update existing label
                    existing.label_value = classification['label_value']
                    existing.score = classification['score']
                    existing.metadata = classification.get('all_scores')
                else:
                    # Create new label
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
            logger.info(f"Labeled {object_type}:{object_id} with {len(classifications)} classifications")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store labels for {object_type}:{object_id}: {e}")
            return False

    def get_labels_for_object(self, object_type: str, object_id: int, session: Session = None) -> List[Dict[str, Any]]:
        """
        Get all labels for a specific object.

        Args:
            object_type: Type of object
            object_id: ID of the object
            session: Database session (creates one if not provided)

        Returns:
            List of label dictionaries
        """
        if session is None:
            session = SessionLocal()
            close_session = True
        else:
            close_session = False

        try:
            labels = session.query(AILabel).filter(
                AILabel.object_type == object_type,
                AILabel.object_id == object_id
            ).all()

            return [{
                'label_type': label.label_type,
                'label_value': label.label_value,
                'score': label.score,
                'model_name': label.model_name,
                'metadata': label.classification_metadata,
                'created_at': label.created_at
            } for label in labels]

        except Exception as e:
            logger.error(f"Error getting labels for {object_type}:{object_id}: {e}")
            return []
        finally:
            if close_session:
                session.close()

    def get_classifier_stats(self, session: Session = None) -> Dict[str, Any]:
        """
        Get statistics about stored labels.

        Args:
            session: Database session (creates one if not provided)

        Returns:
            Dictionary with label statistics
        """
        if session is None:
            session = SessionLocal()
            close_session = True
        else:
            close_session = False

        try:
            total_labels = session.query(AILabel).count()

            # Count by label type
            from sqlalchemy import func
            type_counts = session.query(
                AILabel.label_type,
                func.count(AILabel.id).label('count')
            ).group_by(AILabel.label_type).all()

            # Count by model
            model_counts = session.query(
                AILabel.model_name,
                func.count(AILabel.id).label('count')
            ).group_by(AILabel.model_name).all()

            return {
                'total_labels': total_labels,
                'by_label_type': {row.label_type: row.count for row in type_counts},
                'by_model': {row.model_name: row.count for row in model_counts},
                'available_classifiers': list(self.classifiers.keys()),
                'classifiers_loaded': len(self.classifiers)
            }

        except Exception as e:
            logger.error(f"Error getting classifier stats: {e}")
            return {'error': str(e)}
        finally:
            if close_session:
                session.close()


# Global instance
classifier_manager = ClassifierManager()


def classify_vulnerability(description: str, technical_details: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to classify vulnerabilities."""
    return classifier_manager.classify_vulnerability(description, technical_details)


def label_object(object_type: str, object_id: int, text: str, session: Session) -> bool:
    """Convenience function to label objects."""
    return classifier_manager.label_object(object_type, object_id, text, session)


def get_labels_for_object(object_type: str, object_id: int, session: Session = None) -> List[Dict[str, Any]]:
    """Convenience function to get object labels."""
    return classifier_manager.get_labels_for_object(object_type, object_id, session)


def get_classifier_stats(session: Session = None) -> Dict[str, Any]:
    """Convenience function to get classifier statistics."""
    return classifier_manager.get_classifier_stats(session)