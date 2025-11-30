"""
ai/dialogue.py

Dialogue system for Subzero vs Rayden AI assistants.
Provides contextual, emotional dialogue generation for cyberpunk interface.
"""

import json
import random
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class DialogueManager:
    """Manages dialogue system for Subzero and Rayden AI assistants."""

    def __init__(self, dialogues_path: Optional[str] = None):
        """
        Initialize dialogue manager.

        Args:
            dialogues_path: Path to dialogues.json file. If None, uses default location.
        """
        if dialogues_path is None:
            # Default path relative to this module
            base_dir = Path(__file__).resolve().parent.parent
            dialogues_path = base_dir / "data" / "dialogues.json"

        self.dialogues_path = Path(dialogues_path)
        self.dialogues: List[Dict[str, Any]] = []
        self._load_dialogues()

    def _load_dialogues(self) -> None:
        """Load dialogues from JSON file."""
        try:
            if not self.dialogues_path.exists():
                logger.warning(f"Dialogues file not found: {self.dialogues_path}")
                return

            with open(self.dialogues_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.dialogues = data.get('dialogues', [])
            logger.info(f"Loaded {len(self.dialogues)} dialogues")

        except Exception as e:
            logger.error(f"Failed to load dialogues: {e}")
            self.dialogues = []

    def get_dialogue(
        self,
        context: Optional[str] = None,
        speaker: Optional[str] = None,
        emotion: Optional[str] = None,
        allow_fallback: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Get a random dialogue matching the criteria.

        Args:
            context: Context filter (e.g., 'wifi_audit', 'boot', 'system')
            speaker: Speaker filter ('subzero' or 'rayden')
            emotion: Emotion filter (e.g., 'neutral', 'aggressive', 'sarcastic')
            allow_fallback: If True, fall back to broader matches if no exact match

        Returns:
            Dialogue dict or None if no match found
        """
        if not self.dialogues:
            return None

        # Start with all dialogues
        candidates = self.dialogues.copy()

        # Apply filters
        if context:
            context_matches = [d for d in candidates if d.get('context') == context]
            if context_matches:
                candidates = context_matches
            elif not allow_fallback:
                return None

        if speaker:
            speaker_matches = [d for d in candidates if d.get('speaker') == speaker]
            if speaker_matches:
                candidates = speaker_matches
            elif not allow_fallback:
                return None

        if emotion:
            emotion_matches = [d for d in candidates if d.get('emotion') == emotion]
            if emotion_matches:
                candidates = emotion_matches
            elif not allow_fallback:
                return None

        # Return random candidate if any found
        return random.choice(candidates) if candidates else None

    def get_conversation(
        self,
        context: str,
        length: int = 2,
        alternating: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get a conversation sequence for a context.

        Args:
            context: Context for the conversation
            length: Number of dialogue lines
            alternating: If True, alternate between speakers

        Returns:
            List of dialogue dicts forming a conversation
        """
        conversation = []
        last_speaker = None

        for i in range(length):
            # Alternate speakers if requested
            speaker_filter = None
            if alternating and last_speaker:
                speaker_filter = 'rayden' if last_speaker == 'subzero' else 'subzero'

            dialogue = self.get_dialogue(context=context, speaker=speaker_filter)
            if dialogue:
                conversation.append(dialogue)
                last_speaker = dialogue['speaker']
            else:
                break

        return conversation

    def get_contexts(self) -> List[str]:
        """Get all available contexts."""
        return list(set(d.get('context') for d in self.dialogues if d.get('context')))

    def get_speakers(self) -> List[str]:
        """Get all available speakers."""
        return list(set(d.get('speaker') for d in self.dialogues if d.get('speaker')))

    def get_emotions(self) -> List[str]:
        """Get all available emotions."""
        return list(set(d.get('emotion') for d in self.dialogues if d.get('emotion')))

    def get_stats(self) -> Dict[str, Any]:
        """Get dialogue statistics."""
        if not self.dialogues:
            return {"total_dialogues": 0}

        contexts = {}
        speakers = {}
        emotions = {}

        for d in self.dialogues:
            ctx = d.get('context', 'unknown')
            spk = d.get('speaker', 'unknown')
            emo = d.get('emotion', 'unknown')

            contexts[ctx] = contexts.get(ctx, 0) + 1
            speakers[spk] = speakers.get(spk, 0) + 1
            emotions[emo] = emotions.get(emo, 0) + 1

        return {
            "total_dialogues": len(self.dialogues),
            "contexts": contexts,
            "speakers": speakers,
            "emotions": emotions
        }

# Global dialogue manager instance
dialogue_manager = DialogueManager()

def get_dialogue(
    context: Optional[str] = None,
    speaker: Optional[str] = None,
    emotion: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get a dialogue.

    Args:
        context: Context filter
        speaker: Speaker filter ('subzero' or 'rayden')
        emotion: Emotion filter

    Returns:
        Dialogue dict or None
    """
    return dialogue_manager.get_dialogue(context, speaker, emotion)

def get_conversation(context: str, length: int = 2) -> List[Dict[str, Any]]:
    """
    Convenience function to get a conversation.

    Args:
        context: Context for conversation
        length: Number of dialogue lines

    Returns:
        List of dialogue dicts
    """
    return dialogue_manager.get_conversation(context, length)