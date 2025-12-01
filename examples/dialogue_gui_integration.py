"""
examples/dialogue_gui_integration.py

Example of how to integrate the English dialogue system into your GUI.
This shows how to use the dialogue system for cyberpunk terminal interfaces.
"""

from ai.dialogue import get_dialogue, get_conversation, dialogue_manager

def display_dialogue_in_terminal(speaker: str, text: str, emotion: str = "neutral"):
    """
    Display dialogue in a cyberpunk terminal style.

    Args:
        speaker: 'subzero' or 'rayden'
        text: The dialogue text
        emotion: Emotion for styling
    """
    # Define colors for speakers
    colors = {
        'subzero': '\033[96m',  # Cyan for ice/cold
        'rayden': '\033[93m',   # Yellow for electricity/lightning
    }

    # Define emotion indicators
    emotion_icons = {
        'neutral': '○',
        'aggressive': '▲',
        'sarcastic': '◆',
        'calm': '●',
        'warning': '△',
        'debug': '□'
    }

    color = colors.get(speaker, '\033[97m')  # White default
    icon = emotion_icons.get(emotion, '○')
    reset = '\033[0m'

    speaker_name = speaker.upper()
    print(f"{color}{icon} {speaker_name}:{reset} {text}")

def example_gui_integration():
    """Example of how to integrate dialogues into your GUI."""

    print("🔥 SUBZERO vs RAYDEN - CYBERPUNK TERMINAL INTERFACE")
    print("=" * 60)

    # Example 1: Boot sequence
    print("\n[BOOT SEQUENCE]")
    boot_dialogue = get_dialogue(context='boot')
    if boot_dialogue:
        display_dialogue_in_terminal(
            boot_dialogue['speaker'],
            boot_dialogue['text'],
            boot_dialogue['emotion']
        )

    # Example 2: WiFi audit in progress
    print("\n[WIFI AUDIT IN PROGRESS]")
    wifi_conversation = get_conversation('wifi_audit', 2)
    for dialogue in wifi_conversation:
        display_dialogue_in_terminal(
            dialogue['speaker'],
            dialogue['text'],
            dialogue['emotion']
        )

    # Example 3: System status update
    print("\n[SYSTEM STATUS UPDATE]")
    system_dialogue = get_dialogue(context='system', speaker='rayden')
    if system_dialogue:
        display_dialogue_in_terminal(
            system_dialogue['speaker'],
            system_dialogue['text'],
            system_dialogue['emotion']
        )

    # Example 4: Success notification
    print("\n[AUDIT COMPLETED SUCCESSFULLY]")
    success_conversation = get_conversation('success', 2)
    for dialogue in success_conversation:
        display_dialogue_in_terminal(
            dialogue['speaker'],
            dialogue['text'],
            dialogue['emotion']
        )

    print("\n" + "=" * 60)
    print("💡 INTEGRATION TIPS:")
    print("• Use get_dialogue(context='your_context') for single messages")
    print("• Use get_conversation(context, length) for multi-turn dialogues")
    print("• Filter by speaker: get_dialogue(context='wifi_audit', speaker='subzero')")
    print("• Filter by emotion: get_dialogue(context='error', emotion='warning')")
    print("• Access via API: GET /api/ai/dialogue?context=wifi_audit")

def get_available_contexts():
    """Show all available dialogue contexts."""
    stats = dialogue_manager.get_stats()
    print("\n📋 AVAILABLE DIALOGUE CONTEXTS:")
    for context, count in stats['contexts'].items():
        print(f"  • {context}: {count} dialogues")

    print(f"\n🎭 SPEAKERS: {', '.join(stats['speakers'].keys())}")
    print(f"😊 EMOTIONS: {', '.join(stats['emotions'].keys())}")

if __name__ == "__main__":
    example_gui_integration()
    get_available_contexts()