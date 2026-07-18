from __future__ import annotations

from textual.widgets import ProgressBar, Static
from textual.reactive import reactive
from textual.app import ComposeResult
import math


class StrengthBar(Static):
    """Password strength meter widget."""

    strength = reactive(0.0)

    CSS = """
    StrengthBar {
        width: 100%;
        height: 1;
    }
    """

    def __init__(self, password: str = "", **kwargs):
        super().__init__(**kwargs)
        self.update_strength(password)

    def update_strength(self, password: str):
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 20:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        self.strength = min(score / 6.0, 1.0)
        label = self._label()
        self.update(f"[{label['style']}]{label['text']}[/]")

    def _label(self) -> dict:
        if self.strength < 0.3:
            return {"text": "Weak", "style": "red"}
        elif self.strength < 0.6:
            return {"text": "Fair", "style": "yellow"}
        elif self.strength < 0.8:
            return {"text": "Strong", "style": "green"}
        return {"text": "Very Strong", "style": "bold green"}
