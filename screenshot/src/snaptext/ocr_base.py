"""Shared OCR types."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class OcrBox:
    text: str
    x: int
    y: int
    w: int
    h: int
    conf: float = 1.0


@dataclass
class OcrResult:
    engine: str
    text: str
    boxes: list[OcrBox] = field(default_factory=list)
    mean_conf: float = 0.0

    def __post_init__(self):
        if self.boxes and self.mean_conf == 0.0:
            self.mean_conf = sum(b.conf for b in self.boxes) / max(1, len(self.boxes))
