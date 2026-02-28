"""Coherence grid for tracking state coherence across a 2D coordinate space."""
from __future__ import annotations

from dataclasses import dataclass, field
@dataclass
class GridCell:
    coherence: float
    state: str = ""


class CoherenceGrid:
    """A 2D grid of cells each carrying a coherence score and optional state label."""

    def __init__(self) -> None:
        self._cells: dict[tuple[int, int], GridCell] = {}

    def add_cell(self, pos: tuple[int, int], coherence: float, state: str = "") -> None:
        self._cells[pos] = GridCell(coherence=coherence, state=state)

    def get_cell(self, pos: tuple[int, int]) -> GridCell | None:
        return self._cells.get(pos)

    def update_cell(self, pos: tuple[int, int], coherence: float, state: str = "") -> None:
        if pos in self._cells:
            self._cells[pos] = GridCell(coherence=coherence, state=state)

    def global_coherence(self) -> float:
        if not self._cells:
            return 0.0
        return sum(c.coherence for c in self._cells.values()) / len(self._cells)

    def detect_hotspots(self, threshold: float = 0.75) -> list[tuple[int, int]]:
        """Return positions whose coherence is below *threshold*."""
        return [pos for pos, cell in self._cells.items() if cell.coherence < threshold]

    def neighbors(self, pos: tuple[int, int]) -> list[tuple[int, int]]:
        """Return all existing grid positions within Chebyshev distance 1 of *pos*."""
        x, y = pos
        result: list[tuple[int, int]] = []
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                candidate = (x + dx, y + dy)
                if candidate in self._cells:
                    result.append(candidate)
        return result
