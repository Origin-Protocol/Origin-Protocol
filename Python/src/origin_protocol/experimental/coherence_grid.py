"""Coherence grid for tracking state coherence across a 2D coordinate space."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class GridCell:
    coherence: float
    state: Optional[str] = None


class CoherenceGrid:
    """A 2D grid of cells each carrying a coherence score and an optional state label."""

    def __init__(self) -> None:
        self._cells: dict[tuple[int, int], GridCell] = {}

    def add_cell(
        self,
        coords: tuple[int, int],
        coherence: float,
        state: Optional[str] = None,
    ) -> None:
        """Add a cell at *coords* with the given coherence value and optional state."""
        self._cells[coords] = GridCell(coherence=coherence, state=state)

    def get_cell(self, coords: tuple[int, int]) -> Optional[GridCell]:
        """Return the cell at *coords*, or ``None`` if no cell exists there."""
        return self._cells.get(coords)

    def update_cell(
        self,
        coords: tuple[int, int],
        coherence: Optional[float] = None,
        state: Optional[str] = None,
    ) -> None:
        """Update an existing cell at *coords*.  Unknown coordinates are ignored."""
        cell = self._cells.get(coords)
        if cell is None:
            return
        if coherence is not None:
            cell.coherence = coherence
        if state is not None:
            cell.state = state

    def global_coherence(self) -> float:
        """Return the mean coherence of all cells in the grid."""
        if not self._cells:
            return 0.0
        return sum(c.coherence for c in self._cells.values()) / len(self._cells)

    def detect_hotspots(self, threshold: float = 0.75) -> list[tuple[int, int]]:
        """Return coordinates of cells whose coherence is below *threshold*."""
        return [
            coords
            for coords, cell in self._cells.items()
            if cell.coherence < threshold
        ]

    def neighbors(self, coords: tuple[int, int]) -> list[tuple[int, int]]:
        """Return coordinates of all existing cells that are adjacent (8-directional) to *coords*."""
        x, y = coords
        result: list[tuple[int, int]] = []
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                neighbor = (x + dx, y + dy)
                if neighbor in self._cells:
                    result.append(neighbor)
        return result
