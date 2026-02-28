"""Coherence grid for tracking state coherence across a 2D coordinate space."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

Coord = Tuple[int, int]


@dataclass
class GridCell:
    coord: Coord
    coherence: float
    state: str = "INIT"


class CoherenceGrid:
    """A 2D grid of cells, each with a coherence score and optional state label."""

    def __init__(self) -> None:
        self._cells: Dict[Coord, GridCell] = {}

    def add_cell(self, coord: Coord, coherence: float = 1.0, state: str = "INIT") -> None:
        self._cells[coord] = GridCell(coord=coord, coherence=coherence, state=state)

    def get_cell(self, coord: Coord) -> Optional[GridCell]:
        return self._cells.get(coord)

    def update_cell(
        self,
        coord: Coord,
        coherence: Optional[float] = None,
        state: Optional[str] = None,
    ) -> None:
        cell = self._cells.get(coord)
        if cell is None:
            raise KeyError(f"No cell at {coord}")
        if coherence is not None:
            cell.coherence = coherence
        if state is not None:
            cell.state = state

    def global_coherence(self) -> float:
        if not self._cells:
            return 0.0
        return sum(c.coherence for c in self._cells.values()) / len(self._cells)

    def detect_hotspots(self) -> List[Coord]:
        avg = self.global_coherence()
        return [coord for coord, cell in self._cells.items() if cell.coherence < avg]

    def neighbors(self, coord: Coord) -> List[Coord]:
        x, y = coord
        result = []
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                neighbor = (x + dx, y + dy)
                if neighbor in self._cells:
                    result.append(neighbor)
        return result
