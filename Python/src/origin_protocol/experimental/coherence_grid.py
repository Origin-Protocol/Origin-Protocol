from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Dict, Iterable


CellState = str


@dataclass(frozen=True)
class GridCell:
    state: CellState
    coherence: float
    timestamp: str


@dataclass(frozen=True)
class GridAnalysis:
    global_coherence: float
    hotspots: tuple[tuple[int, int], ...]
    recommendations: tuple[str, ...]


class CoherenceGrid:
    """Experimental coherence grid.

    This module is non-critical to Origin Protocol and may be removed.
    """

    NEIGHBOR_OFFSETS: tuple[tuple[int, int], ...] = (
        (-1, 0),
        (1, 0),
        (0, -1),
        (0, 1),
        (-1, -1),
        (1, 1),
    )

    def __init__(self) -> None:
        self._cells: Dict[tuple[int, int], GridCell] = {}

    def add_cell(self, coord: tuple[int, int], coherence: float, state: CellState = "PLAN") -> None:
        self._cells[coord] = GridCell(state=state, coherence=coherence, timestamp=_now_iso())

    def update_cell(self, coord: tuple[int, int], *, coherence: float | None = None, state: CellState | None = None) -> None:
        current = self._cells.get(coord)
        if current is None:
            raise KeyError(f"Cell not found: {coord}")
        updated = replace(
            current,
            coherence=coherence if coherence is not None else current.coherence,
            state=state if state is not None else current.state,
            timestamp=_now_iso(),
        )
        self._cells[coord] = updated

    def get_cell(self, coord: tuple[int, int]) -> GridCell | None:
        return self._cells.get(coord)

    def neighbors(self, coord: tuple[int, int]) -> tuple[tuple[int, int], ...]:
        return tuple(
            (coord[0] + dx, coord[1] + dy)
            for dx, dy in self.NEIGHBOR_OFFSETS
            if (coord[0] + dx, coord[1] + dy) in self._cells
        )

    def global_coherence(self) -> float:
        if not self._cells:
            return 0.0
        return sum(cell.coherence for cell in self._cells.values()) / len(self._cells)

    def detect_hotspots(self, threshold: float | None = None) -> tuple[tuple[int, int], ...]:
        if not self._cells:
            return tuple()
        baseline = self.global_coherence()
        cutoff = threshold if threshold is not None else baseline * 0.9
        return tuple(coord for coord, cell in self._cells.items() if cell.coherence < cutoff)

    def analyze(self) -> GridAnalysis:
        global_coherence = self.global_coherence()
        hotspots = self.detect_hotspots()
        recommendations = self._recommendations(hotspots, global_coherence)
        return GridAnalysis(
            global_coherence=global_coherence,
            hotspots=hotspots,
            recommendations=recommendations,
        )

    def _recommendations(self, hotspots: Iterable[tuple[int, int]], global_coherence: float) -> tuple[str, ...]:
        hotspot_list = tuple(hotspots)
        recommendations = []
        if not hotspot_list:
            recommendations.append("Coherence stable across grid.")
        else:
            recommendations.append(f"{len(hotspot_list)} hotspots detected; rebalance local patterns.")
        if global_coherence < 0.7:
            recommendations.append("Global coherence below 0.7; consider reducing entropy inputs.")
        return tuple(recommendations)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
