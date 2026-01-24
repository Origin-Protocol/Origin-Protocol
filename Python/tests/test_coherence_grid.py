import unittest

from origin_protocol.experimental.coherence_grid import CoherenceGrid


class CoherenceGridTests(unittest.TestCase):
    def test_add_and_update_cell(self) -> None:
        grid = CoherenceGrid()
        grid.add_cell((0, 0), coherence=0.9, state="PLAN")
        cell = grid.get_cell((0, 0))
        self.assertIsNotNone(cell)
        self.assertEqual(cell.state, "PLAN")

        grid.update_cell((0, 0), coherence=0.8, state="ACTIVE")
        updated = grid.get_cell((0, 0))
        assert updated is not None
        self.assertEqual(updated.state, "ACTIVE")
        self.assertEqual(updated.coherence, 0.8)

    def test_global_coherence(self) -> None:
        grid = CoherenceGrid()
        grid.add_cell((0, 0), coherence=0.9)
        grid.add_cell((1, 0), coherence=0.7)
        self.assertAlmostEqual(grid.global_coherence(), 0.8)

    def test_detect_hotspots(self) -> None:
        grid = CoherenceGrid()
        grid.add_cell((0, 0), coherence=0.9)
        grid.add_cell((1, 0), coherence=0.6)
        hotspots = grid.detect_hotspots()
        self.assertIn((1, 0), hotspots)

    def test_neighbors(self) -> None:
        grid = CoherenceGrid()
        grid.add_cell((0, 0), coherence=0.9)
        grid.add_cell((1, 0), coherence=0.9)
        grid.add_cell((1, 1), coherence=0.9)
        neighbors = grid.neighbors((0, 0))
        self.assertIn((1, 0), neighbors)
        self.assertIn((1, 1), neighbors)


if __name__ == "__main__":
    unittest.main()
