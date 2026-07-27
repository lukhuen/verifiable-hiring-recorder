import sys
from pathlib import Path

# Allow `pytest` without setting PYTHONPATH manually.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
