import os
import sys
import pytest

# Injeta src no sys.path para simplificar imports globais dos modulos do monitor
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
src_path = os.path.join(project_root, "src")

if src_path not in sys.path:
    sys.path.insert(0, src_path)
