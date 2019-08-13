import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from maintain_kubeusers import maintain_kubeusers  # noqa: E402,F401
