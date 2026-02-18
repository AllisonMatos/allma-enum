
import sys
import os
from pathlib import Path

# Add root to path
sys.path.append(os.getcwd())

from plugins.report.main import run

context = {
    "target": "loylegal.com"
}

print("Regenerating official report...")
run(context)
print("Report regenerated.")
