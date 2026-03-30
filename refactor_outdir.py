import os
import re
from pathlib import Path

def refactor_ensure_outdir():
    plugins_dir = Path("plugins")
    
    # regex for the function definition
    func_pattern = re.compile(
        r'def\s+ensure_outdir\s*\([^)]*\)\s*(?:->\s*Path)?\s*:\s*\n'
        r'(?:\s+.*?\n)*?'
        r'\s+return\s+outdir\s*\n',
        re.MULTILINE
    )
    
    # regex for function calls with assignments
    call_pattern = re.compile(r'(outdir|raw_dir|results_dir|results_file_dir)\s*=\s*ensure_outdir\s*\(\s*target\s*\)')
    # and direct usage like `file = ensure_outdir(target) / "file.txt"`
    call_pattern2 = re.compile(r'ensure_outdir\s*\(\s*target\s*\)')

    for main_file in plugins_dir.rglob("main.py"):
        if main_file.parent.name == "plugins":
            continue
            
        module_name = main_file.parent.name
        content = main_file.read_text()
        
        # 1. Remove from utils.py if it exists, replace in main.py
        utils_file = main_file.parent / "utils.py"
        had_utils = False
        if utils_file.exists():
            u_content = utils_file.read_text()
            new_u_content = func_pattern.sub('', u_content)
            utils_file.write_text(new_u_content)
            had_utils = True
            
            # also remove "from .utils import ensure_outdir" from main.py
            content = re.sub(r'from\s+\.utils\s+import\s+(?:.*?,)?\s*ensure_outdir(?:\s*,.*?)?\s*\n', '', content)
            content = re.sub(r'from\s+\.utils\s+import\s+ensure_outdir\s*\n', '', content)
            
        # 2. Remove inline definition in main.py
        content = func_pattern.sub('', content)
        
        # 3. Add import
        if "from plugins import ensure_outdir" not in content:
            # find "from menu import C" or "import json" and insert
            content = content.replace("from menu import C", "from menu import C\nfrom plugins import ensure_outdir")
            if "from plugins import ensure_outdir" not in content:
                # Add it after imports
                content = "from plugins import ensure_outdir\n" + content
                
        # 4. Replace calls
        content = call_pattern2.sub(f'ensure_outdir(target, "{module_name}")', content)
        
        main_file.write_text(content)
        print(f"Refactored {main_file}")

if __name__ == "__main__":
    refactor_ensure_outdir()
