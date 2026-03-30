import re
from pathlib import Path

files = list(Path('plugins').rglob('*.py'))
ua_regex = re.compile(r'["\']User-Agent["\']\s*:\s*["\']Mozilla/5\.0[^"\']*["\']')

for f in files:
    try:
        content = f.read_text(errors='ignore')
        if 'User-Agent' in content and 'Mozilla' in content:
            new_content = ua_regex.sub('"User-Agent": DEFAULT_USER_AGENT', content)
            
            if new_content != content:
                if 'from core.config import DEFAULT_USER_AGENT' not in new_content:
                    lines = new_content.splitlines()
                    for i, line in enumerate(lines):
                        if line.startswith('import ') or line.startswith('from '):
                            lines.insert(i, "from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY")
                            break
                    new_content = '\n'.join(lines) + '\n'
                f.write_text(new_content)
                print(f"Patched User-Agent in {f}")
    except Exception as e:
        print(f"Error reading {f}: {e}")
