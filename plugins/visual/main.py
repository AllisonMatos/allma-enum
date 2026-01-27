#!/usr/bin/env python3
"""
Plugin VISUAL RECON - Tira screenshots de URLs válidas usando gowitness
"""
import shutil
import subprocess
from pathlib import Path

from menu import C
from ..output import info, success, warn, error
from .utils import ensure_outdir

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   📸 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: VISUAL RECON{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )
    
    outdir = ensure_outdir(target)
    screenshots_dir = outdir / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)
    
    # Arquivo de entrada: urls_200.txt
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
        
    if not urls_file.exists():
        warn("⚠️ Nenhuma lista de URLs encontrada para visual recon.")
        return []
        
    # Verificar gowitness
    # Pode estar no PATH ou em ~/go/bin
    gowitness = shutil.which("gowitness")
    if not gowitness:
        home = Path.home()
        possible_path = home / "go" / "bin" / "gowitness"
        if possible_path.exists():
            gowitness = str(possible_path)
            
    if not gowitness:
        warn("⚠️ gowitness não encontrado. Instale com: go install github.com/sensepost/gowitness@latest")
        return []
        
    info(f"{C.BLUE}📸 Tirando screenshots com {gowitness}...{C.END}")
    
    # gowitness scan file -f <file> --screenshot-path <dir> --no-http --threads 5
    cmd = [
        gowitness,
        "scan",
        "file",
        "-f", str(urls_file),
        "--screenshot-path", str(screenshots_dir),
        "--threads", "5",
        "--write-db", str(outdir / "gowitness.sqlite3") 
    ]
    
    try:
        # Popen para ver output em tempo real se quiser, mas aqui vamos capturar
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # Verify output
        count = len(list(screenshots_dir.glob("*.png"))) + len(list(screenshots_dir.glob("*.jpeg"))) + len(list(screenshots_dir.glob("*.jpg")))
        if count > 0:
            success(f"✨ {count} screenshots salvas em {screenshots_dir}")
            
            # Gerar relatório HTML simples (galeria)
            generate_gallery(target, screenshots_dir, outdir / "gallery.html")
            
            return [str(screenshots_dir)]
        else:
            warn("⚠️ Nenhuma screenshot gerada.")
            if proc.stderr:
                info(f"Stderr: {proc.stderr[:500]}")
            
    except Exception as e:
        error(f"Erro ao executar gowitness: {e}")
        
    return []

def generate_gallery(target, img_dir, out_file):
    """Gera uma galeria HTML simples"""
    images = sorted(list(img_dir.glob("*.png")) + list(img_dir.glob("*.jpeg")) + list(img_dir.glob("*.jpg")))
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Visual Recon - {target}</title>
    <style>
        body {{ background: #1a1a1a; color: #fff; font-family: sans-serif; padding: 20px; }}
        .gallery {{ display: flex; flex-wrap: wrap; gap: 20px; }}
        .card {{ background: #333; padding: 10px; border-radius: 5px; width: 300px; }}
        img {{ max-width: 100%; border: 1px solid #555; }}
        a {{ color: #4af; text-decoration: none; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>Visual Recon: {target}</h1>
    <div class="gallery">
"""
    
    for img in images:
        # Filename usually is the URL sanitized.
        # gowitness format: http-example-com.png
        url_guess = img.stem.replace("-", ".").replace("http.", "http://").replace("https.", "https://")
        
        html += f"""
        <div class="card">
            <a href="{url_guess}" target="_blank">{url_guess}</a><br>
            <a href="screenshots/{img.name}" target="_blank">
                <img src="screenshots/{img.name}" loading="lazy">
            </a>
        </div>
"""

    html += """
    </div>
</body>
</html>
"""
    out_file.write_text(html)
    success(f"🖼️ Galeria HTML gerada: {out_file}")
