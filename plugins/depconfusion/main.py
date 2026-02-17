"""
Dependency Confusion Scanner — Detecta pacotes internos/privados
que podem ser registrados no npm público para supply chain attacks.
"""
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from ..output import info, success, warn, error

# Módulos built-in do Node.js (não devem ser verificados no npm)
NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
    # Web APIs / Browser built-ins
    "react", "react-dom", "vue", "angular", "svelte",
    "next", "nuxt", "gatsby",
    "webpack", "vite", "rollup", "esbuild", "parcel",
    "express", "koa", "fastify", "hapi",
    "lodash", "moment", "dayjs", "date-fns",
    "axios", "node-fetch", "got", "superagent",
    "jquery", "d3", "chart.js", "three",
    "typescript", "babel", "eslint", "prettier",
    "jest", "mocha", "chai", "jasmine",
    "mongoose", "sequelize", "knex", "prisma",
    "socket.io", "ws", "graphql", "apollo",
    "redux", "mobx", "zustand", "recoil",
    "tailwindcss", "bootstrap", "material-ui", "antd",
    "uuid", "chalk", "commander", "yargs", "inquirer",
    "dotenv", "cors", "helmet", "jsonwebtoken",
    "bcrypt", "passport", "multer", "formidable",
    "nodemailer", "bull", "agenda", "cron",
    "winston", "pino", "morgan", "debug",
    "sharp", "jimp", "canvas",
    "puppeteer", "playwright", "cheerio",
}

# Regexes para extrair nomes de pacotes
IMPORT_PATTERNS = [
    # require('package') / require("package")
    re.compile(r'''require\s*\(\s*['"]([a-z@][a-z0-9\-_./@]*)['"]\s*\)'''),
    # import ... from 'package' / import ... from "package"
    re.compile(r'''import\s+.*?\s+from\s+['"]([a-z@][a-z0-9\-_./@]*)['"]'''),
    # import('package') — dynamic import
    re.compile(r'''import\s*\(\s*['"]([a-z@][a-z0-9\-_./@]*)['"]\s*\)'''),
    # export ... from 'package'
    re.compile(r'''export\s+.*?\s+from\s+['"]([a-z@][a-z0-9\-_./@]*)['"]'''),
]


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "depconfusion"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def extract_packages_from_content(content: str, source: str) -> list:
    """Extrai nomes de pacotes de conteúdo JavaScript."""
    packages = []
    seen = set()

    for pattern in IMPORT_PATTERNS:
        for match in pattern.finditer(content):
            pkg_name = match.group(1)

            # Normalizar: pegar apenas o pacote (não subpaths)
            # @scope/name/subpath → @scope/name
            # name/subpath → name
            if pkg_name.startswith("@"):
                parts = pkg_name.split("/")
                if len(parts) >= 2:
                    pkg_name = f"{parts[0]}/{parts[1]}"
                else:
                    continue
            else:
                pkg_name = pkg_name.split("/")[0]

            # Filtrar
            if pkg_name in seen:
                continue
            if pkg_name in NODE_BUILTINS:
                continue
            if pkg_name.startswith("."):  # relative import
                continue
            if len(pkg_name) < 2:
                continue

            seen.add(pkg_name)
            packages.append({
                "package": pkg_name,
                "found_in": source,
            })

    return packages


def check_npm_exists(package_name: str) -> dict:
    """
    Verifica se um pacote existe no npm público.
    Retorna info sobre existência e detalhes.
    """
    import httpx

    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(f"https://registry.npmjs.org/{package_name}")

            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("dist-tags", {}).get("latest", "unknown")
                maintainers = data.get("maintainers", [])
                maintainer_names = [m.get("name", "") for m in maintainers[:3]]

                return {
                    "npm_exists": True,
                    "latest_version": latest,
                    "maintainers": maintainer_names,
                    "risk": "LOW",
                    "note": f"Pacote existe no npm (v{latest})",
                }
            elif resp.status_code == 404:
                return {
                    "npm_exists": False,
                    "latest_version": None,
                    "maintainers": [],
                    "risk": "HIGH",
                    "note": "Pacote NÃO EXISTE no npm — potencial dependency confusion!",
                }
            else:
                return {
                    "npm_exists": None,
                    "latest_version": None,
                    "maintainers": [],
                    "risk": "UNKNOWN",
                    "note": f"HTTP {resp.status_code} ao verificar npm",
                }
    except Exception as e:
        return {
            "npm_exists": None,
            "latest_version": None,
            "maintainers": [],
            "risk": "UNKNOWN",
            "note": f"Erro ao verificar npm: {str(e)[:80]}",
        }


def run(context: dict):
    """Executa scan de dependency confusion."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟨───────────────────────────────────────────────────────────🟨\n"
        f"   📦 {C.BOLD}{C.CYAN}DEPENDENCY CONFUSION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟨───────────────────────────────────────────────────────────🟨\n"
    )

    outdir = ensure_outdir(target)

    # Fontes de JS
    # 1. extracted_js.json (URLs de JS encontrados)
    # 2. JS já baixados no wordlist
    js_sources = {}

    # Ler extracted_js.json
    js_json_file = Path("output") / target / "domain" / "extracted_js.json"
    if js_json_file.exists():
        try:
            js_data = json.loads(js_json_file.read_text())
            for js_entry in js_data:
                js_url = js_entry.get("url", "")
                if js_url:
                    js_sources[js_url] = "extracted_js"
        except Exception:
            pass

    # Ler conteúdo dos JS (baixar os que ainda não temos)
    info(f"   📥 Baixando e analisando {len(js_sources)} arquivos JS...")

    all_packages = []
    seen_packages = set()

    def fetch_and_extract(url):
        import httpx
        try:
            with httpx.Client(timeout=10, verify=False, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    return extract_packages_from_content(resp.text, url)
        except Exception:
            pass
        return []

    # Extrair pacotes de JS files
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_extract, url): url for url in js_sources}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 10 == 0:
                print(f"   [{done}/{len(js_sources)}] JS files analyzed...", end="\r")
            try:
                pkgs = future.result()
                for pkg in pkgs:
                    if pkg["package"] not in seen_packages:
                        seen_packages.add(pkg["package"])
                        all_packages.append(pkg)
            except Exception:
                pass

    print("")

    if not all_packages:
        warn("   ⚠️ Nenhum pacote encontrado nos arquivos JS.")
        return []

    info(f"   📋 {len(all_packages)} pacotes únicos encontrados. Verificando no npm...")

    # Verificar cada pacote no npm
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_npm_exists, pkg["package"]): pkg for pkg in all_packages}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 20 == 0:
                print(f"   [{done}/{len(all_packages)}] npm checked...", end="\r")
            try:
                pkg = futures[future]
                npm_result = future.result()
                pkg.update(npm_result)
                results.append(pkg)

                if not npm_result.get("npm_exists"):
                    risk_color = C.RED if npm_result["risk"] == "HIGH" else C.YELLOW
                    info(f"   ⚠️  {risk_color}{pkg['package']}{C.END} — {npm_result['note']}")
            except Exception:
                pass

    print("")

    # Ordenar: HIGH risk primeiro
    risk_order = {"HIGH": 0, "UNKNOWN": 1, "LOW": 2}
    results.sort(key=lambda x: risk_order.get(x.get("risk", "UNKNOWN"), 1))

    # Salvar resultados
    output_file = outdir / "depconfusion.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    # Stats
    high_risk = [r for r in results if r.get("risk") == "HIGH"]
    npm_exists = [r for r in results if r.get("npm_exists") is True]
    unknown = [r for r in results if r.get("npm_exists") is None]

    info(f"\n   📊 Resultados:")
    info(f"      Total pacotes analisados: {len(results)}")
    info(f"      Existem no npm: {C.GREEN}{len(npm_exists)}{C.END}")
    info(f"      {C.RED}{C.BOLD}NÃO existem (RISCO!): {len(high_risk)}{C.END}")
    info(f"      Status desconhecido: {len(unknown)}")

    if high_risk:
        warn(f"\n   🚨 {len(high_risk)} PACOTES COM RISCO DE DEPENDENCY CONFUSION:")
        for pkg in high_risk:
            warn(f"      → {pkg['package']} (encontrado em {pkg['found_in']})")

    success(f"   📂 Resultados salvos em {output_file}\n")

    return results
