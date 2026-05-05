import json
import os
import threading
import uuid
from pathlib import Path

class OastClient:
    """Cliente OAST que gerencia payloads e leitura de resultados do interactsh-client."""

    def __init__(self, interactsh_bin="interactsh-client", payloads_file=None, results_file=None):
        self.bin = interactsh_bin
        self._lock = threading.Lock()

        # Gera um identificador único para esta sessão
        self.session_id = uuid.uuid4().hex[:5]
        # O host base real será determinado quando o binário iniciar, mas usamos um placeholder
        self.base_host = f"{self.session_id}.oast.live"

        # Arquivos de controle
        if payloads_file is None:
            self.payloads_file = Path("output/oast_payloads.txt")
        else:
            self.payloads_file = Path(payloads_file)

        if results_file is None:
            self.results_file = Path("output/oast_results.json")
        else:
            self.results_file = Path(results_file)

        self._proc = None
        self._last_poll_line = 0  # controle de linha para poll incremental

    def start(self, timeout=45):
        """Inicia o subprocesso do interactsh-client e aguarda a URL."""
        import subprocess
        import time
        
        # Limpar payload_file antigo se existir
        if self.payloads_file.exists():
            self.payloads_file.unlink()

        # V11.6: Token persistence — manter mesmo subdomínio OAST entre execuções
        token_file = self.payloads_file.parent / ".oast_token"
        token = None
        if token_file.exists():
            token = token_file.read_text().strip()
        if not token:
            token = uuid.uuid4().hex
            token_file.write_text(token)

        cmd = [
            self.bin,
            "-json",
            "-o", str(self.results_file),
            "-ps", "-psf", str(self.payloads_file),
            "-token", token,              # V11.6: Persistência de sessão OAST
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Aguarda o Interactsh escrever a URL base no arquivo
        start_wait = time.time()
        while time.time() - start_wait < timeout:
            if self.payloads_file.exists():
                content = self.payloads_file.read_text().strip()
                if content:
                    self.base_host = content
                    return self.base_host
            time.sleep(1)
        
        return None

    def stop(self):
        """Encerra o subprocesso."""
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def get_url(self, subdomain: str = "") -> str:
        """Retorna uma URL OAST única para injeção."""
        if subdomain:
            return f"{subdomain}.{self.base_host}"
        return self.base_host

    def add_payload(self, url: str):
        """Adiciona uma URL/domínio ao arquivo de payloads a monitorar."""
        with self._lock:
            with open(self.payloads_file, "a") as f:
                f.write(url + "\n")

    def poll(self, timeout: float = 5.0) -> list:
        """
        Lê novas interações do arquivo JSON de resultados.
        Retorna uma lista de dicts com as interações desde a última chamada.
        """
        if not self.results_file.exists():
            return []

        new_entries = []
        with self._lock:
            try:
                with open(self.results_file, "r") as f:
                    f.seek(self._last_poll_line)
                    for line in f:
                        if line.strip():
                            try:
                                entry = json.loads(line)
                                new_entries.append(entry)
                            except json.JSONDecodeError:
                                pass
                    self._last_poll_line = f.tell()  # guarda até onde lemos
            except Exception:
                pass
        return new_entries