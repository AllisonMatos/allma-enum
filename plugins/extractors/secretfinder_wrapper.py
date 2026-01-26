import re
import math
import sys

class SecretFinderWrapper:
    """
    Wrapper customizado que implementa a logica do SecretFinder:
    - Patterns regex especificos para secrets
    - Validacao de entropia (Shannon Entropy)
    - Filtragem de falsos positivos conhecidos
    """
    
    def __init__(self):
        # Patterns originais do SecretFinder + melhorias
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "Stripe Key": r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
            "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "Facebook OAuth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
            "Twitter OAuth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
            "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
            "Picatic API Key": r"sk_live_[0-9a-z]{32}",
            "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
            "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "Twilio API Key": r"SK[0-9a-fA-F]{32}",
            "Generic API Key": r"(?i)(?:api[_\-]?key|apikey|auth_token|access_token|secret)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
            "Generic Secret": r"(?i)(?:secret|password|pwd)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-!@#$%^&*]{8,64})['\"]"
        }
        
        # Ignorar strings comuns que geram falsos positivos
        self.ignore_list = {
            "undefined", "null", "true", "false", "NaN", "example", 
            "test", "demo", "sample", "your_api_key", "my-secret-key",
            "UA-XXXXX-Y", "xxxxxxxx", "text/javascript", "application/json"
        }

    def shannon_entropy(self, data):
        """
        Calcula a entropia de Shannon de uma string.
        Valores mais altos indicam maior aleatoriedade (bom para secrets).
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    def validate_key(self, key_data):
        """
        Aplica validacoes extras:
        - Entropia minima
        - Checksum (quando possivel)
        - Lista de ignorados
        """
        match_val = key_data["full_match"]
        key_type = key_data["type"]
        
        # 1. Check ignore list
        if any(ignore in match_val.lower() for ignore in self.ignore_list):
            return False
            
        # 2. Check Entropy (apenas para patterns genericos ou chaves longas)
        if "Generic" in key_type or len(match_val) > 20:
            entropy = self.shannon_entropy(match_val)
            # Valor empirico: hex ~3.5-4.0, base64 ~4.5-5.5
            if entropy < 3.0: 
                return False
                
        return True

    def get_context_lines(self, content, match_start, context_size=5):
        """
        Retorna linhas de contexto ao redor do match.
        """
        lines = content.splitlines()
        
        # Encontrar linha do match
        chars_counted = 0
        line_idx = 0
        for i, line in enumerate(lines):
            chars_counted += len(line) + 1  # +1 for newline
            if chars_counted > match_start:
                line_idx = i
                break
        
        start_line = max(0, line_idx - context_size)
        end_line = min(len(lines), line_idx + context_size + 1)
        
        context_lines = lines[start_line:end_line]
        
        return {
            "line_number": line_idx + 1,
            "full_context": "\\n".join(context_lines)
        }

    def scan(self, content):
        """
        Escaneia content e retorna keys validadas com contexto
        """
        found = []
        for name, regex in self.patterns.items():
            try:
                for match in re.finditer(regex, content):
                    key_val = match.group(1) if match.groups() else match.group(0)
                    start_pos = match.start()
                    
                    # Extrair contexto
                    context_data = self.get_context_lines(content, start_pos)
                    
                    key_item = {
                        "type": name,
                        "full_match": key_val,
                        "match": key_val[:10] + "..." if len(key_val) > 10 else key_val,
                        "context": {
                            "full": context_data["full_context"],
                            "line": context_data["line_number"]
                        }
                    }
                    
                    if self.validate_key(key_item):
                        found.append(key_item)
            except Exception:
                pass
                
        return found
