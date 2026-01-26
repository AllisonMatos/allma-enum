"""
Wappalyzer-like technology detection module.
Detecta tecnologias baseado em headers, meta tags, scripts e patterns HTML.
"""

import re
import json
from typing import Dict, List, Optional

# Fingerprints de tecnologias comuns
TECH_FINGERPRINTS = {
    # CMS
    "WordPress": {
        "headers": {"x-powered-by": r"WordPress"},
        "meta": {"generator": r"WordPress"},
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "scripts": [r"wp-content", r"wp-includes"],
        "cookies": ["wordpress_"]
    },
    "Drupal": {
        "headers": {"x-drupal-cache": r".*", "x-generator": r"Drupal"},
        "meta": {"generator": r"Drupal"},
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
        "scripts": [r"drupal\.js", r"drupal\.min\.js"]
    },
    "Joomla": {
        "meta": {"generator": r"Joomla"},
        "html": [r"/media/jui/", r"/components/com_"],
        "scripts": [r"joomla\.javascript\.js"]
    },
    
    # Frameworks Frontend
    "React": {
        "html": [r"data-reactroot", r"data-reactid", r"__NEXT_DATA__", r"_next/static"],
        "scripts": [r"react\.production\.min\.js", r"react-dom", r"react\.min\.js"]
    },
    "Vue.js": {
        "html": [r"data-v-[a-f0-9]", r"v-cloak", r"__vue__"],
        "scripts": [r"vue\.min\.js", r"vue\.global", r"vue\.runtime"]
    },
    "Angular": {
        "html": [r"ng-version", r"ng-app", r"ng-controller", r"\[\(ngModel\)\]"],
        "scripts": [r"angular\.min\.js", r"angular\.js", r"zone\.js"]
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static"],
        "headers": {"x-powered-by": r"Next\.js"}
    },
    "Nuxt.js": {
        "html": [r"__NUXT__", r"_nuxt/"],
        "scripts": [r"nuxt\.js"]
    },
    "jQuery": {
        "scripts": [r"jquery[\.-][\d\.]+\.min\.js", r"jquery\.min\.js", r"jquery\.js"]
    },
    "Bootstrap": {
        "html": [r"class=\"[^\"]*\bcontainer\b", r"class=\"[^\"]*\brow\b", r"class=\"[^\"]*\bcol-"],
        "scripts": [r"bootstrap\.min\.js", r"bootstrap\.bundle"],
        "css": [r"bootstrap\.min\.css", r"bootstrap\.css"]
    },
    "Tailwind CSS": {
        "html": [r"class=\"[^\"]*\b(flex|grid|p-\d|m-\d|text-\w+-\d|bg-\w+-\d)"]
    },
    
    # Frameworks Backend
    "Laravel": {
        "headers": {"set-cookie": r"laravel_session"},
        "html": [r"laravel", r"XSRF-TOKEN"],
        "cookies": ["laravel_session", "XSRF-TOKEN"]
    },
    "Django": {
        "headers": {"set-cookie": r"csrftoken", "x-frame-options": r"SAMEORIGIN"},
        "html": [r"csrfmiddlewaretoken"],
        "cookies": ["csrftoken", "sessionid"]
    },
    "Ruby on Rails": {
        "headers": {"x-powered-by": r"Phusion Passenger", "x-runtime": r"[\d\.]+"},
        "html": [r"csrf-token", r"authenticity_token"]
    },
    "Express": {
        "headers": {"x-powered-by": r"Express"}
    },
    "ASP.NET": {
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".*"},
        "html": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"aspnetForm"],
        "cookies": ["ASP.NET_SessionId", ".AspNetCore."]
    },
    "Spring": {
        "headers": {"x-application-context": r".*"},
        "cookies": ["JSESSIONID"]
    },
    
    # Servidores
    "Nginx": {
        "headers": {"server": r"nginx"}
    },
    "Apache": {
        "headers": {"server": r"Apache"}
    },
    "IIS": {
        "headers": {"server": r"Microsoft-IIS"}
    },
    "Cloudflare": {
        "headers": {"server": r"cloudflare", "cf-ray": r".*"}
    },
    "Amazon CloudFront": {
        "headers": {"x-amz-cf-id": r".*", "via": r".*CloudFront"}
    },
    
    # E-commerce
    "Shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopid": r".*"}
    },
    "WooCommerce": {
        "html": [r"woocommerce", r"wc-add-to-cart"],
        "scripts": [r"woocommerce"]
    },
    "Magento": {
        "html": [r"Mage\.Cookies", r"/skin/frontend/", r"/js/mage/"],
        "cookies": ["frontend", "adminhtml"]
    },
    
    # Analytics
    "Google Analytics": {
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"GoogleAnalyticsObject"],
        "scripts": [r"google-analytics\.com", r"googletagmanager\.com"]
    },
    "Google Tag Manager": {
        "html": [r"googletagmanager\.com/gtm\.js"],
        "scripts": [r"gtm\.js"]
    },
    "Facebook Pixel": {
        "html": [r"connect\.facebook\.net", r"fbq\("],
        "scripts": [r"connect\.facebook\.net"]
    },
    
    # Seguranca
    "reCAPTCHA": {
        "html": [r"google\.com/recaptcha", r"grecaptcha"],
        "scripts": [r"recaptcha"]
    },
    "hCaptcha": {
        "html": [r"hcaptcha\.com", r"h-captcha"],
        "scripts": [r"hcaptcha\.com"]
    },
    
    # CDN/Libraries
    "cdnjs": {
        "scripts": [r"cdnjs\.cloudflare\.com"]
    },
    "jsDelivr": {
        "scripts": [r"cdn\.jsdelivr\.net"]
    },
    "unpkg": {
        "scripts": [r"unpkg\.com"]
    },
    
    # Outras
    "PHP": {
        "headers": {"x-powered-by": r"PHP", "set-cookie": r"PHPSESSID"}
    },
    "Java": {
        "cookies": ["JSESSIONID"]
    },
    "Node.js": {
        "headers": {"x-powered-by": r"Express|Node"}
    },
}


def detect_technologies(
    html: str = None,
    headers: Dict[str, str] = None,
    cookies: List[str] = None,
    scripts: List[str] = None,
    url: str = None
) -> List[Dict]:
    """
    Detecta tecnologias baseado em HTML, headers, cookies e scripts.
    
    Args:
        html: Conteudo HTML da pagina
        headers: Headers HTTP da resposta
        cookies: Lista de nomes de cookies
        scripts: Lista de URLs de scripts
        url: URL da pagina (para contexto)
        
    Returns:
        Lista de tecnologias detectadas com confidence
    """
    detected = []
    headers = headers or {}
    cookies = cookies or []
    scripts = scripts or []
    html = html or ""
    
    # Normalizar headers para lowercase
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for tech_name, fingerprints in TECH_FINGERPRINTS.items():
        confidence = 0
        evidence = []
        
        # Verificar headers
        if "headers" in fingerprints:
            for header, pattern in fingerprints["headers"].items():
                if header in headers_lower:
                    if re.search(pattern, headers_lower[header], re.I):
                        confidence += 30
                        evidence.append(f"Header: {header}")
        
        # Verificar meta tags
        if "meta" in fingerprints and html:
            for meta_name, pattern in fingerprints["meta"].items():
                meta_pattern = rf'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']([^"\']+)["\']'
                match = re.search(meta_pattern, html, re.I)
                if match and re.search(pattern, match.group(1), re.I):
                    confidence += 40
                    evidence.append(f"Meta tag: {meta_name}")
        
        # Verificar patterns HTML
        if "html" in fingerprints and html:
            for pattern in fingerprints["html"]:
                if re.search(pattern, html, re.I):
                    confidence += 20
                    evidence.append(f"HTML pattern matched")
                    break
        
        # Verificar scripts
        if "scripts" in fingerprints:
            for pattern in fingerprints["scripts"]:
                # Verificar na lista de scripts
                for script in scripts:
                    if re.search(pattern, script, re.I):
                        confidence += 25
                        evidence.append(f"Script: {pattern}")
                        break
                # Verificar no HTML tambem
                if html and re.search(rf'src=["\'][^"\']*{pattern}', html, re.I):
                    confidence += 25
                    evidence.append(f"Script in HTML")
                    break
        
        # Verificar cookies
        if "cookies" in fingerprints:
            for cookie_pattern in fingerprints["cookies"]:
                for cookie in cookies:
                    if cookie_pattern.lower() in cookie.lower():
                        confidence += 30
                        evidence.append(f"Cookie: {cookie_pattern}")
                        break
        
        # Adicionar se confidence > 0
        if confidence > 0:
            detected.append({
                "name": tech_name,
                "confidence": min(confidence, 100),  # Cap at 100
                "evidence": evidence,
                "category": get_tech_category(tech_name)
            })
    
    # Ordenar por confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)
    
    return detected


def get_tech_category(tech_name: str) -> str:
    """
    Retorna a categoria da tecnologia.
    """
    categories = {
        "CMS": ["WordPress", "Drupal", "Joomla"],
        "Frontend Framework": ["React", "Vue.js", "Angular", "Next.js", "Nuxt.js"],
        "JavaScript Library": ["jQuery", "Bootstrap", "Tailwind CSS"],
        "Backend Framework": ["Laravel", "Django", "Ruby on Rails", "Express", "ASP.NET", "Spring"],
        "Web Server": ["Nginx", "Apache", "IIS"],
        "CDN/Proxy": ["Cloudflare", "Amazon CloudFront"],
        "E-commerce": ["Shopify", "WooCommerce", "Magento"],
        "Analytics": ["Google Analytics", "Google Tag Manager", "Facebook Pixel"],
        "Security": ["reCAPTCHA", "hCaptcha"],
        "Programming Language": ["PHP", "Java", "Node.js"],
    }
    
    for category, techs in categories.items():
        if tech_name in techs:
            return category
            
    return "Other"


def analyze_page(url: str, html: str, headers: Dict = None) -> Dict:
    """
    Analisa uma pagina completa e retorna tecnologias detectadas.
    """
    # Extrair cookies dos headers
    cookies = []
    if headers and "set-cookie" in {k.lower() for k in headers.keys()}:
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                cookie_name = v.split("=")[0] if "=" in v else v
                cookies.append(cookie_name)
    
    # Extrair scripts do HTML
    scripts = []
    if html:
        script_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        scripts.extend(script_matches)
    
    # Detectar tecnologias
    technologies = detect_technologies(
        html=html,
        headers=headers,
        cookies=cookies,
        scripts=scripts,
        url=url
    )
    
    return {
        "url": url,
        "technologies": technologies,
        "total_detected": len(technologies)
    }


def format_technologies_report(results: List[Dict]) -> str:
    """
    Formata resultados de deteccao em texto.
    """
    lines = []
    
    for result in results:
        lines.append(f"\n{'=' * 60}")
        lines.append(f"URL: {result['url']}")
        lines.append(f"Technologies detected: {result['total_detected']}")
        lines.append("-" * 40)
        
        for tech in result['technologies']:
            confidence_bar = "#" * (tech['confidence'] // 10)
            lines.append(
                f"  [{tech['confidence']:3d}%] {confidence_bar:<10} "
                f"{tech['name']} ({tech['category']})"
            )
            
    return "\n".join(lines)
