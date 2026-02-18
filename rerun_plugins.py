
from plugins.cors import main as cors_main
from plugins.headers import main as headers_main
from menu import C

target = "loylegal.com"
context = {"target": target}

print(f"{C.BOLD}Re-running CORS scan...{C.END}")
cors_main.run(context)

print(f"{C.BOLD}Re-running Headers scan...{C.END}")
headers_main.run(context)

print(f"{C.BOLD}Done.{C.END}")
