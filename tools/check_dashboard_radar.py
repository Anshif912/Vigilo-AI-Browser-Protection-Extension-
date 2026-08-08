import os

target = "c:\\CSP2\\dashboard"
for root, dirs, files in os.walk(target):
    if "node_modules" in root or ".git" in root or "dist" in root:
        continue
    for f in files:
        path = os.path.join(root, f)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
                if "canvas" in content.lower() or "shader" in content.lower() or "gl_" in content.lower() or "ogl" in content.lower() or "radar" in content.lower():
                    print(f"Match in: {path}")
        except Exception:
            pass
