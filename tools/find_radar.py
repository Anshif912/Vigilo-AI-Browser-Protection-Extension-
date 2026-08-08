import os

target = "c:\\CSP2"
matches = []

for root, dirs, files in os.walk(target):
    if "node_modules" in root or ".git" in root or "dist" in root or "build" in root:
        continue
    for f in files:
        if f.endswith((".tsx", ".jsx", ".ts", ".js", ".css", ".html")):
            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as file:
                    content = file.read()
                    if "Radar" in content or "1080px" in content:
                        matches.append(path)
            except Exception:
                pass

print("Found files:")
for m in matches:
    print(m)
