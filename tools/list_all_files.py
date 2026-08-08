import os

target = "c:\\CSP2"
for root, dirs, files in os.walk(target):
    if "node_modules" in root or ".git" in root or "dist" in root or "build" in root:
        continue
    for f in files:
        if f.endswith((".tsx", ".jsx", ".ts", ".js", ".css", ".html")):
            print(os.path.join(root, f))
