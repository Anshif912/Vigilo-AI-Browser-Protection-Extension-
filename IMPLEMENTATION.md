# Vigilo - Implementation Guide

## Requirements

- Python 3.10+
- Node.js 18+
- Google Chrome

---

## 1. Start Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend runs at:

```
http://localhost:8000
```

---

## 2. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard runs at:

```
http://localhost:5173
```

---

## 3. Load Chrome Extension

1. Open Chrome.
2. Go to:

```
chrome://extensions
```

3. Enable **Developer Mode**.
4. Click **Load unpacked**.
5. Select the **extension/dist/** folder.

The extension is now installed.

---

## 4. Run the Project

- Make sure the backend is running.
- Make sure the dashboard is running.
- Open any website.
- Vigilo will analyze URLs automatically.
- If a phishing website is detected, the protection page will appear.

---

## Troubleshooting

**Extension not loading**
- Check `manifest.json`.
- Enable Developer Mode.

**Backend not running**
- Verify `http://localhost:8000/docs` opens.

**Dashboard not starting**
- Run:

```bash
npm install
```

again.

---

For more details, refer to the main `README.md`.