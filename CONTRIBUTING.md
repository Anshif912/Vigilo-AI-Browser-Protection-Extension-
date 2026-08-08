# Contributing to Vigilo IntelligenceOS

Thank you for your interest in contributing to Vigilo! We welcome community contributions in threat intelligence rules, frontend UI enhancements, extension optimization, and backend performance.

---

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating in our community.

---

## Getting Started

### 1. Fork and Clone
```bash
git clone https://github.com/Anshif912/vigilo.git
cd vigilo
```

### 2. Environment Setup

#### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

#### Chrome Extension Setup
```bash
cd extension
npm install
npm run build
```

#### Dashboard Setup
```bash
cd dashboard
npm install
npm run dev
```

---

## Development Workflow

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/threat-rule-enhancement
   ```

2. **Code Standards**:
   - Follow PEP 8 for Python backend code.
   - Use TypeScript and ES6+ standards for Extension and Dashboard components.
   - Ensure all automated unit tests pass in `tests/`.

3. **Running Verification Tests**:
   ```bash
   python tests/test_v3_rule_engine.py
   python tests/test_threat_story_engine.py
   ```

4. **Submit a Pull Request**:
   - Provide a clear summary of changes and threat detection rationale.
   - Reference relevant issue numbers.

---

## Adding New Threat Intelligence Rules

New detection rules belong in `backend/engine/rules/`:
- Create `rule_<NN>_<name>.py`.
- Register the rule in `backend/engine/fusion_engine.py`.
- Include positive and negative test cases in `tests/`.
