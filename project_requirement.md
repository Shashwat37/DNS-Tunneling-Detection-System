# DNS Tunneling Detection System — Project Requirements

## 1. Overview
A simple web application that detects DNS tunneling activity from an uploaded CSV file of DNS query logs. The user logs in, uploads a CSV, the system analyzes it, and shows results with graphs.

**Goal:** Keep it simple — no live packet capture, no complex infrastructure. Just: upload → analyze → visualize.

---

## 2. Core Features

### 2.1 Authentication
- Register page (name, email, password)
- Login page (email, password)
- JWT-based session (simple, no OAuth/social login)
- Logged-in users only can access the upload/analysis pages

### 2.2 CSV Upload & Analysis
- Simple file upload form (drag-and-drop or browse)
- Accepts a CSV of DNS query logs with columns like:
  - `timestamp`, `domain`, `query_type`, `query_length`, `subdomain_count`, `response_size` (exact schema finalized once a sample dataset is picked)
- Backend parses the CSV and runs detection logic:
  - **Rule-based heuristics** (primary, simple):
    - Domain/subdomain length thresholds
    - Character entropy of subdomains (high entropy → likely tunneling)
    - Query frequency per domain (unusually high = suspicious)
    - Unusual query types (e.g., excessive TXT/NULL records)
  - **Optional secondary check:** a lightweight ML anomaly model (Isolation Forest) trained on the same features, purely as a secondary flag — not required for v1 if time is short
- Output per row: `Normal` or `Suspicious`, plus a confidence/score

### 2.3 Results Dashboard
- Summary cards: total queries analyzed, number flagged suspicious, % suspicious
- Graphs (using Recharts):
  - Pie/donut chart: Normal vs Suspicious split
  - Bar chart: Top suspicious domains by query count
  - Line chart: Query volume over time (if timestamp available)
  - Histogram: entropy score distribution
- Table view of flagged rows with sortable/filterable columns
- Option to download results as CSV

---

## 3. Tech Stack (kept minimal)

| Layer | Tech |
|---|---|
| Frontend | React (Vite) + TailwindCSS + Recharts |
| Backend | FastAPI (Python) |
| Auth | JWT (simple email/password, hashed with bcrypt) |
| Database | MongoDB (stores users, uploaded file metadata, analysis results) |
| Detection logic | Python (pandas, numpy; scikit-learn optional for Isolation Forest) |
| Deployment | Docker Compose (single command to run frontend + backend + DB) |

---

## 4. Pages / Routes

| Page | Description |
|---|---|
| `/register` | Create account |
| `/login` | Log in |
| `/upload` | Upload CSV file |
| `/results/:id` | View analysis results + graphs for a specific upload |
| `/history` | List of past uploads (optional, nice-to-have) |

---

## 5. Non-Goals (explicitly out of scope for v1)
- No live network/packet capture
- No real-time monitoring
- No multi-user roles/permissions (just one role: logged-in user)
- No email verification / password reset flows
- No cloud deployment setup — local Docker Compose is enough

---

## 6. Success Criteria
- User can register, log in, and stay logged in via JWT
- User can upload a CSV and get a result within a few seconds for a reasonably sized file (up to ~50k rows)
- Results page clearly shows suspicious vs normal traffic with at least 3 graph types
- Whole system runs locally with `docker-compose up`
