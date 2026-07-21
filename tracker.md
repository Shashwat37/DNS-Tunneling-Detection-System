# DNS Tunneling Detection System — Build Tracker

Tracks progress against `project_requirement.md`. Check items off as you complete them. Keep milestones small — each one should be demoable on its own.

---

## Milestone 0 — Project Setup
- [ ] Init repo, folder structure (`/frontend`, `/backend`)
- [ ] `docker-compose.yml` skeleton (frontend, backend, MongoDB containers)
- [ ] Backend: FastAPI hello-world route running in Docker
- [ ] Frontend: Vite + React + TailwindCSS scaffold running in Docker
- [ ] Confirm frontend can hit backend `/health` endpoint

---

## Milestone 1 — Auth (Register/Login)
- [ ] MongoDB `users` collection schema (name, email, hashed password)
- [ ] Backend: `/register` endpoint (bcrypt hash password)
- [ ] Backend: `/login` endpoint (returns JWT)
- [ ] Backend: JWT middleware/dependency to protect routes
- [ ] Frontend: Register page + form validation
- [ ] Frontend: Login page + form validation
- [ ] Frontend: store JWT (context/local state), redirect to `/upload` on success
- [ ] Frontend: protected route wrapper (redirect to `/login` if not authed)

**Demo checkpoint:** can register, log in, and land on a protected upload page.

---

## Milestone 2 — CSV Upload & Storage
- [ ] Decide final CSV schema (columns + finalize sample dataset source)
- [ ] Frontend: upload form (file picker, basic validation for `.csv`)
- [ ] Backend: `/upload` endpoint — accept file, parse with pandas
- [ ] Backend: store upload metadata (filename, user_id, timestamp, row count) in MongoDB
- [ ] Backend: basic error handling (bad format, missing columns, empty file)

**Demo checkpoint:** logged-in user can upload a CSV and get a success response with row count.

---

## Milestone 3 — Detection Logic
- [ ] Feature extraction: domain length, subdomain count, subdomain entropy, query frequency per domain, query type distribution
- [ ] Rule-based heuristic scoring (thresholds for entropy/length/frequency)
- [ ] Label each row: `Normal` / `Suspicious` + score
- [ ] (Optional) Isolation Forest as secondary check, blended or shown separately
- [ ] Backend: store per-row results linked to the upload id
- [ ] Backend: `/results/:id` endpoint returning summary + row-level results

**Demo checkpoint:** uploading a CSV returns real Normal/Suspicious labels, not placeholders.

---

## Milestone 4 — Results Dashboard
- [ ] Frontend: `/results/:id` page skeleton
- [ ] Summary cards (total analyzed, suspicious count, % suspicious)
- [ ] Pie/donut chart — Normal vs Suspicious (Recharts)
- [ ] Bar chart — top suspicious domains
- [ ] Line chart — query volume over time
- [ ] Histogram — entropy distribution
- [ ] Sortable/filterable results table
- [ ] "Download results as CSV" button

**Demo checkpoint:** full flow works end-to-end — register → login → upload → see graphs and table.

---

## Milestone 5 — Polish (optional, nice-to-have)
- [ ] `/history` page — list of past uploads per user
- [ ] Basic loading/empty/error states across pages
- [ ] Responsive check (mobile/tablet)
- [ ] README with setup instructions (`docker-compose up` steps)

---

## Notes / Decisions Log
*(add dated notes here as you make calls during the build — e.g. dataset chosen, threshold values picked, scope cuts)*

-
