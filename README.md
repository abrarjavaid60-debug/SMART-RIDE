# SmartRide - Student Shared Transport Booking System (Python)

Python implementation of the SmartRide SRS: students search shared trips and request seats, drivers accept or reject,
admins verify drivers. Stack: **Flask + SQLite + Jinja templates** (replaces React/Node/MongoDB from the proposal).

## Run
```bash
pip install -r requirements.txt
python seed.py --reset  # demo data (--reset wipes the old database first)
python app.py           # http://127.0.0.1:5000
python -m unittest discover -s tests -v   # automated tests TC-01..TC-07
```
Demo logins (password `password123`): `admin@smartride.test`, `driver1@smartride.test`, `driver2@smartride.test`,
`student1@smartride.test`, `student2@smartride.test`. Set `SECRET_KEY` in the environment for any real use.

## Cities
Trips run between **Srinagar, Baramulla and Kupwara** (list in `services.CITIES`; drivers choose from it,
pickup points such as Lal Chowk or Sopore are free text).

## Extra features
| Feature | Where |
|---|---|
| Home page with route search and popular routes | `/` |
| Trips become **Completed** automatically after departure; unanswered requests are closed | `services.complete_past_trips` |
| Driver can **edit** a scheduled trip; booked students are notified | `/driver/trips/<id>/edit`, `services.update_trip` |
| Students **rate drivers** (1-5 stars + comment) after a completed trip; average shown on trips | `services.rate_driver`, `/my-bookings` |
| **Change password** | `/account/password` |
| Friendlier error pages (400/403/404/405/500) | `templates/error.html` |

## Security notes
- Passwords are hashed (Werkzeug); CSRF token on every POST; role-based access on every protected route.
- `SECRET_KEY` comes from the environment, otherwise a random key is generated once into `instance/secret_key`.
- Login throttle: 5 failed attempts per email blocks further tries for 5 minutes.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- Seat booking uses `BEGIN IMMEDIATE` transactions, so two requests cannot take the last seat.

## Put it on GitHub
```bash
git init
git add .
git commit -m "SmartRide: Flask + SQLite student shared transport booking"
git branch -M main
git remote add origin https://github.com/<your-username>/smartride.git
git push -u origin main
```
`.gitignore` already excludes the database, secret key and `__pycache__`.

## Architecture (matches Figure 4)
| Layer | Files |
|---|---|
| Presentation | `templates/`, `static/style.css` (responsive, mobile-first) |
| Application | `app.py` (routes, auth, roles, CSRF), `services.py` (business rules) |
| Data | `schema.sql`, `db.py` (SQLite; tables = ERD entities + notifications) |

## Requirement traceability
| SRS | Where |
|---|---|
| FR-01 register/login | `/register`, `/login` (hashed passwords, roles) |
| FR-02 create trip | `/driver/trips/new` (verified drivers only) |
| FR-03 search | `/trips` (origin/pickup, destination, date, time) |
| FR-04 request seats | `services.request_booking` -> status Pending |
| FR-05 accept/reject | `services.respond_booking` |
| FR-06 seat control | seats left = offered − confirmed; checked on request and re-checked on accept inside `BEGIN IMMEDIATE` |
| FR-07 status/cancel | `/my-bookings`, `services.cancel_booking` (60-min cut-off, configurable) |
| FR-08 notifications | `notifications` table, 🔔 badge, `/notifications` |
| FR-09 administration | `/admin` (verify drivers, block users, booking activity) |

Business rules enforced: no overbooking, no duplicate active booking per student/trip, statuses
Pending/Confirmed/Rejected/Cancelled, cancelling a trip cancels its bookings and notifies students.

## Out of scope (as in the proposal)
Live GPS, payments, traffic prediction, arrival-time guarantees.
