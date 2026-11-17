"""SmartRide - Student Shared Transport Booking System (Flask application layer)."""
import os
import re
import secrets
import time
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for, jsonify)
from werkzeug.security import check_password_hash, generate_password_hash

import db as database
import services as svc

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?\d[\d \-]{5,16}\d$")


def _persistent_secret(instance_path):
    """Use SECRET_KEY from the environment, else a random key stored once in instance/secret_key."""
    os.makedirs(instance_path, exist_ok=True)
    path = os.path.join(instance_path, "secret_key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as f:
        f.write(key)
    return key


def create_app(config=None):
    app = Flask(__name__)
    failed_logins = {}  # email -> list of timestamps (simple brute-force throttle)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or _persistent_secret(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "smartride.db"),
        CANCEL_CUTOFF_MINUTES=60,
        CSRF_ENABLED=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if config:
        app.config.update(config)
    os.makedirs(app.instance_path, exist_ok=True)
    database.init_app(app)

    # ---------------- request hooks ----------------
    @app.before_request
    def load_user():
        uid = session.get("user_id")
        g.user = None
        if uid:
            g.user = database.get_db().execute(
                "SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
            if g.user is None:
                session.clear()

    @app.before_request
    def auto_complete_trips():
        if request.endpoint != "static":
            svc.complete_past_trips(database.get_db())

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.before_request
    def csrf_protect():
        if not app.config["CSRF_ENABLED"] or request.method != "POST":
            return
        token = session.get("_csrf")
        sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, sent):
            abort(400, "Invalid or missing CSRF token.")

    @app.context_processor
    def inject():
        def csrf_token():
            if "_csrf" not in session:
                session["_csrf"] = secrets.token_hex(16)
            return session["_csrf"]
        unread = 0
        if g.get("user"):
            unread = database.get_db().execute(
                "SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                (g.user["id"],)).fetchone()[0]
        return {"csrf_token": csrf_token, "unread": unread, "cities": svc.CITIES}

    @app.template_filter("dt")
    def fmt_dt(s):
        return s.replace("T", " ") if s else ""

    @app.template_filter("departs_in")
    def departs_in(s):
        try:
            mins = int((svc.parse_dt(s) - datetime.now()).total_seconds() // 60)
        except (TypeError, ValueError):
            return ""
        if mins < 0:
            return "Departed"
        if mins < 60:
            return f"Departs in {mins} min"
        if mins < 24 * 60:
            return f"Departs in {mins // 60} h {mins % 60} min"
        days = mins // (24 * 60)
        return f"Departs in {days} day{'s' if days != 1 else ''}"

    def login_required(*roles):
        def deco(f):
            @wraps(f)
            def wrapper(*a, **k):
                if g.user is None:
                    return redirect(url_for("login", next=request.path))
                if roles and g.user["role"] not in roles:
                    abort(403)
                return f(*a, **k)
            return wrapper
        return deco

    def db():
        return database.get_db()

    # ---------------- authentication (FR-01) ----------------
    @app.route("/")
    def index():
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            f = request.form
            name, email = f.get("name", "").strip(), f.get("email", "").strip().lower()
            phone, role = f.get("phone", "").strip(), f.get("role", "student")
            pw = f.get("password", "")
            error = None
            if role not in ("student", "driver"):
                error = "Choose student or driver."
            elif not name or not phone:
                error = "Name and phone are required."
            elif not EMAIL_RE.match(email):
                error = "Enter a valid email address."
            elif len(pw) < 6:
                error = "Password must be at least 6 characters."
            elif db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                error = "That email is already registered."
            if error:
                flash(error, "error")
            else:
                db().execute(
                    "INSERT INTO users (name,email,phone,password_hash,role,verified,created_at) VALUES (?,?,?,?,?,?,?)",
                    (name, email, phone, generate_password_hash(pw), role,
                     1 if role == "student" else 0, svc.now_str()))
                if role == "driver":
                    flash("Registered. An administrator must verify your driver record before you can publish trips.", "info")
                else:
                    flash("Registered. Please log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            now = time.time()
            recent = [t for t in failed_logins.get(email, []) if now - t < 300]
            if len(recent) >= 5:
                flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
                return render_template("login.html")
            user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user and user["active"] and check_password_hash(user["password_hash"], request.form.get("password", "")):
                failed_logins.pop(email, None)
                session.clear()
                session["user_id"] = user["id"]
                nxt = request.args.get("next", "")
                if nxt.startswith("/") and not nxt.startswith("//"):
                    return redirect(nxt)
                home = {"driver": "driver_home", "admin": "admin_home"}.get(user["role"], "search")
                return redirect(url_for(home))
            recent.append(now)
            failed_logins[email] = recent
            flash("Invalid email or password.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------------- search & booking (FR-03, FR-04, FR-07) ----------------
    @app.route("/trips")
    def search():
        q = {k: request.args.get(k, "").strip() for k in ("origin", "destination", "date", "time", "sort")}
        trips = svc.search_trips(db(), **q)
        return render_template("search.html", trips=trips, q=q)

    @app.route("/trips/<int:trip_id>")
    def trip_detail(trip_id):
        trip = svc.get_trip(db(), trip_id)
        if trip is None:
            abort(404)
        allowed = svc.can_track(db(), g.user, trip) if g.user else False
        return render_template("trip_detail.html", t=trip, can_track=allowed)

    @app.route("/trips/<int:trip_id>/book", methods=["POST"])
    @login_required("student")
    def book(trip_id):
        try:
            svc.request_booking(db(), g.user["id"], trip_id, request.form.get("seats"))
            flash("Seat request sent. You'll be notified when the driver responds.", "success")
            return redirect(url_for("my_bookings"))
        except svc.BookingError as e:
            flash(str(e), "error")
            return redirect(url_for("trip_detail", trip_id=trip_id))

    @app.route("/my-bookings")
    @login_required("student")
    def my_bookings():
        rows = db().execute(
            "SELECT b.*, t.origin, t.destination, t.depart_at, t.status AS trip_status, "
            "u.name AS driver_name, u.phone AS driver_phone, v.plate_no, r.stars AS my_stars, "
            "EXISTS (SELECT 1 FROM trip_locations l WHERE l.trip_id=t.id) AS live "
            "FROM bookings b JOIN trips t ON t.id=b.trip_id JOIN vehicles v ON v.id=t.vehicle_id "
            "LEFT JOIN ratings r ON r.booking_id=b.id "
            "JOIN users u ON u.id=v.driver_id WHERE b.student_id=? ORDER BY b.created_at DESC",
            (g.user["id"],)).fetchall()
        return render_template("my_bookings.html", bookings=rows)

    @app.route("/bookings/<int:booking_id>/cancel", methods=["POST"])
    @login_required("student")
    def cancel_booking(booking_id):
        try:
            svc.cancel_booking(db(), g.user["id"], booking_id, app.config["CANCEL_CUTOFF_MINUTES"])
            flash("Booking cancelled.", "success")
        except svc.BookingError as e:
            flash(str(e), "error")
        except PermissionError:
            abort(403)
        return redirect(url_for("my_bookings"))

    @app.route("/bookings/<int:booking_id>/rate", methods=["POST"])
    @login_required("student")
    def rate(booking_id):
        try:
            svc.rate_driver(db(), g.user["id"], booking_id, request.form.get("stars"), request.form.get("comment", ""))
            flash("Thanks for your feedback!", "success")
        except svc.BookingError as e:
            flash(str(e), "error")
        except PermissionError:
            abort(403)
        return redirect(url_for("my_bookings"))

    # ---------------- driver (FR-02, FR-05) ----------------
    def require_verified():
        if not g.user["verified"]:
            flash("Your driver record is awaiting administrator verification.", "error")
            return False
        return True

    @app.route("/driver")
    @login_required("driver")
    def driver_home():
        vehicles = db().execute("SELECT * FROM vehicles WHERE driver_id=?", (g.user["id"],)).fetchall()
        trips = db().execute(svc.TRIP_SQL + " WHERE v.driver_id=? ORDER BY t.depart_at DESC", (g.user["id"],)).fetchall()
        pending = db().execute(
            "SELECT b.*, u.name AS student_name, u.phone AS student_phone, t.origin, t.destination, t.depart_at, "
            "t.seats_total - COALESCE((SELECT SUM(x.seats) FROM bookings x WHERE x.trip_id=t.id AND x.status='Confirmed'),0) AS seats_left "
            "FROM bookings b JOIN trips t ON t.id=b.trip_id JOIN vehicles v ON v.id=t.vehicle_id "
            "JOIN users u ON u.id=b.student_id WHERE v.driver_id=? AND b.status='Pending' ORDER BY t.depart_at",
            (g.user["id"],)).fetchall()
        rating = db().execute("SELECT ROUND(AVG(stars), 1) AS avg, COUNT(*) AS n FROM ratings WHERE driver_id=?",
                              (g.user["id"],)).fetchone()
        reviews = db().execute(
            "SELECT r.stars, r.comment, r.created_at, u.name FROM ratings r JOIN users u ON u.id=r.student_id "
            "WHERE r.driver_id=? ORDER BY r.id DESC LIMIT 5", (g.user["id"],)).fetchall()
        return render_template("driver_home.html", vehicles=vehicles, trips=trips, pending=pending,
                               rating=rating, reviews=reviews, now=datetime.now().strftime(svc.FMT))

    @app.route("/driver/vehicles/new", methods=["GET", "POST"])
    @login_required("driver")
    def new_vehicle():
        if request.method == "POST":
            plate = request.form.get("plate_no", "").strip().upper()
            try:
                cap = int(request.form.get("capacity", ""))
            except ValueError:
                cap = 0
            if not plate or not 1 <= cap <= 20:
                flash("Enter a plate number and a capacity between 1 and 20.", "error")
            elif db().execute("SELECT 1 FROM vehicles WHERE plate_no=?", (plate,)).fetchone():
                flash("That plate number is already registered.", "error")
            else:
                db().execute("INSERT INTO vehicles (driver_id, plate_no, capacity) VALUES (?,?,?)",
                             (g.user["id"], plate, cap))
                flash("Vehicle added.", "success")
                return redirect(url_for("driver_home"))
        return render_template("vehicle_form.html")

    def validate_trip_form(f, capacity):
        """Return ((origin, dest, pickup, when, seats), None) or (None, error message)."""
        origin, dest = f.get("origin", "").strip(), f.get("destination", "").strip()
        when = f.get("depart_at", "")
        try:
            seats = int(f.get("seats_total", ""))
            dep = svc.parse_dt(when)
        except ValueError:
            return None, "Enter valid seats and departure time."
        if origin not in svc.CITIES or dest not in svc.CITIES:
            return None, "Choose origin and destination from the city list."
        if origin == dest:
            return None, "Origin and destination must be different."
        if dep <= datetime.now():
            return None, "Departure must be in the future."
        if not 1 <= seats <= capacity:
            return None, f"Seats must be between 1 and the vehicle capacity ({capacity})."
        return (origin, dest, f.get("pickup_points", "").strip(), when, seats), None

    @app.route("/driver/trips/new", methods=["GET", "POST"])
    @login_required("driver")
    def new_trip():
        vehicles = db().execute("SELECT * FROM vehicles WHERE driver_id=?", (g.user["id"],)).fetchall()
        if not require_verified():
            return redirect(url_for("driver_home"))
        if not vehicles:
            flash("Add a vehicle first.", "error")
            return redirect(url_for("new_vehicle"))
        f = request.form
        if request.method == "POST":
            veh = db().execute("SELECT * FROM vehicles WHERE id=? AND driver_id=?",
                               (f.get("vehicle_id", 0), g.user["id"])).fetchone()
            if veh is None:
                flash("Choose one of your vehicles.", "error")
            else:
                values, error = validate_trip_form(f, veh["capacity"])
                if error:
                    flash(error, "error")
                else:
                    origin, dest, pickup, when, seats = values
                    db().execute(
                        "INSERT INTO trips (vehicle_id, origin, destination, pickup_points, depart_at, seats_total, created_at) "
                        "VALUES (?,?,?,?,?,?,?)", (veh["id"], origin, dest, pickup, when, seats, svc.now_str()))
                    flash("Trip published.", "success")
                    return redirect(url_for("driver_home"))
        return render_template("trip_form.html", vehicles=vehicles, f=f, editing=False)

    @app.route("/driver/trips/<int:trip_id>/edit", methods=["GET", "POST"])
    @login_required("driver")
    def edit_trip(trip_id):
        trip = svc.get_trip(db(), trip_id)
        if trip is None:
            abort(404)
        if trip["driver_id"] != g.user["id"]:
            abort(403)
        if trip["status"] != "Scheduled":
            flash("Only scheduled trips can be edited.", "error")
            return redirect(url_for("driver_home"))
        f = request.form if request.method == "POST" else trip
        if request.method == "POST":
            values, error = validate_trip_form(f, trip["capacity"])
            if error:
                flash(error, "error")
            else:
                try:
                    n = svc.update_trip(db(), g.user["id"], trip_id, *values)
                    flash(f"Trip updated; {n} student(s) notified.", "success")
                    return redirect(url_for("driver_home"))
                except svc.BookingError as e:
                    flash(str(e), "error")
                except PermissionError:
                    abort(403)
        return render_template("trip_form.html", f=f, editing=True, trip=trip)

    @app.route("/driver/trips/<int:trip_id>/cancel", methods=["POST"])
    @login_required("driver")
    def driver_cancel_trip(trip_id):
        try:
            n = svc.cancel_trip(db(), g.user["id"], trip_id)
            flash(f"Trip cancelled; {n} booking(s) cancelled and students notified.", "success")
        except svc.BookingError as e:
            flash(str(e), "error")
        except PermissionError:
            abort(403)
        return redirect(url_for("driver_home"))

    @app.route("/driver/bookings/<int:booking_id>/<action>", methods=["POST"])
    @login_required("driver")
    def driver_respond(booking_id, action):
        if action not in ("accept", "reject"):
            abort(404)
        try:
            status = svc.respond_booking(db(), g.user["id"], booking_id, action == "accept")
            flash(f"Request {status.lower()}.", "success")
        except svc.BookingError as e:
            flash(str(e), "error")
        except PermissionError:
            abort(403)
        return redirect(url_for("driver_home"))

    # ---------------- account ----------------
    @app.route("/account/password", methods=["GET", "POST"])
    @login_required()
    def change_password():
        if request.method == "POST":
            f = request.form
            current, new, confirm = f.get("current", ""), f.get("new", ""), f.get("confirm", "")
            if not check_password_hash(g.user["password_hash"], current):
                flash("Current password is incorrect.", "error")
            elif len(new) < 6:
                flash("New password must be at least 6 characters.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            elif new == current:
                flash("Choose a password different from the current one.", "error")
            else:
                db().execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(new), g.user["id"]))
                flash("Password changed.", "success")
                return redirect(url_for("index"))
        return render_template("change_password.html")

    # ---------------- profile (students, drivers, admins) ----------------
    def validate_profile(f, user_id):
        name = f.get("name", "").strip()
        phone = f.get("phone", "").strip()
        email = f.get("email", "").strip().lower()
        city = f.get("city", "").strip()
        institution = f.get("institution", "").strip()
        if not name or len(name) > 60:
            return None, "Enter a name (up to 60 characters)."
        if not PHONE_RE.match(phone):
            return None, "Enter a valid phone number (digits, spaces, dashes; optional leading +)."
        if not EMAIL_RE.match(email):
            return None, "Enter a valid email address."
        if db().execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, user_id)).fetchone():
            return None, "That email is already used by another account."
        if city and city not in svc.CITIES:
            return None, "Choose a city from the list."
        if len(institution) > 80:
            return None, "College / institute name is too long."
        return (name, phone, email, city, institution), None

    @app.route("/account/profile", methods=["GET", "POST"])
    @login_required()
    def profile():
        f = request.form if request.method == "POST" else g.user
        if request.method == "POST":
            values, error = validate_profile(f, g.user["id"])
            if error:
                flash(error, "error")
            else:
                db().execute("UPDATE users SET name=?, phone=?, email=?, city=?, institution=? WHERE id=?",
                             (*values, g.user["id"]))
                flash("Profile updated.", "success")
                return redirect(url_for("profile"))
        return render_template("profile.html", f=f)

    @app.route("/about")
    def about():
        return render_template("about.html")

    # ---------------- live tracking ----------------
    @app.route("/trips/<int:trip_id>/track")
    @login_required()
    def track_trip(trip_id):
        trip = svc.get_trip(db(), trip_id)
        if trip is None:
            abort(404)
        if not svc.can_track(db(), g.user, trip):
            abort(403)
        return render_template("track.html", t=trip, is_driver=trip["driver_id"] == g.user["id"],
                               origin_xy=svc.CITY_COORDS.get(trip["origin"]),
                               dest_xy=svc.CITY_COORDS.get(trip["destination"]))

    @app.route("/api/trips/<int:trip_id>/location", methods=["GET"])
    @login_required()
    def api_get_location(trip_id):
        trip = svc.get_trip(db(), trip_id)
        if trip is None or not svc.can_track(db(), g.user, trip):
            return jsonify(error="Not allowed."), 403
        loc = svc.get_location(db(), trip_id)
        return jsonify(sharing=loc is not None, status=trip["status"], **(loc or {}))

    @app.route("/api/trips/<int:trip_id>/location", methods=["POST"])
    @login_required("driver")
    def api_set_location(trip_id):
        data = request.get_json(silent=True) or {}
        try:
            first = svc.set_location(db(), g.user["id"], trip_id, data.get("lat"), data.get("lng"), data.get("accuracy"))
        except svc.BookingError as e:
            return jsonify(error=str(e)), 400
        except PermissionError:
            return jsonify(error="Not your trip."), 403
        return jsonify(ok=True, first=first)

    @app.route("/api/trips/<int:trip_id>/location/stop", methods=["POST"])
    @login_required("driver")
    def api_stop_location(trip_id):
        try:
            svc.stop_location(db(), g.user["id"], trip_id)
        except svc.BookingError as e:
            return jsonify(error=str(e)), 400
        except PermissionError:
            return jsonify(error="Not your trip."), 403
        return jsonify(ok=True)

    @app.route("/driver/trips/<int:trip_id>/finish", methods=["POST"])
    @login_required("driver")
    def driver_finish_trip(trip_id):
        try:
            n = svc.complete_trip(db(), g.user["id"], trip_id)
            flash(f"Trip marked as completed; {n} passenger(s) can now rate you.", "success")
        except svc.BookingError as e:
            flash(str(e), "error")
        except PermissionError:
            abort(403)
        return redirect(url_for("driver_home"))

    # ---------------- notifications (FR-08) ----------------
    @app.route("/notifications", methods=["GET", "POST"])
    @login_required()
    def notifications():
        if request.method == "POST":
            db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (g.user["id"],))
            return redirect(url_for("notifications"))
        rows = db().execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",
                            (g.user["id"],)).fetchall()
        return render_template("notifications.html", notes=rows)

    # ---------------- administration (FR-09) ----------------
    @app.route("/admin")
    @login_required("admin")
    def admin_home():
        users = db().execute("SELECT * FROM users ORDER BY role, name").fetchall()
        stats = {
            "users": db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "trips": db().execute("SELECT COUNT(*) FROM trips").fetchone()[0],
            "bookings": db().execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
            "confirmed": db().execute("SELECT COUNT(*) FROM bookings WHERE status='Confirmed'").fetchone()[0],
        }
        recent = db().execute(
            "SELECT b.id, b.seats, b.status, b.created_at, s.name AS student, t.origin, t.destination, t.depart_at "
            "FROM bookings b JOIN users s ON s.id=b.student_id JOIN trips t ON t.id=b.trip_id "
            "ORDER BY b.id DESC LIMIT 15").fetchall()
        return render_template("admin.html", users=users, stats=stats, recent=recent)

    @app.route("/admin/users/<int:user_id>/<action>", methods=["POST"])
    @login_required("admin")
    def admin_user_action(user_id, action):
        user = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        if action == "verify" and user["role"] == "driver":
            db().execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
            svc.notify(db(), user_id, "Your driver record has been verified. You can now publish trips.")
            flash("Driver verified.", "success")
        elif action == "toggle" and user["id"] != g.user["id"]:
            db().execute("UPDATE users SET active = 1 - active WHERE id=?", (user_id,))
            flash("Account status changed.", "success")
        else:
            abort(400)
        return redirect(url_for("admin_home"))

    @app.route("/admin/user/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required("admin")
    def admin_edit_user(user_id):
        user = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        f = request.form if request.method == "POST" else user
        if request.method == "POST":
            values, error = validate_profile(f, user_id)
            if error:
                flash(error, "error")
            else:
                db().execute("UPDATE users SET name=?, phone=?, email=?, city=?, institution=? WHERE id=?",
                             (*values, user_id))
                flash("User details updated.", "success")
                return redirect(url_for("admin_home"))
        return render_template("admin_user_edit.html", f=f, u=user)

    @app.route("/admin/export.csv")
    @login_required("admin")
    def admin_export_csv():
        import csv
        import io
        from flask import Response
        rows = db().execute(
            "SELECT b.id, s.name AS student, t.origin, t.destination, t.depart_at, "
            "b.seats, b.status, b.created_at "
            "FROM bookings b JOIN users s ON s.id=b.student_id JOIN trips t ON t.id=b.trip_id "
            "ORDER BY b.id").fetchall()
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["Booking", "Student", "From", "To", "Departure", "Seats", "Status", "Created"])
        for r in rows:
            w.writerow([r["id"], r["student"], r["origin"], r["destination"], r["depart_at"],
                        r["seats"], r["status"], r["created_at"]])
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=smartride_bookings.csv"})

    @app.route("/account/name", methods=["GET", "POST"])
    @login_required()
    def change_name():
        if request.method == "POST":
            new_name = request.form.get("name", "").strip()
            if not new_name or len(new_name) > 60:
                flash("Enter a name (up to 60 characters).", "error")
            else:
                db().execute("UPDATE users SET name=? WHERE id=?", (new_name, g.user["id"]))
                flash("Name updated.", "success")
                return redirect(url_for("change_name"))
        return render_template("change_name.html")

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, msg="You do not have access to this page."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, msg="Page not found."), 404

    @app.errorhandler(405)
    def not_allowed(_e):
        return render_template("error.html", code=405, msg="That action is not allowed here."), 405

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, msg="Something went wrong on our side. Please try again."), 500

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request.")), 400

    return app


if __name__ == "__main__":
    create_app().run(debug=os.environ.get("FLASK_DEBUG") == "1")