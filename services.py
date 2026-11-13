"""Business rules: seat control, booking workflow, cancellation, notifications.

Every state-changing operation runs inside BEGIN IMMEDIATE so that two
simultaneous requests cannot both reserve the last seat (SRS 2.12, TC-04).
"""
from contextlib import contextmanager
from datetime import datetime, timedelta

FMT = "%Y-%m-%dT%H:%M"
ACTIVE = ("Pending", "Confirmed")
CITIES = ["Srinagar", "Baramulla", "Kupwara"]


class BookingError(Exception):
    """A business-rule violation that is safe to show to the user."""


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(s):
    return datetime.strptime(s, FMT)


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


# ---------- queries ----------
TRIP_SQL = """
SELECT t.*, v.plate_no, v.capacity, v.driver_id, u.name AS driver_name, u.phone AS driver_phone,
       t.seats_total - COALESCE((SELECT SUM(b.seats) FROM bookings b
                                 WHERE b.trip_id = t.id AND b.status = 'Confirmed'), 0) AS seats_left,
       (SELECT ROUND(AVG(r.stars), 1) FROM ratings r WHERE r.driver_id = v.driver_id) AS avg_rating,
       (SELECT COUNT(*) FROM ratings r WHERE r.driver_id = v.driver_id) AS rating_count
FROM trips t
JOIN vehicles v ON v.id = t.vehicle_id
JOIN users u ON u.id = v.driver_id
"""


def get_trip(db, trip_id):
    return db.execute(TRIP_SQL + " WHERE t.id = ?", (trip_id,)).fetchone()


def seats_left(db, trip_id):
    row = get_trip(db, trip_id)
    return row["seats_left"] if row else 0


def search_trips(db, origin="", destination="", date="", time=""):
    sql = TRIP_SQL + " WHERE t.status = 'Scheduled' AND t.depart_at >= ?"
    args = [datetime.now().strftime(FMT)]
    if origin:
        sql += " AND (t.origin LIKE ? OR t.pickup_points LIKE ?)"
        args += [f"%{origin}%", f"%{origin}%"]
    if destination:
        sql += " AND t.destination LIKE ?"
        args.append(f"%{destination}%")
    if date:
        sql += " AND substr(t.depart_at, 1, 10) = ?"
        args.append(date)
    if time:
        sql += " AND substr(t.depart_at, 12, 5) >= ?"
        args.append(time)
    sql += " ORDER BY t.depart_at"
    return db.execute(sql, args).fetchall()


def notify(db, user_id, message):
    db.execute("INSERT INTO notifications (user_id, message, created_at) VALUES (?,?,?)",
               (user_id, message, now_str()))


def trip_label(t):
    return f"{t['origin']} -> {t['destination']} at {t['depart_at'].replace('T', ' ')}"


# ---------- booking workflow ----------
def request_booking(db, student_id, trip_id, seats):
    """FR-04: student requests seats. Saved as Pending (SRS 5.5 step 4)."""
    try:
        seats = int(seats)
    except (TypeError, ValueError):
        raise BookingError("Seats must be a whole number.")
    if seats < 1:
        raise BookingError("Request at least one seat.")
    with transaction(db):
        trip = get_trip(db, trip_id)
        if trip is None:
            raise BookingError("Trip not found.")
        if trip["status"] != "Scheduled":
            raise BookingError("This trip is no longer available.")
        if trip["depart_at"] <= datetime.now().strftime(FMT):
            raise BookingError("This trip has already departed.")
        if trip["driver_id"] == student_id:
            raise BookingError("You cannot book your own trip.")
        dup = db.execute("SELECT 1 FROM bookings WHERE student_id=? AND trip_id=? AND status IN ('Pending','Confirmed')",
                         (student_id, trip_id)).fetchone()
        if dup:
            raise BookingError("You already have an active booking for this trip.")
        if seats > trip["seats_left"]:
            raise BookingError(f"Only {trip['seats_left']} seat(s) left on this trip.")
        ts = now_str()
        cur = db.execute("INSERT INTO bookings (student_id, trip_id, seats, status, created_at, updated_at) "
                         "VALUES (?,?,?,'Pending',?,?)", (student_id, trip_id, seats, ts, ts))
        student = db.execute("SELECT name FROM users WHERE id=?", (student_id,)).fetchone()
        notify(db, trip["driver_id"], f"New request: {student['name']} wants {seats} seat(s) on {trip_label(trip)}.")
        return cur.lastrowid


def respond_booking(db, driver_id, booking_id, accept):
    """FR-05 / FR-06: driver accepts or rejects. Capacity is re-checked on accept."""
    with transaction(db):
        b = db.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
        if b is None:
            raise BookingError("Booking not found.")
        trip = get_trip(db, b["trip_id"])
        if trip["driver_id"] != driver_id:
            raise PermissionError("Not your trip.")
        if b["status"] != "Pending":
            raise BookingError(f"This request is already {b['status']}.")
        if accept:
            if trip["status"] != "Scheduled":
                raise BookingError("Trip is not active.")
            if b["seats"] > trip["seats_left"]:
                raise BookingError(f"Cannot accept: only {trip['seats_left']} seat(s) left. Reject or ask the student to rebook.")
            new_status, text = "Confirmed", "confirmed"
        else:
            new_status, text = "Rejected", "rejected"
        db.execute("UPDATE bookings SET status=?, updated_at=? WHERE id=?", (new_status, now_str(), booking_id))
        notify(db, b["student_id"], f"Your booking for {trip_label(trip)} was {text} by the driver.")
        return new_status


def cancel_booking(db, user_id, booking_id, cutoff_minutes=60):
    """FR-07: student cancels a Pending/Confirmed booking before the cut-off."""
    with transaction(db):
        b = db.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
        if b is None:
            raise BookingError("Booking not found.")
        if b["student_id"] != user_id:
            raise PermissionError("Not your booking.")
        if b["status"] not in ACTIVE:
            raise BookingError(f"A {b['status']} booking cannot be cancelled.")
        trip = get_trip(db, b["trip_id"])
        if parse_dt(trip["depart_at"]) - datetime.now() < timedelta(minutes=cutoff_minutes):
            raise BookingError(f"Bookings cannot be cancelled within {cutoff_minutes} minutes of departure.")
        db.execute("UPDATE bookings SET status='Cancelled', updated_at=? WHERE id=?", (now_str(), booking_id))
        notify(db, trip["driver_id"], f"A booking for {trip_label(trip)} was cancelled by the student; seats released.")


def cancel_trip(db, driver_id, trip_id):
    """Trip change: all active bookings are cancelled and students are notified (FR-08)."""
    with transaction(db):
        trip = get_trip(db, trip_id)
        if trip is None:
            raise BookingError("Trip not found.")
        if trip["driver_id"] != driver_id:
            raise PermissionError("Not your trip.")
        if trip["status"] != "Scheduled":
            raise BookingError("Trip is not active.")
        db.execute("UPDATE trips SET status='Cancelled' WHERE id=?", (trip_id,))
        affected = db.execute("SELECT * FROM bookings WHERE trip_id=? AND status IN ('Pending','Confirmed')",
                              (trip_id,)).fetchall()
        for b in affected:
            db.execute("UPDATE bookings SET status='Cancelled', updated_at=? WHERE id=?", (now_str(), b["id"]))
            notify(db, b["student_id"], f"Trip cancelled by driver: {trip_label(trip)}.")
        return len(affected)


def complete_past_trips(db):
    """Trips whose departure time has passed become 'Completed'; unanswered requests are closed."""
    cutoff = datetime.now().strftime(FMT)
    if not db.execute("SELECT 1 FROM trips WHERE status='Scheduled' AND depart_at <= ? LIMIT 1", (cutoff,)).fetchone():
        return 0
    with transaction(db):
        ids = [r["id"] for r in db.execute(
            "SELECT id FROM trips WHERE status='Scheduled' AND depart_at <= ?", (cutoff,)).fetchall()]
        for tid in ids:
            db.execute("UPDATE trips SET status='Completed' WHERE id=?", (tid,))
            pending = db.execute("SELECT id, student_id FROM bookings WHERE trip_id=? AND status='Pending'",
                                 (tid,)).fetchall()
            for b in pending:
                db.execute("UPDATE bookings SET status='Rejected', updated_at=? WHERE id=?", (now_str(), b["id"]))
                notify(db, b["student_id"], "Your seat request expired because the trip departed without a driver response.")
    return len(ids)


def update_trip(db, driver_id, trip_id, origin, destination, pickup_points, depart_at, seats_total):
    """Driver edits a scheduled trip. Students with active bookings are notified of changes."""
    with transaction(db):
        trip = get_trip(db, trip_id)
        if trip is None:
            raise BookingError("Trip not found.")
        if trip["driver_id"] != driver_id:
            raise PermissionError("Not your trip.")
        if trip["status"] != "Scheduled":
            raise BookingError("Only scheduled trips can be edited.")
        confirmed = trip["seats_total"] - trip["seats_left"]
        if seats_total < confirmed:
            raise BookingError(f"{confirmed} seat(s) are already confirmed, so you cannot offer fewer.")
        if seats_total > trip["capacity"]:
            raise BookingError(f"Seats cannot exceed the vehicle capacity ({trip['capacity']}).")
        changed = (origin, destination, pickup_points, depart_at) != (
            trip["origin"], trip["destination"], trip["pickup_points"], trip["depart_at"])
        db.execute("UPDATE trips SET origin=?, destination=?, pickup_points=?, depart_at=?, seats_total=? WHERE id=?",
                   (origin, destination, pickup_points, depart_at, seats_total, trip_id))
        notified = 0
        if changed:
            new_label = trip_label({"origin": origin, "destination": destination, "depart_at": depart_at})
            affected = db.execute("SELECT student_id FROM bookings WHERE trip_id=? AND status IN ('Pending','Confirmed')",
                                  (trip_id,)).fetchall()
            for b in affected:
                notify(db, b["student_id"], f"Trip changed by driver: was {trip_label(trip)}, now {new_label}. "
                                            "Cancel your booking if this no longer suits you.")
            notified = len(affected)
        return notified


def rate_driver(db, student_id, booking_id, stars, comment=""):
    """Student rates the driver (1-5 stars) after a confirmed trip is completed. One rating per booking."""
    try:
        stars = int(stars)
    except (TypeError, ValueError):
        raise BookingError("Choose a rating from 1 to 5.")
    if not 1 <= stars <= 5:
        raise BookingError("Choose a rating from 1 to 5.")
    comment = (comment or "").strip()[:300]
    with transaction(db):
        b = db.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
        if b is None:
            raise BookingError("Booking not found.")
        if b["student_id"] != student_id:
            raise PermissionError("Not your booking.")
        trip = get_trip(db, b["trip_id"])
        if b["status"] != "Confirmed" or trip["status"] != "Completed":
            raise BookingError("You can rate a driver only after a confirmed trip has been completed.")
        if db.execute("SELECT 1 FROM ratings WHERE booking_id=?", (booking_id,)).fetchone():
            raise BookingError("You already rated this trip.")
        db.execute("INSERT INTO ratings (booking_id, student_id, driver_id, stars, comment, created_at) "
                   "VALUES (?,?,?,?,?,?)", (booking_id, student_id, trip["driver_id"], stars, comment, now_str()))
        notify(db, trip["driver_id"], f"You received a {stars}-star rating for {trip_label(trip)}.")
