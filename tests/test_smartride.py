"""Automated versions of the planned test cases TC-01 .. TC-07 from the assignment."""
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import db as database  # noqa: E402
import services as svc  # noqa: E402
from app import create_app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.app = create_app({"DATABASE": self.path, "TESTING": True, "CSRF_ENABLED": False})
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db = database.get_db()
        self.admin = self.mk("Admin", "a@t.io", "admin")
        self.driver = self.mk("Driver", "d@t.io", "driver")
        self.driver2 = self.mk("Driver Two", "d2@t.io", "driver")
        self.s1 = self.mk("Stu One", "s1@t.io", "student")
        self.s2 = self.mk("Stu Two", "s2@t.io", "student")
        self.vehicle = self.db.execute("INSERT INTO vehicles (driver_id,plate_no,capacity) VALUES (?,?,?)",
                                       (self.driver, "PLATE1", 4)).lastrowid
        self.trip = self.mk_trip(seats=2)

    def tearDown(self):
        database.close_db()
        self.ctx.pop()
        os.unlink(self.path)

    def mk(self, name, email, role):
        return self.db.execute(
            "INSERT INTO users (name,email,phone,password_hash,role,verified,created_at) VALUES (?,?,?,?,?,1,?)",
            (name, email, "1", generate_password_hash("secret1"), role, svc.now_str())).lastrowid

    def mk_trip(self, seats=2, hours=24):
        when = (datetime.now() + timedelta(hours=hours)).strftime(svc.FMT)
        return self.db.execute(
            "INSERT INTO trips (vehicle_id,origin,destination,pickup_points,depart_at,seats_total,created_at) "
            "VALUES (?,?,?,?,?,?,?)", (self.vehicle, "Market", "College", "Temple", when, seats, svc.now_str())).lastrowid

    def login(self, client, email):
        return client.post("/login", data={"email": email, "password": "secret1"}, follow_redirects=True)


class TestSmartRide(Base):
    def test_tc01_login_and_role_access(self):  # TC-01
        c = self.app.test_client()
        self.assertIn(b"Invalid", c.post("/login", data={"email": "s1@t.io", "password": "bad"}).data)
        self.login(c, "s1@t.io")
        self.assertEqual(c.get("/my-bookings").status_code, 200)
        self.assertEqual(c.get("/admin").status_code, 403)

    def test_tc02_search_filters(self):  # TC-02
        other = self.mk_trip(seats=1, hours=48)
        self.db.execute("UPDATE trips SET origin='Lake', destination='Station' WHERE id=?", (other,))
        found = svc.search_trips(self.db, origin="Market", destination="College")
        self.assertEqual([t["id"] for t in found], [self.trip])
        self.assertEqual(len(svc.search_trips(self.db)), 2)

    def test_tc03_capacity_rule(self):  # TC-03
        with self.assertRaises(svc.BookingError):
            svc.request_booking(self.db, self.s1, self.trip, 3)  # only 2 seats offered
        bid = svc.request_booking(self.db, self.s1, self.trip, 2)
        self.assertEqual(svc.respond_booking(self.db, self.driver, bid, True), "Confirmed")
        self.assertEqual(svc.seats_left(self.db, self.trip), 0)
        with self.assertRaises(svc.BookingError):
            svc.request_booking(self.db, self.s2, self.trip, 1)

    def test_tc04_concurrent_last_seat(self):  # TC-04
        trip = self.mk_trip(seats=1)
        b1 = svc.request_booking(self.db, self.s1, trip, 1)
        b2 = svc.request_booking(self.db, self.s2, trip, 1)  # both pending, one seat
        results = []

        def accept(bid):
            with self.app.app_context():
                try:
                    results.append(svc.respond_booking(database.get_db(), self.driver, bid, True))
                except svc.BookingError:
                    results.append("blocked")
                finally:
                    database.close_db()

        threads = [threading.Thread(target=accept, args=(b,)) for b in (b1, b2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(results), ["Confirmed", "blocked"])
        self.assertEqual(svc.seats_left(self.db, trip), 0)

    def test_tc05_status_transitions(self):  # TC-05
        b = svc.request_booking(self.db, self.s1, self.trip, 1)
        self.assertEqual(self.status(b), "Pending")
        svc.respond_booking(self.db, self.driver, b, True)
        self.assertEqual(self.status(b), "Confirmed")
        svc.cancel_booking(self.db, self.s1, b)
        self.assertEqual(self.status(b), "Cancelled")
        self.assertEqual(svc.seats_left(self.db, self.trip), 2)  # seats released
        b2 = svc.request_booking(self.db, self.s1, self.trip, 1)
        svc.respond_booking(self.db, self.driver, b2, False)
        self.assertEqual(self.status(b2), "Rejected")
        with self.assertRaises(svc.BookingError):  # cannot decide twice
            svc.respond_booking(self.db, self.driver, b2, True)

    def test_tc05b_cancel_cutoff_and_duplicates(self):
        soon = self.mk_trip(seats=2, hours=0)
        self.db.execute("UPDATE trips SET depart_at=? WHERE id=?",
                        ((datetime.now() + timedelta(minutes=30)).strftime(svc.FMT), soon))
        b = svc.request_booking(self.db, self.s1, soon, 1)
        with self.assertRaises(svc.BookingError):
            svc.cancel_booking(self.db, self.s1, b, cutoff_minutes=60)
        with self.assertRaises(svc.BookingError):
            svc.request_booking(self.db, self.s1, soon, 1)  # duplicate active booking

    def test_tc06_notifications(self):  # TC-06
        b = svc.request_booking(self.db, self.s1, self.trip, 1)
        self.assertEqual(self.count_notes(self.driver), 1)
        svc.respond_booking(self.db, self.driver, b, True)
        self.assertEqual(self.count_notes(self.s1), 1)
        self.assertEqual(svc.cancel_trip(self.db, self.driver, self.trip), 1)
        self.assertEqual(self.count_notes(self.s1), 2)

    def test_tc07_access_control(self):  # TC-07
        b = svc.request_booking(self.db, self.s1, self.trip, 1)
        with self.assertRaises(PermissionError):  # another driver
            svc.respond_booking(self.db, self.driver2, b, True)
        with self.assertRaises(PermissionError):  # another student
            svc.cancel_booking(self.db, self.s2, b)
        with self.assertRaises(PermissionError):
            svc.cancel_trip(self.db, self.driver2, self.trip)
        c = self.app.test_client()
        self.login(c, "s1@t.io")
        self.assertEqual(c.post(f"/driver/bookings/{b}/accept").status_code, 403)

    def test_registration_and_driver_verification(self):
        c = self.app.test_client()
        r = c.post("/register", data={"name": "New Driver", "email": "nd@t.io", "phone": "9", "role": "driver",
                                      "password": "secret1"}, follow_redirects=True)
        self.assertIn(b"verify", r.data)
        self.login(c, "nd@t.io")
        r = c.get("/driver/trips/new", follow_redirects=True)
        self.assertIn(b"awaiting administrator verification", r.data)
        self.assertEqual(c.post("/register", data={"name": "x", "email": "nd@t.io", "phone": "9",
                                                   "password": "secret1"}).status_code, 200)

    def test_csrf_enforced(self):
        app = create_app({"DATABASE": self.path, "TESTING": True})  # CSRF on
        self.assertEqual(app.test_client().post("/login", data={"email": "a", "password": "b"}).status_code, 400)

    def test_completed_trips_and_expired_requests(self):  # auto "Completed" status
        b = svc.request_booking(self.db, self.s1, self.trip, 1)
        self.db.execute("UPDATE trips SET depart_at=? WHERE id=?",
                        ((datetime.now() - timedelta(hours=1)).strftime(svc.FMT), self.trip))
        self.assertEqual(svc.complete_past_trips(self.db), 1)
        self.assertEqual(self.trip_status(self.trip), "Completed")
        self.assertEqual(self.status(b), "Rejected")  # unanswered request closed
        self.assertEqual(svc.complete_past_trips(self.db), 0)

    def test_driver_edit_trip_notifies_students(self):
        b = svc.request_booking(self.db, self.s1, self.trip, 2)
        svc.respond_booking(self.db, self.driver, b, True)
        before = self.count_notes(self.s1)
        when = (datetime.now() + timedelta(days=2)).strftime(svc.FMT)
        self.assertEqual(svc.update_trip(self.db, self.driver, self.trip, "Srinagar", "Kupwara", "Lal Chowk", when, 3), 1)
        self.assertEqual(self.count_notes(self.s1), before + 1)
        with self.assertRaises(svc.BookingError):  # 2 seats already confirmed
            svc.update_trip(self.db, self.driver, self.trip, "Srinagar", "Kupwara", "", when, 1)
        with self.assertRaises(PermissionError):
            svc.update_trip(self.db, self.driver2, self.trip, "Srinagar", "Kupwara", "", when, 3)

    def test_rating_rules(self):
        b = svc.request_booking(self.db, self.s1, self.trip, 1)
        svc.respond_booking(self.db, self.driver, b, True)
        with self.assertRaises(svc.BookingError):  # trip not completed yet
            svc.rate_driver(self.db, self.s1, b, 5, "great")
        self.db.execute("UPDATE trips SET status='Completed' WHERE id=?", (self.trip,))
        with self.assertRaises(PermissionError):
            svc.rate_driver(self.db, self.s2, b, 5)
        with self.assertRaises(svc.BookingError):
            svc.rate_driver(self.db, self.s1, b, 9)
        svc.rate_driver(self.db, self.s1, b, 4, "good ride")
        with self.assertRaises(svc.BookingError):  # only one rating per booking
            svc.rate_driver(self.db, self.s1, b, 5)
        self.assertEqual(svc.get_trip(self.db, self.trip)["avg_rating"], 4.0)

    def test_change_password(self):
        c = self.app.test_client()
        self.login(c, "s1@t.io")
        r = c.post("/account/password", data={"current": "wrong", "new": "newpass1", "confirm": "newpass1"})
        self.assertIn(b"incorrect", r.data)
        c.post("/account/password", data={"current": "secret1", "new": "newpass1", "confirm": "newpass1"})
        c2 = self.app.test_client()
        r = c2.post("/login", data={"email": "s1@t.io", "password": "newpass1"})
        self.assertEqual(r.status_code, 302)

    def test_city_validation_when_publishing(self):
        c = self.app.test_client()
        self.login(c, "d@t.io")
        when = (datetime.now() + timedelta(days=1)).strftime(svc.FMT)
        data = {"vehicle_id": self.vehicle, "origin": "Delhi", "destination": "Kupwara",
                "depart_at": when, "seats_total": 2}
        self.assertIn(b"city list", c.post("/driver/trips/new", data=data).data)
        data["origin"] = "Srinagar"
        c.post("/driver/trips/new", data=data)
        n = self.db.execute("SELECT COUNT(*) FROM trips WHERE origin='Srinagar' AND destination='Kupwara'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_login_throttle(self):
        c = self.app.test_client()
        for _ in range(5):
            c.post("/login", data={"email": "s2@t.io", "password": "bad"})
        r = c.post("/login", data={"email": "s2@t.io", "password": "secret1"})
        self.assertIn(b"Too many", r.data)

    # helpers
    def status(self, bid):
        return self.db.execute("SELECT status FROM bookings WHERE id=?", (bid,)).fetchone()[0]

    def trip_status(self, tid):
        return self.db.execute("SELECT status FROM trips WHERE id=?", (tid,)).fetchone()[0]

    def count_notes(self, uid):
        return self.db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=?", (uid,)).fetchone()[0]


if __name__ == "__main__":
    unittest.main()
