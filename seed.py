"""Populate the database with demo users and trips.

    python seed.py            add demo data (skipped if the database already has users)
    python seed.py --reset    delete the database first, then add fresh demo data
"""
import os
import sys
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

import services as svc
from app import create_app
import db as database


def seed(app):
    with app.app_context():
        d = database.get_db()
        if d.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("Database already has data - skipping seed. (Use: python seed.py --reset)")
            return
        now = svc.now_str()

        def user(name, email, phone, role, verified=1):
            return d.execute(
                "INSERT INTO users (name,email,phone,password_hash,role,verified,created_at) VALUES (?,?,?,?,?,?,?)",
                (name, email, phone, generate_password_hash("password123"), role, verified, now)).lastrowid

        user("Admin", "admin@smartride.test", "0000000000", "admin")
        drv1 = user("Ravi Kumar", "driver1@smartride.test", "9000000001", "driver")
        drv2 = user("Sita Devi", "driver2@smartride.test", "9000000002", "driver")
        user("Unverified Driver", "driver3@smartride.test", "9000000003", "driver", verified=0)
        stu1 = user("Asha Student", "student1@smartride.test", "9100000001", "student")
        user("Bilal Student", "student2@smartride.test", "9100000002", "student")
        v1 = d.execute("INSERT INTO vehicles (driver_id, plate_no, capacity) VALUES (?,?,?)", (drv1, "JK01AB1234", 6)).lastrowid
        v2 = d.execute("INSERT INTO vehicles (driver_id, plate_no, capacity) VALUES (?,?,?)", (drv2, "JK05CD5678", 4)).lastrowid
        tomorrow = datetime.now().replace(hour=7, minute=30, second=0, microsecond=0) + timedelta(days=1)
        trips = [
            (v1, "Srinagar", "Baramulla", "Lal Chowk; Parimpora; Pattan", tomorrow, 5),
            (v1, "Baramulla", "Srinagar", "Baramulla Bus Stand; Sopore", tomorrow.replace(hour=16, minute=30), 5),
            (v2, "Kupwara", "Srinagar", "Kupwara Bus Stand; Handwara; Sopore", tomorrow.replace(hour=7, minute=0), 3),
            (v2, "Srinagar", "Kupwara", "Lal Chowk; Parimpora; Sopore; Handwara", tomorrow + timedelta(days=1, hours=8), 3),
            (v2, "Baramulla", "Kupwara", "Baramulla Bus Stand; Sopore; Handwara", tomorrow + timedelta(days=2), 3),
        ]
        for veh, o, dst, pk, when, seats in trips:
            d.execute("INSERT INTO trips (vehicle_id,origin,destination,pickup_points,depart_at,seats_total,created_at) "
                      "VALUES (?,?,?,?,?,?,?)", (veh, o, dst, pk, when.strftime(svc.FMT), seats, now))
        # a finished trip with a confirmed booking, so the rating feature can be demonstrated
        past = (tomorrow - timedelta(days=2)).strftime(svc.FMT)
        past_trip = d.execute(
            "INSERT INTO trips (vehicle_id,origin,destination,pickup_points,depart_at,seats_total,status,created_at) "
            "VALUES (?,?,?,?,?,?,'Completed',?)",
            (v1, "Srinagar", "Kupwara", "Lal Chowk; Handwara", past, 4, now)).lastrowid
        d.execute("INSERT INTO bookings (student_id,trip_id,seats,status,created_at,updated_at) VALUES (?,?,?,'Confirmed',?,?)",
                  (stu1, past_trip, 1, now, now))
        print("Seeded. Logins (password: password123): admin@smartride.test, driver1@smartride.test, "
              "driver2@smartride.test, student1@smartride.test, student2@smartride.test")


if __name__ == "__main__":
    app = create_app()
    if "--reset" in sys.argv:
        path = app.config["DATABASE"]
        if os.path.exists(path):
            os.remove(path)
            print("Old database deleted.")
        app = create_app()
    seed(app)
