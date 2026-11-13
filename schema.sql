-- SmartRide schema (SQLite). Mirrors the ERD in the assignment.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student','driver','admin')),
    verified INTEGER NOT NULL DEFAULT 0,   -- drivers need admin verification
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vehicles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    driver_id INTEGER NOT NULL REFERENCES users(id),
    plate_no TEXT NOT NULL UNIQUE,
    capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 20)
);
CREATE TABLE IF NOT EXISTS trips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER NOT NULL REFERENCES vehicles(id),
    origin TEXT NOT NULL,
    destination TEXT NOT NULL,
    pickup_points TEXT NOT NULL DEFAULT '',
    depart_at TEXT NOT NULL,               -- ISO 'YYYY-MM-DDTHH:MM'
    seats_total INTEGER NOT NULL CHECK (seats_total >= 1),
    status TEXT NOT NULL DEFAULT 'Scheduled'
        CHECK (status IN ('Scheduled','Cancelled','Completed')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id),
    trip_id INTEGER NOT NULL REFERENCES trips(id),
    seats INTEGER NOT NULL CHECK (seats >= 1),
    status TEXT NOT NULL DEFAULT 'Pending'
        CHECK (status IN ('Pending','Confirmed','Rejected','Cancelled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL UNIQUE REFERENCES bookings(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    driver_id INTEGER NOT NULL REFERENCES users(id),
    stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
    comment TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ratings_driver ON ratings(driver_id);
CREATE INDEX IF NOT EXISTS idx_trips_depart ON trips(depart_at);
CREATE INDEX IF NOT EXISTS idx_bookings_trip ON bookings(trip_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_stud ON bookings(student_id);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read);
