import sqlite3

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT 0
)
''')

# Create reports table
cursor.execute('''
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    application_number TEXT NOT NULL,
    image_path TEXT NOT NULL,
    detection_result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    patient_email TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# 🔁 Ensure column exists in case the table was created earlier without patient_email
try:
    cursor.execute("ALTER TABLE reports ADD COLUMN patient_email TEXT")
except sqlite3.OperationalError:
    pass  # Column already exists

connection.commit()
connection.close()

print("✅ Database initialized with application_number and patient_email.")
