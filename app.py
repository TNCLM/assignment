import re  
from werkzeug.utils import escape #for preventing sql injection and xss added to login and egister

# Define password validation function
def is_password_valid(password):

    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    return None

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import pymysql
from flask_bcrypt import Bcrypt
from utils import log_action
from db_config1 import get_db_connection
from db_config1 import initialize_database
from flask import flash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Set session lifetime
app.permanent_session_lifetime = timedelta(minutes=2)  

bcrypt = Bcrypt(app)
db = get_db_connection()
initialize_database()


@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = escape(request.form["username"])
        password = escape(request.form["password"])
        email = escape(request.form["email"])
        secondary_password = escape(request.form["secondary_password"])


        # Validate passwords
        validation_error = is_password_valid(password)
        if validation_error:
            flash(validation_error, "danger")
            return render_template("register.html")
        
        if not secondary_password or len(secondary_password) < 8:
            flash("Secondary password must be at least 8 characters long.", "danger")
            return render_template("register.html")

        # Hash passwords
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        hashed_secondary_password = bcrypt.generate_password_hash(secondary_password).decode("utf-8")

        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, secondary_password) VALUES (%s, %s, %s, %s)",
                (username, hashed_password, email, hashed_secondary_password),
            )
            db.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except pymysql.MySQLError as e:
            db.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = escape(request.form["username"])
        password = escape(request.form["password"])

        cursor = db.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT id, password, is_admin FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["is_admin"] = user["is_admin"]
            log_action(db, user_id=user["id"], action="USER LOGGED IN", table_name="users")
            return redirect(url_for("transactions"))

        log_action(db, user_id=None, action="FAILED LOGIN ATTEMPT", table_name="users")
        return "Invalid credentials. Try again."
    return render_template("login.html")


@app.route("/transactions", methods=["GET", "POST"])
def transactions():
    if "user_id" not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        secondary_password = request.form["secondary_password"]
        amount = request.form["amount"]

        cursor = db.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT secondary_password FROM users WHERE id = %s", (session["user_id"],))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user["secondary_password"], secondary_password):
            cursor.execute("INSERT INTO transactions (user_id, amount) VALUES (%s, %s)", (session["user_id"], amount))
            db.commit()
            log_action(db, session["user_id"], "CREATE TRANSACTION", "transactions")
            flash("Transaction created successfully.", "success")
        else:
            flash("Invalid secondary password.", "danger")
    
    return render_template("transactions.html")



@app.route("/audit_logs", methods=["GET", "POST"])
def audit_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        secondary_password = request.form["secondary_password"]
        try:
            cursor = db.cursor(pymysql.cursors.DictCursor)
            cursor.execute("SELECT secondary_password, is_admin FROM users WHERE id = %s", (session["user_id"],))
            user = cursor.fetchone()

            if user and bcrypt.check_password_hash(user["secondary_password"], secondary_password):
                # Check if the user is an admin
                if user["is_admin"]:
                    # Admin can view all logs
                    query = """
                    SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.table_name,
                           audit_logs.record_id, audit_logs.ip_address, audit_logs.timestamp
                    FROM audit_logs
                    LEFT JOIN users ON audit_logs.user_id = users.id
                    ORDER BY audit_logs.timestamp DESC;
                    """
                else:
                    # Regular user can only view their own logs
                    query = """
                    SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.table_name,
                           audit_logs.record_id, audit_logs.ip_address, audit_logs.timestamp
                    FROM audit_logs
                    LEFT JOIN users ON audit_logs.user_id = users.id
                    WHERE audit_logs.user_id = %s
                    ORDER BY audit_logs.timestamp DESC;
                    """
                
                cursor.execute(query, (session["user_id"],) if not user["is_admin"] else ())
                logs = cursor.fetchall()
                return render_template("audit_logs.html", logs=logs)

            flash("Invalid secondary password.", "danger")
        except Exception as e:
            flash(f"An error occurred while fetching logs: {str(e)}", "danger")
            return redirect(url_for("home"))

    return render_template("secondary_password_prompt.html", action="view audit logs")



@app.route("/view_database")
def view_database():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check if the user is admin
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user or not user[0]:  # Not admin or user not found
        return "You are not authorized to view this page."

    # Fetch all tables
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

    database_data = {}
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        cursor.execute(f"SHOW COLUMNS FROM {table_name}")
        columns = [col[0] for col in cursor.fetchall()]
        database_data[table_name] = {"columns": columns, "rows": rows}

    return render_template("view_database.html", database_data=database_data)

@app.route("/delete_table/<table_name>", methods=["POST"])
def delete_table(table_name):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check if the user is admin
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user or not user[0]:  
        return "You are not authorized to perform this action."

    try:
        # Delete the table
        cursor.execute(f"DROP TABLE `{table_name}`")
        db.commit()
        flash(f"Table '{table_name}' has been deleted successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while deleting the table: {str(e)}", "danger")

    return redirect(url_for("view_database"))




@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)