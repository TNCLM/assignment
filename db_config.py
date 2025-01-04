# db_config.py
import pymysql
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

def get_db_connection():
    """
    Establishes a connection to the MySQL database.
    :return: A connection object for the database.
    """
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="company_db"
    )

def get_db_connection(database="company_db"):
    """
    Establishes a connection to the MySQL server or a specific database.
    :param database: Name of the database to connect to (default is 'company_db').
    :return: A connection object for the database or server.
    """
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",  # Add your MySQL password if applicable
        database=database,  # Ensures the correct database is selected
        autocommit=True
    )


def create_database():
    """
    Creates the database if it does not exist.
    """
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS company_db;")
    connection.close()
    print("Database 'company_db' created successfully or already exists.")

def initialize_database():
    """
    Creates the required tables in the 'company_db' database if they do not exist
    and inserts a preset admin account.
    """
    # Ensure the database exists
    create_database()

    # Connect to the database
    connection = get_db_connection(database="company_db")
    cursor = connection.cursor()

    # SQL for creating the users table
    users = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        secondary_password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """


    # SQL for creating the transactions table
    transactions = """
    CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """

    # SQL for creating the audit_logs table
    audit = """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        action VARCHAR(255) NOT NULL,
        table_name VARCHAR(255),
        record_id INT,
        ip_address VARCHAR(45),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """

    # Execute the SQL statements
    cursor.execute(users)
    cursor.execute(transactions)
    cursor.execute(audit)

    # Check if the admin user already exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    result = cursor.fetchone()
    
    if result[0] == 0:
        # Generate hashed passwords
        admin_password = bcrypt.generate_password_hash("adminpassword").decode("utf-8")
        admin_secondary_password = bcrypt.generate_password_hash("adminsecondary").decode("utf-8")  # Example secondary password

        # Insert admin user with both passwords
        cursor.execute("""
            INSERT INTO users (username, password, secondary_password, email, is_admin)
            VALUES (%s, %s, %s, %s, TRUE)
        """, ("admin", admin_password, admin_secondary_password, "admin@example.com"))
        connection.commit()
        print("Admin user created successfully.")

    connection.close()
    print("Database tables initialized successfully!")