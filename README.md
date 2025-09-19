Project Overview
A personal health tracking web application built using Python, Flask, SQLAlchemy, and Jinja2. The application allows users to securely record, view, and analyze various health metrics over time, including weight, blood pressure, and sleep duration. It features user authentication, data persistence via an SQLite database, and basic trend visualization.
Key Features:
User Authentication: Secure registration and login system enabling users to manage their private health data.
Data Logging: Intuitive interface for manually entering daily health metrics:
Date
Weight (in kg)
Blood Pressure (Systolic/Diastolic)
Sleep Duration (in hours)
Notes for additional context
Historical Data View: A chronological display of all logged health entries for a user.
Trend Visualization: Basic charts (using Chart.js) to visualize trends for selected metrics (e.g., weight over time).
Data Persistence: Uses SQLite for local database storage, ensuring data is saved and accessible across sessions.
Input Validation: Basic validation on user inputs (dates, numbers, password matching) to ensure data integrity.
Technology Stack:
Backend: Python
Web Framework: Flask
Database ORM: Flask-SQLAlchemy
Database: SQLite
Authentication: Flask-Login
Frontend: HTML, CSS, JavaScript (for Chart.js)
Development Environment: PyCharm Community Edition
Version Control: Git (Recommended for project management)
How it was Built (Development Process):
Project Setup:
Created a new Python project with a virtual environment (.venv).
Installed necessary libraries: Flask, Flask-SQLAlchemy, Flask-Login, SQLAlchemy, Werkzeug, Flask-Migrate (optional but recommended for larger projects).
Established a clear project structure with app.py, templates/, static/, and instance/ directories.
Database Design and Setup:
Defined SQLAlchemy models (User, HealthEntry) representing database tables.
Configured app.config for SECRET_KEY and SQLALCHEMY_DATABASE_URI (sqlite:///instance/health_tracker.db).
Implemented db.create_all() within an application context to initialize the SQLite database file and create tables based on models.
User Authentication Implementation:
Integrated Flask-Login for managing user sessions.
Created User model with password hashing (set_password, check_password).
Implemented routes for user registration (/register), login (/login), and logout (/logout).
Protected core application routes (/, /add, /history, /trends) using the @login_required decorator.
Ensured health data is associated with the logged-in user via user_id foreign key.
Core Feature Development:
Data Logging: Built the /add route and add_entry.html form with robust input validation and error handling.
History View: Implemented the /history route and history.html to display logged data chronologically, filtered by the current user.
Trends Visualization: Developed the /trends route and trends.html to fetch user-specific data and use Chart.js for plotting metric trends.
Frontend Development:
Created a base.html layout for consistent page structure.
Designed individual HTML templates (index.html, login.html, register.html, etc.).
Used Jinja2 templating for dynamic content and passing data from Flask to HTML.
Implemented basic CSS (static/style.css) for layout and appearance.
Debugging and Iteration:
Systematically troubleshooted TemplateNotFound errors by verifying file structure and PyCharm caches.
Resolved OperationalError by ensuring the database schema was recreated after model changes (deleting the old .db file).
Used print statements and PyCharm's debugger to diagnose issues.
