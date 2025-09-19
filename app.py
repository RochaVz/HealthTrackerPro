from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- App Initialization ---
app = Flask(__name__, template_folder='templates')
# IMPORTANT: Change this to a strong, random secret key for production!
# For development, you can use a simple string, but NEVER commit this to public repos.
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_me_TO_SOMETHING_RANDOM_AND_LONG'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Initialize Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Route name for the login page
login_manager.login_message_category = 'info'  # Category for flash messages


# --- User Loader Function for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Data Models ---

# 1. User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    health_entries = db.relationship('HealthEntry', backref='author', lazy=True,
                                     cascade="all, delete-orphan")  # Added cascade for deletion

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# 2. Health Entry Model (with foreign key to User)
class HealthEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    weight_kg = db.Column(db.Float)
    systolic_bp = db.Column(db.Integer)
    diastolic_bp = db.Column(db.Integer)
    sleep_hours = db.Column(db.Float)
    notes = db.Column(db.Text)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<HealthEntry {self.date} for User {self.user_id}>'


# Create the database tables
with app.app_context():
    db.create_all()


# --- Routes ---

# Route to protect - requires login
@app.route('/')
@login_required
def index():
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.desc()).limit(5).all()

    # Fetch data for the weight chart preview (last 30 days)
    weight_entries = HealthEntry.query.filter_by(user_id=current_user.id).filter(
        HealthEntry.weight_kg.isnot(None)).order_by(HealthEntry.date.asc()).limit(30).all()

    chart_dates = [entry.date.isoformat() for entry in weight_entries]
    chart_values = [entry.weight_kg for entry in weight_entries]

    # Pass all data to the template
    return render_template('index.html',
                           entries=entries,
                           current_user=current_user,
                           chart_dates=chart_dates,
                           chart_values=chart_values)
# Route to protect
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    error = None
    # Storing submitted form values to re-fill the form on error
    form_data = {
        'date': request.form.get('date', datetime.now().strftime('%Y-%m-%d')),
        # Default to today if GET or date not submitted
        'weight_kg': request.form.get('weight_kg', ''),
        'systolic_bp': request.form.get('systolic_bp', ''),
        'diastolic_bp': request.form.get('diastolic_bp', ''),
        'sleep_hours': request.form.get('sleep_hours', ''),
        'notes': request.form.get('notes', '')
    }

    if request.method == 'POST':
        entry_date_str = form_data['date']
        weight_str = form_data['weight_kg']
        systolic_str = form_data['systolic_bp']
        diastolic_str = form_data['diastolic_bp']
        sleep_str = form_data['sleep_hours']
        notes = form_data['notes']

        # --- Data Validation and Conversion ---

        # 1. Date Validation
        entry_date = None
        if not entry_date_str:
            error = "Date is required."
        else:
            try:
                entry_date = datetime.strptime(entry_date_str, '%Y-%m-%d').date()
            except ValueError:
                error = "Invalid date format. Please use YYYY-MM-DD."

        # 2. Numerical Conversions (handle empty strings and invalid numbers)
        weight_kg = None
        if weight_str:
            try:
                weight_kg = float(weight_str)
                if weight_kg < 0: error = "Weight cannot be negative."
            except ValueError:
                error = "Invalid input for Weight. Please enter a number."

        systolic_bp = None
        if systolic_str:
            try:
                systolic_bp = int(systolic_str)
                if not (0 <= systolic_bp <= 300): error = "Systolic BP must be between 0 and 300."
            except ValueError:
                error = "Invalid input for Systolic BP. Please enter a whole number."

        diastolic_bp = None
        if diastolic_str:
            try:
                diastolic_bp = int(diastolic_str)
                if not (0 <= diastolic_bp <= 200): error = "Diastolic BP must be between 0 and 200."
            except ValueError:
                error = "Invalid input for Diastolic BP. Please enter a whole number."

        # BP consistency check
        if systolic_bp is not None and diastolic_bp is not None and systolic_bp < diastolic_bp:
            error = "Systolic BP cannot be less than Diastolic BP."

        sleep_hours = None
        if sleep_str:
            try:
                sleep_hours = float(sleep_str)
                if not (0 <= sleep_hours <= 24): error = "Sleep duration must be between 0 and 24 hours."
            except ValueError:
                error = "Invalid input for Sleep Duration. Please enter a number."

        # --- Database Operation ---
        if error:
            # If there was an error, re-render the form with the error message and pre-filled data
            return render_template('add_entry.html',
                                   error=error,
                                   today=form_data['date'],  # Use the submitted date string
                                   weight_kg_val=form_data['weight_kg'],
                                   systolic_bp_val=form_data['systolic_bp'],
                                   diastolic_bp_val=form_data['diastolic_bp'],
                                   sleep_hours_val=form_data['sleep_hours'],
                                   notes_val=form_data['notes'])
        else:
            # If no errors, create and save the new entry, linking it to the current user
            new_entry = HealthEntry(
                date=entry_date,
                weight_kg=weight_kg,
                systolic_bp=systolic_bp,
                diastolic_bp=diastolic_bp,
                sleep_hours=sleep_hours,
                notes=notes,
                user_id=current_user.id  # Link to the logged-in user
            )
            db.session.add(new_entry)
            db.session.commit()
            # Use flash message for success feedback
            flash('Health entry added successfully!', 'success')
            return redirect(url_for('index'))  # Redirect on success

    # For GET request, show the form with default values
    return render_template('add_entry.html',
                           today=datetime.now().strftime('%Y-%m-%d'),
                           weight_kg_val="", systolic_bp_val="", diastolic_bp_val="", sleep_hours_val="", notes_val="")


# Route to protect
@app.route('/history')
@login_required
def history():
    # Filter entries by the current user
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.desc()).all()
    return render_template('history.html', entries=entries)


# Route to protect
@app.route('/trends')
@login_required
def trends():
    # Filter entries by the current user
    metric = request.args.get('metric', 'weight')  # Default to weight

    # Fetch data for a range (e.g., last 30 days) for the current user
    # You might want to make this date range dynamic later
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.asc()).limit(30).all()

    dates = []
    values = []
    title = "Trend"
    ylabel = "Value"

    # Data preparation for Chart.js
    if metric == 'weight':
        title = "Weight Trend (kg)"
        ylabel = "Weight (kg)"
        for entry in entries:
            if entry.weight_kg is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.weight_kg)
    elif metric == 'bp_systolic':
        title = "Systolic Blood Pressure Trend"
        ylabel = "BP (mmHg)"
        for entry in entries:
            if entry.systolic_bp is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.systolic_bp)
    elif metric == 'bp_diastolic':
        title = "Diastolic Blood Pressure Trend"
        ylabel = "BP (mmHg)"
        for entry in entries:
            if entry.diastolic_bp is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.diastolic_bp)
    elif metric == 'sleep_hours':
        title = "Sleep Duration Trend"
        ylabel = "Hours"
        for entry in entries:
            if entry.sleep_hours is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.sleep_hours)
    else:  # Fallback to weight if metric is invalid
        metric = 'weight'
        title = "Weight Trend (kg)"
        ylabel = "Weight (kg)"
        for entry in entries:
            if entry.weight_kg is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.weight_kg)

    # Pass data to the template
    return render_template('trends.html',
                           dates=dates,
                           values=values,
                           metric=metric,
                           title=title,
                           ylabel=ylabel)


# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # If already logged in, redirect to index
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        error = None
        if not username or not email or not password or not confirm_password:
            error = "Please fill in all fields."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif User.query.filter_by(username=username).first():  # Check if username exists
            error = "Username already taken."
        elif User.query.filter_by(email=email).first():  # Check if email exists
            error = "Email already registered."

        if error:
            # Render register page with error and pre-filled values
            return render_template('register.html', error=error, username=username, email=email)
        else:
            # Create new user
            new_user = User(username=username, email=email)
            new_user.set_password(password)  # Hash and set password
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! Please log in.', 'success')  # Success message
            return redirect(url_for('login'))

            # For GET request, show the registration form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (previous code like redirect if already logged in) ...

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        print(
            f"Login POST received: username='{username}', password='{password}', remember='{remember}'")  # Debug print

        user = User.query.filter_by(username=username).first()

        print(f"User found in DB: {user}")  # Debug print

        error = None
        if not username or not password:
            error = "Please enter both username and password."
        elif not user:
            error = "Username not found."
            print("Login Error: Username not found.")  # Debug print
        elif not user.check_password(password):
            error = "Incorrect password."
            print("Login Error: Incorrect password.")  # Debug print

        if error:
            print(f"Login Error to display: {error}")  # Debug print
            return render_template('login.html', error=error, username=username)
        else:
            print("Login successful. Logging in user.")  # Debug print
            login_user(user, remember=remember)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

            # ... (GET request logic) ...
    return render_template('login.html')


@app.route('/logout')
@login_required  # Must be logged in to log out
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))  # Redirect to login page after logout


# --- Run the App ---
if __name__ == '__main__':
    # debug=True is great for development but disable for production
    app.run(debug=True)