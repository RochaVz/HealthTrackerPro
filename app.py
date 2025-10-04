from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, FloatField, IntegerField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange
from datetime import datetime
import os
import logging
import bleach
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
import urllib.parse

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Load Environment Variables ---
load_dotenv()

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_for_development_only_change_me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///health_tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Context Processor for 'now' ---
# This makes 'now' (a datetime object) available in ALL Jinja2 templates rendered by Flask.
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# --- User Loader Function ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) # Using the SQLAlchemy 2.0 recommended method

# --- Form Classes ---
# ... (Your form classes remain the same) ...
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class HealthEntryForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired()], format='%Y-%m-%d')
    weight_kg = FloatField('Weight (kg)', validators=[NumberRange(min=0)])
    systolic_bp = IntegerField('Systolic BP', validators=[NumberRange(min=0, max=300)])
    diastolic_bp = IntegerField('Diastolic BP', validators=[NumberRange(min=0, max=200)])
    sleep_hours = FloatField('Sleep Hours', validators=[NumberRange(min=0, max=24)])
    notes = TextAreaField('Notes')
    submit = SubmitField('Submit')

class MedicationForm(FlaskForm):
    medication_name = StringField('Medication Name', validators=[DataRequired()])
    dosage = StringField('Dosage')
    frequency = StringField('Frequency')
    last_taken_date = DateField('Last Taken Date', format='%Y-%m-%d')
    notes = TextAreaField('Notes')
    submit = SubmitField('Submit')

class SymptomForm(FlaskForm):
    symptom_name = StringField('Symptom Name', validators=[DataRequired()])
    severity = IntegerField('Severity (1-5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    symptom_date_time = DateField('Date', validators=[DataRequired()], format='%Y-%m-%d')
    notes = TextAreaField('Notes')
    submit = SubmitField('Submit')

# --- Data Models ---
# ... (Your User, HealthEntry, Medication, Symptom models remain the same) ...
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)

    health_entries = db.relationship('HealthEntry', backref='author', lazy=True, cascade="all, delete-orphan")
    medications = db.relationship('Medication', backref='owner', lazy=True, cascade="all, delete-orphan")
    symptoms = db.relationship('Symptom', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class HealthEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    weight_kg = db.Column(db.Float)
    systolic_bp = db.Column(db.Integer)
    diastolic_bp = db.Column(db.Integer)
    sleep_hours = db.Column(db.Float)
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)

    def __repr__(self):
        return f'<HealthEntry {self.date} for User ID {self.user_id}>'

class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    medication_name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50))
    frequency = db.Column(db.String(100))
    last_taken_date = db.Column(db.Date)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f'<Medication {self.medication_name} for User {self.user_id}>'

class Symptom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    symptom_name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.Integer, nullable=False, default=1)
    symptom_date_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f'<Symptom {self.symptom_name} on {self.symptom_date_time} for User {self.user_id}>'


# --- Database Initialization ---
with app.app_context():
    db.create_all()
    logger.info("Database tables created (or already exist).")

# --- Helper Function for Validation ---
def validate_health_entry(form):
    data = {}
    error = None

    if form.validate_on_submit():
        if form.systolic_bp.data is not None and form.diastolic_bp.data is not None and form.systolic_bp.data < form.diastolic_bp.data:
            error = "Systolic BP cannot be less than Diastolic BP."
            return data, error

        data['date'] = form.date.data
        data['weight_kg'] = form.weight_kg.data
        data['systolic_bp'] = form.systolic_bp.data
        data['diastolic_bp'] = form.diastolic_bp.data
        data['sleep_hours'] = form.sleep_hours.data
        data['notes'] = bleach.clean(form.notes.data) if form.notes.data else None
    else:
        error = "Invalid form data. Please check your inputs."

    return data, error

# --- Routes ---
@app.route('/')
@login_required
def index():
    entries = HealthEntry.query.options(selectinload(HealthEntry.author)).filter_by(user_id=current_user.id).order_by(
        HealthEntry.date.desc()).limit(5).all()
    weight_entries = HealthEntry.query.filter_by(user_id=current_user.id).filter(
        HealthEntry.weight_kg.isnot(None)).order_by(HealthEntry.date.asc()).limit(30).all()
    chart_dates = [entry.date.isoformat() for entry in weight_entries]
    chart_values = [entry.weight_kg for entry in weight_entries]
    med_logs = Medication.query.filter_by(user_id=current_user.id).order_by(Medication.last_taken_date.desc()).limit(
        3).all()
    recent_symptoms = Symptom.query.filter_by(user_id=current_user.id).order_by(Symptom.symptom_date_time.desc()).limit(
        3).all()

    return render_template('index.html',
                           entries=entries,
                           current_user=current_user,
                           chart_dates=chart_dates,
                           chart_values=chart_values,
                           med_logs=med_logs,
                           recent_symptoms=recent_symptoms)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    form = HealthEntryForm()
    if request.method == 'POST' and form.validate_on_submit(): # Simplified POST validation check
        data, error = validate_health_entry(form)
        if error:
            flash(error, 'danger')
            return render_template('add_entry.html', form=form, error=error)

        try:
            new_entry = HealthEntry(
                date=data['date'],
                weight_kg=data['weight_kg'],
                systolic_bp=data['systolic_bp'],
                diastolic_bp=data['diastolic_bp'],
                sleep_hours=data['sleep_hours'],
                notes=data['notes'],
                user_id=current_user.id
            )
            db.session.add(new_entry)
            db.session.commit()
            flash('Health entry added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding health entry: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
            return render_template('add_entry.html', form=form, error=str(e))

    return render_template('add_entry.html', form=form, error=None)

@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = HealthEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if not entry:
        flash('Entry not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('history'))

    # For POST requests, bind request.form data to the form.
    # For GET requests, it will use the obj=entry to pre-fill.
    form = HealthEntryForm(request.form, obj=entry)

    if request.method == 'POST':
        logger.info(f"Received POST request for edit_entry with ID: {entry_id}")
        logger.info(f"Raw POST data: {request.form}")
        logger.info(f"Form object data before validation: {form.data}")

        if form.validate_on_submit():
            logger.info(f"Form validated successfully for entry ID: {entry_id}")
            try:
                logger.info(f"Attempting to update entry {entry.id}...")
                entry.date = form.date.data
                entry.weight_kg = form.weight_kg.data
                entry.systolic_bp = form.systolic_bp.data
                entry.diastolic_bp = form.diastolic_bp.data
                entry.sleep_hours = form.sleep_hours.data
                entry.notes = bleach.clean(form.notes.data) if form.notes.data else None

                db.session.commit()
                logger.info(f"Entry {entry.id} updated successfully.")
                flash('Health entry updated successfully!', 'success')
                return redirect(url_for('history'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error updating health entry {entry.id}: {str(e)}")
                flash(f'An error occurred: {str(e)}', 'danger')
                return render_template('edit_entry.html', form=form, entry_id=entry.id, entry=entry) # Pass entry here
        else:
            logger.warning(f"Form validation failed for entry ID: {entry_id}. Errors: {form.errors}")
            return render_template('edit_entry.html', form=form, entry_id=entry.id, entry=entry) # Pass entry here

    # For GET request, render the form populated with the existing entry's data.
    logger.info(f"Rendering GET form for edit_entry ID: {entry_id}")
    return render_template('edit_entry.html', form=form, entry_id=entry.id, entry=entry) # Pass entry here


@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = HealthEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if not entry:
        flash('Entry not found or you do not have permission to delete it.', 'danger')
        return redirect(url_for('history'))

    try:
        db.session.delete(entry)
        db.session.commit()
        flash('Health entry deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting health entry: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('history'))


@app.route('/history')
@login_required
def history():
    """
    Displays a paginated list of the current user's health entries,
    ordered by date in descending order.
    """
    page = request.args.get('page', 1, type=int)  # Get the page number from query parameters, default to 1

    # Query for health entries belonging to the current user, order by date descending,
    # and paginate the results. paginate() returns an object that contains
    # the items for the current page, and pagination metadata.
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.desc()).paginate(page=page,
                                                                                                              per_page=10)
    form_for_csrf = RegisterForm()
    # --- CSRF Protection Fix ---
    # We need to pass a form object to the template so that form.hidden_tag() works.
    # This is necessary because the history.html template uses form.hidden_tag()
    # in the delete form, which requires a 'form' object in the template context.
    # We can use any form that has a hidden_tag() method, like RegisterForm,
    # or create a minimal one just for this purpose if preferred.
    # Ensure the form class you use here is imported. For example:
    # from .forms import RegisterForm # If forms are in a separate forms.py file
    # If RegisterForm is defined in app.py, you don't need a separate import here.

    # Assuming RegisterForm is defined within app.py or imported correctly:
    form_for_csrf = RegisterForm()  # Instantiate a form object.

    # Render the history.html template, passing the paginated entries and the form object.
    return render_template('history.html', entries=entries, form=form_for_csrf)

@app.route('/trends')
@login_required
def trends():
    metric = request.args.get('metric', 'weight')
    # Fetch more entries for better trend visualization if needed, or adjust query
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.asc()).limit(30).all()

    dates = []
    values = []
    title = "Trend"
    ylabel = "Value"

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
    else:
        metric = 'weight' # Default to weight
        title = "Weight Trend (kg)"
        ylabel = "Weight (kg)"
        for entry in entries:
            if entry.weight_kg is not None:
                dates.append(entry.date.isoformat())
                values.append(entry.weight_kg)

    if not dates or not values:
        flash('No data available for the selected metric.', 'info')

    return render_template('trends.html',
                           dates=dates,
                           values=values,
                           metric=metric,
                           title=title,
                           ylabel=ylabel)

@app.route('/medications')
@login_required
def medications():
    page = request.args.get('page', 1, type=int)
    med_logs = Medication.query.filter_by(user_id=current_user.id).order_by(Medication.medication_name.asc()).paginate(
        page=page, per_page=10)
    return render_template('medications.html', med_logs=med_logs)


@app.route('/add_medication', methods=['GET', 'POST'])
@login_required
def add_medication():
    form = MedicationForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            new_med = Medication(
                user_id=current_user.id,
                medication_name=form.medication_name.data,
                dosage=form.dosage.data,
                frequency=form.frequency.data,
                last_taken_date=form.last_taken_date.data,
                notes=bleach.clean(form.notes.data) if form.notes.data else None
            )
            db.session.add(new_med)
            db.session.commit()
            flash('Medication added successfully!', 'success')
            return redirect(url_for('medications'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding medication: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    return render_template('add_medication.html', form=form, error=None)

@app.route('/edit_medication/<int:med_id>', methods=['GET', 'POST'])
@login_required
def edit_medication(med_id):
    medication = Medication.query.filter_by(id=med_id, user_id=current_user.id).first()
    if not medication:
        flash('Medication not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('medications'))

    form = MedicationForm(obj=medication)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            medication.medication_name = form.medication_name.data
            medication.dosage = form.dosage.data
            medication.frequency = form.frequency.data
            medication.last_taken_date = form.last_taken_date.data
            medication.notes = bleach.clean(form.notes.data) if form.notes.data else None
            db.session.commit()
            flash('Medication updated successfully!', 'success')
            return redirect(url_for('medications'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating medication: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    return render_template('edit_medication.html', form=form, error=None, med_id=med_id)

@app.route('/delete_medication/<int:med_id>', methods=['POST'])
@login_required
def delete_medication(med_id):
    medication = Medication.query.filter_by(id=med_id, user_id=current_user.id).first()
    if not medication:
        flash('Medication not found or you do not have permission to delete it.', 'danger')
        return redirect(url_for('medications'))
    try:
        db.session.delete(medication)
        db.session.commit()
        flash('Medication deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting medication: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'danger')
    return redirect(url_for('medications'))

@app.route('/symptoms')
@login_required
def symptoms():
    page = request.args.get('page', 1, type=int)
    symptoms = Symptom.query.filter_by(user_id=current_user.id).order_by(Symptom.symptom_date_time.desc()).paginate(
        page=page, per_page=10)
    return render_template('symptoms.html', symptoms=symptoms)

@app.route('/add_symptom', methods=['GET', 'POST'])
@login_required
def add_symptom():
    form = SymptomForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Combine date with min time for datetime object as per your model
            symptom_datetime = datetime.combine(form.symptom_date_time.data, datetime.min.time())
            new_symptom = Symptom(
                user_id=current_user.id,
                symptom_name=form.symptom_name.data,
                severity=form.severity.data,
                symptom_date_time=symptom_datetime,
                notes=bleach.clean(form.notes.data) if form.notes.data else None
            )
            db.session.add(new_symptom)
            db.session.commit()
            flash('Symptom added successfully!', 'success')
            return redirect(url_for('symptoms'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding symptom: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    return render_template('add_symptom.html', form=form, error=None)

@app.route('/edit_symptom/<int:symptom_id>', methods=['GET', 'POST'])
@login_required
def edit_symptom(symptom_id):
    symptom = Symptom.query.filter_by(id=symptom_id, user_id=current_user.id).first()
    if not symptom:
        flash('Symptom not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('symptoms'))

    form = SymptomForm(obj=symptom)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            symptom_datetime = datetime.combine(form.symptom_date_time.data, datetime.min.time())
            symptom.symptom_name = form.symptom_name.data
            symptom.severity = form.severity.data
            symptom.symptom_date_time = symptom_datetime
            symptom.notes = bleach.clean(form.notes.data) if form.notes.data else None
            db.session.commit()
            flash('Symptom updated successfully!', 'success')
            return redirect(url_for('symptoms'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating symptom: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
    return render_template('edit_symptom.html', form=form, error=None, symptom_id=symptom_id)

@app.route('/delete_symptom/<int:symptom_id>', methods=['POST'])
@login_required
def delete_symptom(symptom_id):
    symptom = Symptom.query.filter_by(id=symptom_id, user_id=current_user.id).first()
    if not symptom:
        flash('Symptom not found or you do not have permission to delete it.', 'danger')
        return redirect(url_for('symptoms'))
    try:
        db.session.delete(symptom)
        db.session.commit()
        flash('Symptom deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting symptom: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'danger')
    return redirect(url_for('symptoms'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already taken.', 'danger')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during registration: {str(e)}")
            flash(f'An unexpected error occurred: {str(e)}', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        logger.debug(f"Login attempt for username='{form.username.data}'")
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            flash('Username not found.', 'danger')
        elif not user.check_password(form.password.data):
            flash('Incorrect password.', 'danger')
        else:
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Helper for get_health_history_text ---
@app.route('/get_health_history_text')
@login_required
def get_health_history_text():
    """Generates a text summary of health entries for the current user."""
    entries = HealthEntry.query.filter_by(user_id=current_user.id).order_by(HealthEntry.date.desc()).all()

    if not entries:
        return jsonify({"error": "No health entries found."}), 404

    text_summary = f"Health Entry History for {current_user.username}:\n\n"
    for entry in entries:
        text_summary += f"Date: {entry.date.strftime('%Y-%m-%d')}\n"
        if entry.weight_kg:
            text_summary += f"  Weight: {entry.weight_kg:.1f} kg\n"
        if entry.systolic_bp and entry.diastolic_bp:
            text_summary += f"  Blood Pressure: {entry.systolic_bp}/{entry.diastolic_bp} mmHg\n"
        if entry.sleep_hours:
            text_summary += f"  Sleep: {entry.sleep_hours:.1f} hours\n"
        if entry.notes:
            text_summary += f"  Notes: {entry.notes}\n"
        text_summary += "---\n"

    encoded_text = urllib.parse.quote(text_summary)
    whatsapp_share_url = f"whatsapp://send?text={encoded_text}"

    return jsonify({
        "text_summary": text_summary,
        "whatsapp_share_url": whatsapp_share_url
    })

# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True)