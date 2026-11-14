from datetime import date, timedelta
from functools import wraps
from pathlib import Path
import os
import secrets
import sqlite3

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'school-resource-dev-secret'
app.config['DATABASE'] = str(Path(__file__).with_name('school.db'))


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    connection = g.pop('db', None)
    if connection is not None:
        connection.close()


def init_db():
    database = db()
    database.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'teacher'))
        );
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity >= 0)
        );
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES users(id),
            resource_id INTEGER NOT NULL REFERENCES resources(id),
            status TEXT NOT NULL DEFAULT 'Pending',
            date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            due_date TEXT
        );
        CREATE TABLE IF NOT EXISTS issue_reports (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES users(id),
            resource_id INTEGER NOT NULL REFERENCES resources(id),
            category TEXT NOT NULL CHECK(category IN ('Outdated', 'Damaged', 'Missing', 'Other')),
            comment TEXT NOT NULL CHECK(length(comment) BETWEEN 1 AND 500),
            date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    loan_columns = {
        column['name'] for column in database.execute('PRAGMA table_info(loans)')
    }
    if 'due_date' not in loan_columns:
        database.execute('ALTER TABLE loans ADD COLUMN due_date TEXT')
    database.execute(
        "UPDATE loans SET due_date = ? WHERE status = 'Approved' AND due_date IS NULL",
        ((date.today() + timedelta(days=14)).isoformat(),),
    )
    if database.execute('SELECT 1 FROM users LIMIT 1').fetchone() is None:
        database.executemany(
            'INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)',
            [
                ('Alex Student', 'student', generate_password_hash('student123'), 'student'),
                ('Ms. Taylor', 'teacher', generate_password_hash('Teacher123'), 'teacher'),
            ],
        )
        database.executemany(
            'INSERT INTO resources (title, subject, description, quantity) VALUES (?, ?, ?, ?)',
            [
                ('Mathematics textbook', 'Mathematics', 'Grade 10 practice questions and worked examples.', 12),
                ('Science lab kit', 'Science', 'Equipment for supervised classroom experiments.', 5),
                ('World atlas', 'Geography', 'Maps and reference material for geography lessons.', 8),
                ('English reader', 'English', 'Short stories and reading activities.', 15),
            ],
        )
    database.commit()


@app.before_request
def prepare_request():
    g.user = None
    user_id = session.get('user_id')
    if user_id is not None:
        g.user = db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    session.setdefault('token', secrets.token_hex(24))
    if request.method == 'POST' and not secrets.compare_digest(
        session['token'], request.form.get('token', '')
    ):
        abort(400)


def require(role=None):
    def decorate(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.user is None:
                return redirect(url_for('login'))
            if role and g.user['role'] != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorate


def create_user_account(username, password, role):
    username = username.strip()
    if not 3 <= len(username) <= 32:
        return 'Username must be between 3 and 32 characters.'
    if not 8 <= len(password) <= 128:
        return 'Password must be between 8 and 128 characters.'
    if role not in {'student', 'teacher'}:
        return 'Choose a valid account type.'

    try:
        db().execute(
            'INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)',
            (username, username, generate_password_hash(password), role),
        )
        db().commit()
    except sqlite3.IntegrityError:
        db().rollback()
        return 'That username is already registered.'
    return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db().execute(
            'SELECT * FROM users WHERE username = ?',
            (request.form.get('username', '').strip(),),
        ).fetchone()
        if user and check_password_hash(user['password'], request.form.get('password', '')):
            session.clear()
            session['user_id'] = user['id']
            session['token'] = secrets.token_hex(24)
            return redirect(url_for('home'))
        flash('Incorrect username or password.', 'danger')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user is not None:
        return redirect(url_for('home'))
    if request.method == 'POST':
        error = create_user_account(
            request.form.get('username', ''),
            request.form.get('password', ''),
            'student',
        )
        if error:
            flash(error, 'danger')
        else:
            flash('Student account created. You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.post('/users/add')
@require('teacher')
def add_user():
    error = create_user_account(
        request.form.get('username', ''),
        request.form.get('password', ''),
        request.form.get('role', ''),
    )
    if error:
        flash(error, 'danger')
    else:
        flash('User account created.', 'success')
    return redirect(url_for('home'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.get('/api/status')
def system_status():
    return jsonify({
        'status': 'online',
        'system_version': '2.0.0-alpha',
        'active_database': 'SQLite',
    }), 200


@app.get('/welcome/<string:username>')
def welcome_user(username):
    return render_template('welcome.html', username=username.strip().capitalize())


@app.get('/')
@require()
def home():
    database = db()
    resources = database.execute('SELECT * FROM resources ORDER BY title').fetchall()
    issue_reports = {}
    if g.user['role'] == 'teacher':
        reports = database.execute('''
            SELECT issue_reports.*, users.name
            FROM issue_reports
            JOIN users ON users.id = issue_reports.student_id
            ORDER BY issue_reports.id DESC
        ''').fetchall()
        for report in reports:
            issue_reports.setdefault(report['resource_id'], []).append(report)
    query = '''
        SELECT loans.*, users.name, resources.title
        FROM loans
        JOIN users ON users.id = loans.student_id
        JOIN resources ON resources.id = loans.resource_id
    '''
    if g.user['role'] == 'teacher':
        loans = db().execute(query + ' ORDER BY loans.id DESC').fetchall()
    else:
        loans = db().execute(
            query + ' WHERE loans.student_id = ? ORDER BY loans.id DESC',
            (g.user['id'],),
        ).fetchall()
    return render_template(
        'index.html',
        resources=resources,
        issue_reports=issue_reports,
        loans=loans,
        available=sum(resource['quantity'] for resource in resources),
        pending=sum(loan['status'] == 'Pending' for loan in loans),
        today=date.today().isoformat(),
        app_title='EduHub Resource Center',
        term='Academic Term 2026',
    )


@app.post('/resources/add')
@require('teacher')
def add_resource():
    title = request.form.get('title', '').strip()
    subject = request.form.get('subject', '').strip()
    description = request.form.get('description', '').strip()
    try:
        quantity = int(request.form.get('quantity', ''))
    except ValueError:
        quantity = -1

    if not (0 < len(title) <= 100 and 0 < len(subject) <= 50
            and 0 <= len(description) <= 500
            and 0 <= quantity <= 1000):
        flash('Enter a title, subject, description (up to 500 characters), and a quantity between 0 and 1000.', 'danger')
    else:
        db().execute(
            'INSERT INTO resources (title, subject, description, quantity) VALUES (?, ?, ?, ?)',
            (title, subject, description, quantity),
        )
        db().commit()
        flash('Resource added.', 'success')
    return redirect(url_for('home'))


@app.post('/resources/<int:resource_id>/delete')
@require('teacher')
def delete_resource(resource_id):
    database = db()
    database.execute('BEGIN IMMEDIATE')
    resource = database.execute(
        'SELECT id FROM resources WHERE id = ?', (resource_id,)
    ).fetchone()
    if resource is None:
        database.rollback()
        abort(404)

    database.execute('DELETE FROM issue_reports WHERE resource_id = ?', (resource_id,))
    database.execute('DELETE FROM loans WHERE resource_id = ?', (resource_id,))
    database.execute('DELETE FROM resources WHERE id = ?', (resource_id,))
    database.commit()
    flash('Resource and its requests and reports deleted.', 'success')
    return redirect(url_for('home'))


@app.post('/resources/<int:resource_id>/issues')
@require('student')
def report_issue(resource_id):
    category = request.form.get('category', '')
    comment = request.form.get('comment', '').strip()
    if category not in {'Outdated', 'Damaged', 'Missing', 'Other'}:
        flash('Choose a valid issue type.', 'danger')
        return redirect(url_for('home'))
    if not 1 <= len(comment) <= 500:
        flash('Add a comment of up to 500 characters.', 'danger')
        return redirect(url_for('home'))

    database = db()
    resource = database.execute(
        'SELECT id FROM resources WHERE id = ?', (resource_id,)
    ).fetchone()
    if resource is None:
        abort(404)
    database.execute(
        'INSERT INTO issue_reports (student_id, resource_id, category, comment) VALUES (?, ?, ?, ?)',
        (g.user['id'], resource_id, category, comment),
    )
    database.commit()
    flash('Your issue report was sent to the teacher.', 'success')
    return redirect(url_for('home'))


@app.post('/resources/<int:resource_id>/request')
@require('student')
def borrow(resource_id):
    database = db()
    database.execute('BEGIN IMMEDIATE')
    resource = database.execute(
        'SELECT * FROM resources WHERE id = ?', (resource_id,)
    ).fetchone()
    if resource is None:
        database.rollback()
        abort(404)
    existing = database.execute(
        "SELECT id FROM loans WHERE student_id = ? AND resource_id = ? AND status IN ('Pending', 'Approved')",
        (g.user['id'], resource_id),
    ).fetchone()
    if existing or resource['quantity'] <= 0:
        database.rollback()
        flash('Item unavailable or you already have an active request.', 'warning')
    else:
        database.execute(
            'INSERT INTO loans (student_id, resource_id) VALUES (?, ?)',
            (g.user['id'], resource_id),
        )
        database.commit()
        flash('Request sent to your teacher.', 'success')
    return redirect(url_for('home'))


@app.post('/loans/<int:loan_id>/<action>')
@require('teacher')
def update_loan(loan_id, action):
    database = db()
    database.execute('BEGIN IMMEDIATE')
    loan = database.execute('SELECT * FROM loans WHERE id = ?', (loan_id,)).fetchone()
    if loan is None:
        database.rollback()
        abort(404)

    if action == 'approve' and loan['status'] == 'Pending':
        changed = database.execute(
            'UPDATE resources SET quantity = quantity - 1 WHERE id = ? AND quantity > 0',
            (loan['resource_id'],),
        ).rowcount
        if not changed:
            database.rollback()
            flash('No copies available.', 'warning')
            return redirect(url_for('home'))
        status = 'Approved'
        due_date = (date.today() + timedelta(days=14)).isoformat()
    elif action == 'decline' and loan['status'] == 'Pending':
        status = 'Declined'
    elif action == 'return' and loan['status'] == 'Approved':
        database.execute(
            'UPDATE resources SET quantity = quantity + 1 WHERE id = ?',
            (loan['resource_id'],),
        )
        status = 'Returned'
    else:
        database.rollback()
        abort(400)

    if action == 'approve':
        database.execute(
            'UPDATE loans SET status = ?, due_date = ? WHERE id = ?',
            (status, due_date, loan_id),
        )
    else:
        database.execute('UPDATE loans SET status = ? WHERE id = ?', (status, loan_id))
    database.commit()
    flash('Request updated.', 'success')
    return redirect(url_for('home'))


with app.app_context():
    init_db()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=os.environ.get('FLASK_DEBUG') == '1')