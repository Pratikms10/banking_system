import os
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_bcrypt import Bcrypt
import mysql.connector
from mysql.connector import Error, IntegrityError

app = Flask(__name__)
# Use environment variables for secrets (safer than hardcoding)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_should_change")
bcrypt = Bcrypt(app)

# ---------------- DATABASE CONNECTION ----------------
def get_db_connection():
    """Return a new MySQL connection. For production, consider pooling."""
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", "pratik1011"),
        database=os.environ.get("DB_NAME", "bank_db")
    )
conn = get_db_connection()
cursor = conn.cursor(dictionary=True)

# ---------------- HOME PAGE ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Basic server-side validation
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        raw_password = request.form.get('password', '')

        if not name or not email or not raw_password:
            flash("All fields are required.", "warning")
            return render_template('register.html')

        # TODO: validate email format and password strength here

        hashed = bcrypt.generate_password_hash(raw_password).decode('utf-8')

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password, balance) VALUES (%s, %s, %s, %s)",
                (name, email, hashed, 0.0)
            )
            conn.commit()
            flash("Account created. Please login.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            # likely duplicate email because of unique constraint
            flash("Email already registered. Try logging in.", "danger")
            return render_template('register.html')
        except Error as e:
            # generic DB error
            flash(f"Database error: {e}", "danger")
            return render_template('register.html')
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid email or password")
    
    return render_template('login.html')


# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    message = request.args.get('message')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch balance
    cursor.execute("SELECT balance FROM users WHERE id=%s", (session['user_id'],))
    balance = cursor.fetchone()['balance']

    # Fetch total transactions
    cursor.execute("SELECT COUNT(*) AS total FROM transactions WHERE user_id=%s", (session['user_id'],))
    total_txn = cursor.fetchone()['total']

    # Fetch latest 5 transactions
    cursor.execute("""
        SELECT type, amount, timestamp, note
        FROM transactions
        WHERE user_id=%s
        ORDER BY timestamp DESC
        LIMIT 5
    """, (session['user_id'],))
    recent_txns = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'dashboard.html',
        balance=balance,
        total_transactions=total_txn,
        recent_txns=recent_txns,
        message=message
    )

# ---------------- DEPOSIT ----------------
@app.route('/deposit', methods=['POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    amount = float(request.form['amount'])
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET balance = balance + %s WHERE id=%s", (amount, session['user_id']))
    cursor.execute("INSERT INTO transactions (user_id, type, amount) VALUES (%s, %s, %s)",
                   (session['user_id'], 'Deposit', amount))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('dashboard', message="Deposit Successful! 💰"))


# ---------------- WITHDRAW ----------------
@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    amount = float(request.form['amount'])
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT balance FROM users WHERE id=%s", (session['user_id'],))
    balance = cursor.fetchone()['balance']

    if amount > balance:
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard', message="Insufficient Balance ❌"))

    cursor = conn.cursor()
    cursor.execute("UPDATE users SET balance = balance - %s WHERE id=%s", (amount, session['user_id']))
    cursor.execute("INSERT INTO transactions (user_id, type, amount) VALUES (%s, %s, %s)",
                   (session['user_id'], 'Withdraw', amount))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('dashboard', message="Withdrawal Successful! 💵"))


# ---------------- TRANSFER ----------------
@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    receiver_email = request.form['receiver_email']
    amount = float(request.form['amount'])
    note = request.form.get('note', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Find receiver
    cursor.execute("SELECT id FROM users WHERE email=%s", (receiver_email,))
    receiver = cursor.fetchone()

    if not receiver:
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard', message="Receiver Not Found ❌"))

    if receiver['id'] == session['user_id']:
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard', message="Cannot transfer to yourself ❌"))

    # Check sender balancels
    
    cursor.execute("SELECT balance FROM users WHERE id=%s", (session['user_id'],))
    sender_balance = cursor.fetchone()['balance']

    if sender_balance < amount:
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard', message="Insufficient Balance ❌"))

    # Perform transfer
    cursor.execute("UPDATE users SET balance = balance - %s WHERE id=%s", (amount, session['user_id']))
    cursor.execute("UPDATE users SET balance = balance + %s WHERE id=%s", (amount, receiver['id']))

    # Record transactions
    cursor.execute("INSERT INTO transactions (user_id, type, amount, receiver_id, note) VALUES (%s, %s, %s, %s, %s)",
                   (session['user_id'], 'Transfer Sent', amount, receiver['id'], note))
    cursor.execute("INSERT INTO transactions (user_id, type, amount, receiver_id, note) VALUES (%s, %s, %s, %s, %s)",
                   (receiver['id'], 'Transfer Received', amount, session['user_id'], note))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('dashboard', message="Transfer Successful! 💸"))

# ---------------- TRANSACTIONS ----------------
@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.*, u.email AS receiver_email
        FROM transactions t
        LEFT JOIN users u ON t.receiver_id = u.id
        WHERE t.user_id = %s
        ORDER BY t.timestamp DESC
    """, (session['user_id'],))
    txns = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('transactions.html', txns=txns, title="Transactions")


# ---------------- LOANS SECTION ----------------
@app.route('/loans', methods=['GET', 'POST'])
def loans():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        loan_type = request.form['loan_type']
        amount = float(request.form['amount'])
        interest = float(request.form['interest'])
        tenure = int(request.form['tenure'])

        monthly_rate = interest / (12 * 100)
        emi = amount * monthly_rate * (1 + monthly_rate) ** tenure / ((1 + monthly_rate) ** tenure - 1)

        cursor.execute("""
            INSERT INTO loans (user_id, loan_type, amount, interest_rate, tenure, emi)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session['user_id'], loan_type, amount, interest, tenure, emi))
        conn.commit()

    cursor.execute("SELECT * FROM loans WHERE user_id = %s ORDER BY applied_on DESC", (session['user_id'],))
    loans = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('loans.html', loans=loans, title="Loans")


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)

@app.route('/transactions')
def transactions_page():
    return render_template('transactions.html')

@app.route('/loans', methods=['GET'])
def loans():
    # For now, use dummy data to display
    loans_data = [
        {"id": 1, "amount": 50000, "term": 12, "status": "approved"},
        {"id": 2, "amount": 25000, "term": 6, "status": "pending"},
    ]
    return render_template('loans.html', loans=loans_data)

@app.route('/apply_loan', methods=['POST'])
def apply_loan():
    loan_type = request.form['loan_type']
    amount = request.form['amount']
    flash(f'Loan request for ₹{amount} ({loan_type}) submitted successfully!', 'success')
    return redirect(url_for('loans'))

@app.route('/testdb')
def testdb():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE()")
        db_name = cursor.fetchone()
        return f"✅ Connected to {db_name}"
    except Exception as e:
        return f"❌ DB Error: {e}"



