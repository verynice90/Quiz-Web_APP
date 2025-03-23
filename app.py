from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import mysql.connector
import pdfkit
from datetime import datetime
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database configuration
db = mysql.connector.connect(
    host="localhost",
    user="", #username
    password="",  # Add your MySQL password
    database="quiz"
)
cursor = db.cursor()

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Admin registration
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        security_code = request.form['security_code']

        if security_code != "203040":
            flash("Invalid security code!")
            return redirect(url_for('admin_register'))

        try:
            cursor.execute("INSERT INTO admins (username, password, security_code) VALUES (%s, %s, %s)", 
                           (username, password, security_code))
            db.commit()
            flash("Admin registered successfully!")
            return redirect(url_for('admin_login'))
        except mysql.connector.Error as err:
            if err.errno == 1062:  # Duplicate entry error code
                flash("Username already exists! Please choose a different username.")
            else:
                flash("An error occurred during registration. Please try again.")
            return redirect(url_for('admin_register'))

    return render_template('admin_register.html')


# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM admins WHERE username = %s AND password = %s", (username, password))
        admin = cursor.fetchone()

        if admin:
            session['admin_id'] = admin[0]
            flash("Logged in successfully!")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

# Admin change password (updated to return JSON)
@app.route('/admin/change_password', methods=['POST'])
def admin_change_password():
    if 'admin_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Verify old password
    cursor.execute("SELECT * FROM admins WHERE id = %s AND password = %s", (session['admin_id'], old_password))
    if not cursor.fetchone():
        return jsonify({"success": False, "message": "Incorrect old password"})

    # Check if new passwords match
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match"})

    # Update password
    cursor.execute("UPDATE admins SET password = %s WHERE id = %s", (new_password, session['admin_id']))
    db.commit()
    return jsonify({"success": True, "message": "Password changed successfully"})

# Admin dashboard with user details
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    # Fetch admin details
    cursor.execute("SELECT admin_name, username FROM admins WHERE id = %s", (session['admin_id'],))
    admin = cursor.fetchone()
    if not admin:
        flash("Admin not found!")
        return redirect(url_for('admin_login'))
    admin_name = admin[0]
    username = admin[1]

    # Fetch questions added by the admin
    cursor.execute("SELECT * FROM questions WHERE added_by_admin = %s", (session['admin_id'],))
    questions = cursor.fetchall()

    # Fetch all questions with admin names and options
    cursor.execute("""
        SELECT q.id, q.question_type, q.question_text, q.option1, q.option2, q.option3, q.option4, q.correct_option, a.admin_name
        FROM questions q
        JOIN admins a ON q.added_by_admin = a.id
    """)
    all_questions = cursor.fetchall()

    # Fetch user details (name, age, username)
    cursor.execute("SELECT name, age, username FROM users")
    users = cursor.fetchall()

    return render_template('admin_dashboard.html', admin_name=admin_name, username=username, questions=questions, all_questions=all_questions, users=users)

# Edit admin profile (updated to return JSON)
@app.route('/admin/edit_profile', methods=['POST'])
def edit_admin_profile():
    if 'admin_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    admin_name = request.form['admin_name']
    username = request.form['username']

    # Check if the new username already exists
    cursor.execute("SELECT * FROM admins WHERE username = %s AND id != %s", (username, session['admin_id']))
    if cursor.fetchone():
        return jsonify({"success": False, "message": "Username already exists! Please choose another."})

    # Update admin details
    cursor.execute("UPDATE admins SET admin_name = %s, username = %s WHERE id = %s",
                   (admin_name, username, session['admin_id']))
    db.commit()
    return jsonify({"success": True, "message": "Profile updated successfully"})

# Add question
@app.route('/admin/add_question', methods=['GET', 'POST'])
def add_question():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        question_type = request.form['question_type']
        question_text = request.form['question_text']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = request.form['correct_option']

        cursor.execute("INSERT INTO questions (question_type, question_text, option1, option2, option3, option4, correct_option, added_by_admin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                       (question_type, question_text, option1, option2, option3, option4, correct_option, session['admin_id']))
        db.commit()
        flash("Question added successfully!")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_question.html')

# Modify question
@app.route('/admin/modify_question/<int:question_id>', methods=['GET', 'POST'])
def modify_question(question_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        question_type = request.form['question_type']
        question_text = request.form['question_text']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = request.form['correct_option']

        cursor.execute("UPDATE questions SET question_type = %s, question_text = %s, option1 = %s, option2 = %s, option3 = %s, option4 = %s, correct_option = %s WHERE id = %s",
                       (question_type, question_text, option1, option2, option3, option4, correct_option, question_id))
        db.commit()
        flash("Question updated successfully!")
        return redirect(url_for('admin_dashboard'))

    cursor.execute("SELECT * FROM questions WHERE id = %s", (question_id,))
    question = cursor.fetchone()
    if not question:
        flash("Question not found!")
        return redirect(url_for('admin_dashboard'))
    return render_template('modify_question.html', question=question)

# Delete question
@app.route('/admin/delete_question/<int:question_id>')
def delete_question(question_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    cursor.execute("DELETE FROM questions WHERE id = %s", (question_id,))
    db.commit()
    flash("Question deleted successfully!")
    return redirect(url_for('admin_dashboard'))

# User registration
@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        age = request.form['age']

        try:
            cursor.execute("INSERT INTO users (username, password, name, age) VALUES (%s, %s, %s, %s)", 
                           (username, password, name, age))
            db.commit()
            flash("User registered successfully!")
            return redirect(url_for('user_login'))
        except mysql.connector.Error as err:
            if err.errno == 1062:  # Duplicate entry error code
                flash("Username already exists! Please choose a different username.")
            else:
                flash("An error occurred during registration. Please try again.")
            return redirect(url_for('user_register'))

    return render_template('user_register.html')


# User login
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()

        if user:
            session['user_id'] = user[0]
            flash("Logged in successfully!")
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('user_login'))

    return render_template('user_login.html')

# User dashboard
@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Fetch user details
    cursor.execute("SELECT name, username FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('user_login'))
    name = user[0]
    username = user[1]

    return render_template('user_dashboard.html', name=name, username=username)

# Edit user profile (updated to return JSON)
@app.route('/user/edit_profile', methods=['POST'])
def edit_profile():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    name = request.form['name']
    username = request.form['username']

    # Check if the new username already exists
    cursor.execute("SELECT * FROM users WHERE username = %s AND id != %s", (username, session['user_id']))
    if cursor.fetchone():
        return jsonify({"success": False, "message": "Username already exists! Please choose another."})

    # Update user details
    cursor.execute("UPDATE users SET name = %s, username = %s WHERE id = %s", (name, username, session['user_id']))
    db.commit()
    return jsonify({"success": True, "message": "Profile updated successfully"})

# Change user password (updated to return JSON)
@app.route('/user/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Verify old password
    cursor.execute("SELECT * FROM users WHERE id = %s AND password = %s", (session['user_id'], old_password))
    if not cursor.fetchone():
        return jsonify({"success": False, "message": "Incorrect old password"})

    # Check if new passwords match
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match"})

    # Update password
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, session['user_id']))
    db.commit()
    return jsonify({"success": True, "message": "Password changed successfully"})

# Take quiz
@app.route('/user/take_quiz', methods=['GET', 'POST'])
def take_quiz():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        question_type = request.form['question_type']
        num_questions = int(request.form['num_questions'])

        cursor.execute("SELECT * FROM questions WHERE question_type = %s ORDER BY RAND() LIMIT %s", (question_type, num_questions))
        questions = cursor.fetchall()
        if not questions:
            
            return redirect(url_for('user_dashboard'))
        flash("No questions found for the selected quiz type!")
        return render_template('quiz.html', questions=questions)

    # No need to render take_quiz.html anymore
    return redirect(url_for('user_dashboard'))

# Submit quiz
@app.route('/user/submit_quiz', methods=['POST'])
def submit_quiz():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    correct_answers = 0
    total_questions = -1

    # Loop through the submitted form data to calculate correct answers
    for key, value in request.form.items():
        if key.startswith('question_'):
            total_questions += 1
            question_id = key.split('_')[1]
            
            # Fetch the correct answer for the question
            cursor.execute("SELECT correct_option FROM questions WHERE id = %s", (question_id,))
            result = cursor.fetchone()
            
            if result is None:
                continue

            correct_option = result[0]
            if int(value) == correct_option:
                correct_answers += 1

    # Insert the quiz result into the database
    cursor.execute(
        "INSERT INTO results (user_id, question_type, total_questions, correct_answers) VALUES (%s, %s, %s, %s)",
        (session['user_id'], request.form['question_type'], total_questions, correct_answers)
    )
    db.commit()

    # Get the ID of the newly inserted result
    result_id = cursor.lastrowid

    # Fetch user details
    cursor.execute("SELECT name FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('user_dashboard'))
    name = user[0]

    # Redirect to the quiz result page with the result_id
    return redirect(url_for('quiz_result', result_id=result_id))
@app.route('/user/quiz_result/<int:result_id>')
def quiz_result(result_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Fetch the quiz result
    cursor.execute("SELECT correct_answers, total_questions FROM results WHERE id = %s AND user_id = %s", (result_id, session['user_id']))
    result = cursor.fetchone()
    if not result:
        flash("Quiz result not found!")
        return redirect(url_for('user_dashboard'))
    correct_answers = result[0]
    total_questions = result[1]

    # Fetch user details
    cursor.execute("SELECT name FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('user_dashboard'))
    name = user[0]

    # Render the quiz result page
    return render_template('quiz_result.html', 
                           correct_answers=correct_answers, 
                           total_questions=total_questions, 
                           name=name, 
                           result_id=result_id)

@app.route('/user/result_history')
def result_history():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Fetch user's quiz results
    cursor.execute("SELECT id, question_type, total_questions, correct_answers, created_at FROM results WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
    results = cursor.fetchall()

    # Render the result history page
    return render_template('result_history.html', results=results)
# Certificate route
@app.route('/user/certificate/<int:result_id>')
def certificate(result_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Fetch user details
    cursor.execute("SELECT name FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('user_dashboard'))
    name = user[0]

    # Fetch the specific quiz result
    cursor.execute("SELECT correct_answers, total_questions FROM results WHERE id = %s AND user_id = %s", (result_id, session['user_id']))
    result = cursor.fetchone()
    if not result:
        flash("Quiz result not found!")
        return redirect(url_for('user_dashboard'))
    correct_answers = result[0]
    total_questions = result[1]

    # Render the certificate page
    return render_template('certificate.html', 
                           name=name, 
                           correct_answers=correct_answers, 
                           total_questions=total_questions, 
                           date=datetime.now().strftime("%Y-%m-%d"))
# Download certificate as HTML
@app.route('/download_certificate')
def download_certificate():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Fetch user details
    cursor.execute("SELECT name FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('user_dashboard'))
    name = user[0]

    # Fetch the latest quiz result
    cursor.execute("SELECT correct_answers, total_questions FROM results WHERE user_id = %s ORDER BY id DESC LIMIT 1", (session['user_id'],))
    result = cursor.fetchone()
    if not result:
        flash("No quiz results found!")
        return redirect(url_for('user_dashboard'))
    correct_answers = result[0]
    total_questions = result[1]

    # Generate certificate HTML
    certificate_html = render_template('certificate.html', 
                                       name=name, 
                                       correct_answers=correct_answers, 
                                       total_questions=total_questions, 
                                       date=datetime.now().strftime("%Y-%m-%d"))

    # Save the certificate as an HTML file
    certificate_filename = f"certificate_{session['user_id']}.html"
    with open(certificate_filename, "w") as file:
        file.write(certificate_html)

    # Send the file for download
    return send_file(certificate_filename, as_attachment=True)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)