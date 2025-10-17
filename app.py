
# # from flask import Flask, render_template, request, redirect, url_for, flash, session
# # from flask_sqlalchemy import SQLAlchemy
# # from werkzeug.security import generate_password_hash, check_password_hash
# # from functools import wraps

# # app = Flask(__name__)
# # app.config['SECRET_KEY'] = 'your-secret-key' # IMPORTANT: Change this to a strong, unique secret key
# # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polling.db'
# # app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# # db = SQLAlchemy(app)

# # class User(db.Model):
# #     id = db.Column(db.Integer, primary_key=True)
# #     username = db.Column(db.String(80), unique=True, nullable=False)
# #     password_hash = db.Column(db.String(128), nullable=False)

# #     def set_password(self, password):
# #         self.password_hash = generate_password_hash(password)

# #     def check_password(self, password):
# #         return check_password_hash(self.password_hash, password)

# # class Poll(db.Model):
# #     id = db.Column(db.Integer, primary_key=True)
# #     question = db.Column(db.String(255), nullable=False)
# #     creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
# #     options = db.relationship('Option', backref='poll', lazy=True, cascade='all, delete-orphan')

# # class Option(db.Model):
# #     id = db.Column(db.Integer, primary_key=True)
# #     option_text = db.Column(db.String(255), nullable=False)
# #     agenda = db.Column(db.Text, nullable=True)
# #     poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
# #     votes = db.relationship('Vote', backref='option', lazy=True, cascade='all, delete-orphan')

# # class Vote(db.Model):
# #     id = db.Column(db.Integer, primary_key=True)
# #     voter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
# #     poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
# #     option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
# #     __table_args__ = (db.UniqueConstraint('voter_id', 'poll_id', name='_voter_poll_uc'),)


# # def login_required(f):
# #     @wraps(f)
# #     def decorated_function(*args, **kwargs):
# #         if 'user_id' not in session:
# #             flash('Please log in first.')
# #             return redirect(url_for('login'))
# #         return f(*args, **kwargs)
# #     return decorated_function

# # def get_current_user():
# #     if 'user_id' in session:
# #         return User.query.get(session['user_id'])
# #     return None

# # @app.route('/')
# # def index():
# #     return redirect(url_for('dashboard'))

# # @app.route('/register', methods=['GET','POST'])
# # def register():
# #     if request.method == 'POST':
# #         username = request.form['username'].strip()
# #         password = request.form['password']
# #         if not username or not password:
# #             flash('Username and password required.')
# #             return redirect(url_for('register'))
# #         if User.query.filter_by(username=username).first():
# #             flash('Username already taken.')
# #             return redirect(url_for('register'))
# #         user = User(username=username)
# #         user.set_password(password)
# #         db.session.add(user)
# #         db.session.commit()
# #         flash('Registration successful! Please log in.')
# #         return redirect(url_for('login'))
# #     return render_template('register.html')

# # @app.route('/login', methods=['GET','POST'])
# # def login():
# #     if request.method == 'POST':
# #         username = request.form['username'].strip()
# #         password = request.form['password']
# #         user = User.query.filter_by(username=username).first()
# #         if user and user.check_password(password):
# #             session['user_id'] = user.id
# #             flash(f'Welcome, {user.username}!')
# #             return redirect(url_for('dashboard'))
# #         flash('Invalid username or password.')
# #         return redirect(url_for('login')) # Redirect on failed login too
# #     return render_template('login.html')

# # @app.route('/logout')
# # @login_required
# # def logout():
# #     session.clear()
# #     flash('Logged out successfully.')
# #     return redirect(url_for('login'))

# # @app.route('/dashboard')
# # @login_required
# # def dashboard():
# #     user = get_current_user()
# #     if not user: # Should not happen with @login_required but good for safety
# #         flash('Session expired, please log in again.')
# #         return redirect(url_for('login'))
    
# #     polls = Poll.query.all()
# #     # Fetch existing votes for the current user to display on dashboard
# #     user_votes = {vote.poll_id for vote in Vote.query.filter_by(voter_id=user.id).all()}
    
# #     return render_template('dashboard.html', polls=polls, user=user, user_votes=user_votes)

# # @app.route('/create_poll', methods=['GET','POST'])
# # @login_required
# # def create_poll():
# #     if request.method == 'POST':
# #         question = request.form['question'].strip()
# #         options = request.form.getlist('options')
# #         agendas = request.form.getlist('agendas')
        
# #         # Filter out empty options before validating count
# #         valid_options_count = len([opt for opt in options if opt.strip()])
        
# #         if not question:
# #             flash('Please enter a question for the poll.')
# #             return redirect(url_for('create_poll'))
        
# #         if valid_options_count < 2:
# #             flash('Please enter at least two options for the poll.')
# #             return redirect(url_for('create_poll'))

# #         user = get_current_user()
# #         poll = Poll(question=question, creator_id=user.id)
# #         db.session.add(poll)
# #         db.session.commit() # Commit to get poll.id for options

# #         for opt_text, agenda_text in zip(options, agendas):
# #             if opt_text.strip(): # Only add non-empty options
# #                 option = Option(option_text=opt_text.strip(), agenda=agenda_text.strip(), poll=poll)
# #                 db.session.add(option)
# #         db.session.commit()
# #         flash('Poll created successfully!')
# #         return redirect(url_for('dashboard'))
# #     return render_template('create_poll.html')

# # @app.route('/poll/<int:poll_id>', methods=['GET','POST'])
# # @login_required
# # def view_poll(poll_id):
# #     poll = Poll.query.get_or_404(poll_id)
# #     user = get_current_user()
    
# #     # Check if the user has already voted in this poll
# #     existing_vote = Vote.query.filter_by(poll_id=poll.id, voter_id=user.id).first()

# #     # Calculate total votes for display
# #     total_votes = db.session.query(Vote).filter_by(poll_id=poll.id).count()

# #     if request.method == 'POST':
# #         if existing_vote:
# #             flash('You have already voted in this poll.')
# #             # Redirect to GET request to show results immediately without re-processing POST
# #             return redirect(url_for('view_poll', poll_id=poll.id))
            
# #         selected_option_id = request.form.get('option')
# #         if not selected_option_id:
# #             flash('Please select an option to vote.')
# #             return redirect(url_for('view_poll', poll_id=poll.id))
        
# #         # Ensure the selected option belongs to this poll
# #         option = Option.query.filter_by(id=selected_option_id, poll_id=poll.id).first()
# #         if not option:
# #             flash('Invalid option selected.')
# #             return redirect(url_for('view_poll', poll_id=poll.id))
        
# #         vote = Vote(voter_id=user.id, poll_id=poll.id, option_id=option.id)
# #         db.session.add(vote)
# #         db.session.commit()
# #         flash('Your vote has been recorded!')
# #         return redirect(url_for('view_poll', poll_id=poll.id)) # Redirect to GET to show updated state/results

# #     return render_template('view_poll.html', poll=poll, existing_vote=existing_vote,
# #                             total_votes=total_votes)


# # @app.route('/delete_poll/<int:poll_id>', methods=['POST'])
# # @login_required
# # def delete_poll(poll_id):
# #     poll = Poll.query.get_or_404(poll_id)
# #     user = get_current_user()

# #     if poll.creator_id != user.id:
# #         flash('You are not authorized to delete this poll.')
# #         return redirect(url_for('dashboard'))
    
# #     db.session.delete(poll)
# #     db.session.commit()
# #     flash('Poll deleted successfully!')
# #     return redirect(url_for('dashboard'))

# # # --- NEW ADMIN ROUTE ADDED HERE ---
# # @app.route('/admin')
# # @login_required
# # def admin_panel():
# #     user = get_current_user()
# #     # You can restrict admin view to a specific user (like 'admin')
# #     if user.username != 'admin':
# #         flash('Access denied. Admins only.')
# #         return redirect(url_for('dashboard'))

# #     polls_data = []
# #     polls = Poll.query.all()
# #     for poll in polls:
# #         poll_info = {
# #             'question': poll.question,
# #             'options': []
# #         }
# #         total_votes = Vote.query.filter_by(poll_id=poll.id).count()
# #         poll_info['total_votes'] = total_votes
# #         for option in poll.options:
# #             votes = Vote.query.filter_by(option_id=option.id).all()
# #             voters = [User.query.get(v.voter_id).username for v in votes]
# #             poll_info['options'].append({
# #                 'option_text': option.option_text,
# #                 'agenda': option.agenda,
# #                 'voters': voters
# #             })
# #         polls_data.append(poll_info)
# #     return render_template('admin.html', polls=polls_data)
# # # --- END OF NEW ADMIN ROUTE ---


# # if __name__ == '__main__':
# #     with app.app_context():
# #         db.create_all()
# #     app.run(debug=True)



















# from flask import Flask, render_template, request, redirect, url_for, flash, session
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
# from functools import wraps

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your-secret-key'  # IMPORTANT: Change this to a strong, unique secret key
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polling.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)


# # =====================
# # DATABASE MODELS
# # =====================
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password_hash = db.Column(db.String(128), nullable=False)

#     def set_password(self, password):
#         self.password_hash = generate_password_hash(password)

#     def check_password(self, password):
#         return check_password_hash(self.password_hash, password)


# class Poll(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     question = db.Column(db.String(255), nullable=False)
#     creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     options = db.relationship('Option', backref='poll', lazy=True, cascade='all, delete-orphan')


# class Option(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     option_text = db.Column(db.String(255), nullable=False)
#     agenda = db.Column(db.Text, nullable=True)
#     poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
#     votes = db.relationship('Vote', backref='option', lazy=True, cascade='all, delete-orphan')


# class Vote(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     voter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
#     option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
#     __table_args__ = (db.UniqueConstraint('voter_id', 'poll_id', name='_voter_poll_uc'),)


# # =====================
# # HELPERS
# # =====================
# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             flash('Please log in first.')
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#     return decorated_function


# def get_current_user():
#     if 'user_id' in session:
#         return User.query.get(session['user_id'])
#     return None


# # =====================
# # ROUTES
# # =====================

# @app.route('/')
# def index():
#     return redirect(url_for('dashboard'))


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username'].strip()
#         password = request.form['password']
#         if not username or not password:
#             flash('Username and password required.')
#             return redirect(url_for('register'))

#         if User.query.filter_by(username=username).first():
#             flash('Username already exists.')
#             return redirect(url_for('register'))

#         new_user = User(username=username)
#         new_user.set_password(password)
#         db.session.add(new_user)
#         db.session.commit()
#         flash('Registration successful! Please log in.')
#         return redirect(url_for('login'))
#     return render_template('register.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username'].strip()
#         password = request.form['password']
#         user = User.query.filter_by(username=username).first()

#         if user and user.check_password(password):
#             session['user_id'] = user.id
#             flash('Login successful!')
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Invalid username or password.')
#             return redirect(url_for('login'))
#     return render_template('login.html')


# @app.route('/logout')
# def logout():
#     session.pop('user_id', None)
#     flash('Logged out successfully.')
#     return redirect(url_for('login'))


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     user = get_current_user()
#     polls = Poll.query.all()
#     user_votes = {vote.poll_id for vote in Vote.query.filter_by(voter_id=user.id).all()}
#     return render_template('dashboard.html', user=user, polls=polls, user_votes=user_votes)


# @app.route('/create_poll', methods=['GET', 'POST'])
# @login_required
# def create_poll():
#     if request.method == 'POST':
#         question = request.form['question'].strip()
#         options = request.form.getlist('options')
#         agendas = request.form.getlist('agendas')

#         if not question or len(options) < 2:
#             flash('Please provide a question and at least two options.')
#             return redirect(url_for('create_poll'))

#         user = get_current_user()
#         new_poll = Poll(question=question, creator_id=user.id)
#         db.session.add(new_poll)
#         db.session.commit()

#         for opt_text, agenda_text in zip(options, agendas):
#             if opt_text.strip():
#                 new_option = Option(option_text=opt_text.strip(), agenda=agenda_text.strip(), poll_id=new_poll.id)
#                 db.session.add(new_option)

#         db.session.commit()
#         flash('Poll created successfully!')
#         return redirect(url_for('dashboard'))

#     return render_template('create_poll.html')


# @app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
# @login_required
# def view_poll(poll_id):
#     poll = Poll.query.get_or_404(poll_id)
#     user = get_current_user()
#     existing_vote = Vote.query.filter_by(voter_id=user.id, poll_id=poll.id).first()
#     total_votes = Vote.query.filter_by(poll_id=poll.id).count()

#     if request.method == 'POST':
#         if existing_vote:
#             flash('You have already voted on this poll.')
#             return redirect(url_for('view_poll', poll_id=poll.id))

#         selected_option_id = request.form.get('option')
#         if not selected_option_id:
#             flash('Please select an option before voting.')
#             return redirect(url_for('view_poll', poll_id=poll.id))

#         vote = Vote(voter_id=user.id, poll_id=poll.id, option_id=int(selected_option_id))
#         db.session.add(vote)
#         db.session.commit()
#         flash('Vote recorded successfully!')
#         return redirect(url_for('view_poll', poll_id=poll.id))

#     return render_template('view_poll.html', poll=poll, existing_vote=existing_vote, total_votes=total_votes)


# @app.route('/delete_poll/<int:poll_id>', methods=['POST'])
# @login_required
# def delete_poll(poll_id):
#     poll = Poll.query.get_or_404(poll_id)
#     user = get_current_user()

#     if poll.creator_id != user.id:
#         flash('You are not authorized to delete this poll.')
#         return redirect(url_for('dashboard'))

#     db.session.delete(poll)
#     db.session.commit()
#     flash('Poll deleted successfully.')
#     return redirect(url_for('dashboard'))


# # =====================
# # RUN APP
# # =====================
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)



from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # IMPORTANT: Change this to a strong, unique secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polling.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------------- MODELS -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    options = db.relationship('Option', backref='poll', lazy=True, cascade='all, delete-orphan')

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.String(255), nullable=False)
    agenda = db.Column(db.Text, nullable=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy=True, cascade='all, delete-orphan')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('voter_id', 'poll_id', name='_voter_poll_uc'),)

# ----------------------- HELPERS -----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# ----------------------- ROUTES -----------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken.')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash(f'Welcome, {user.username}!')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    polls = Poll.query.all()
    user_votes = {vote.poll_id for vote in Vote.query.filter_by(voter_id=user.id).all()}
    return render_template('dashboard.html', polls=polls, user=user, user_votes=user_votes)

@app.route('/create_poll', methods=['GET','POST'])
@login_required
def create_poll():
    if request.method == 'POST':
        question = request.form['question'].strip()
        options = request.form.getlist('options')
        agendas = request.form.getlist('agendas')

        valid_options_count = len([opt for opt in options if opt.strip()])
        if not question:
            flash('Please enter a question for the poll.')
            return redirect(url_for('create_poll'))
        if valid_options_count < 2:
            flash('Please enter at least two options for the poll.')
            return redirect(url_for('create_poll'))

        user = get_current_user()
        poll = Poll(question=question, creator_id=user.id)
        db.session.add(poll)
        db.session.commit()

        for opt_text, agenda_text in zip(options, agendas):
            if opt_text.strip():
                option = Option(option_text=opt_text.strip(), agenda=agenda_text.strip(), poll=poll)
                db.session.add(option)
        db.session.commit()
        flash('Poll created successfully!')
        return redirect(url_for('dashboard'))
    return render_template('create_poll.html')

@app.route('/poll/<int:poll_id>', methods=['GET','POST'])
@login_required
def view_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    user = get_current_user()
    existing_vote = Vote.query.filter_by(poll_id=poll.id, voter_id=user.id).first()
    total_votes = db.session.query(Vote).filter_by(poll_id=poll.id).count()

    if request.method == 'POST':
        if existing_vote:
            flash('You have already voted in this poll.')
            return redirect(url_for('view_poll', poll_id=poll.id))
        selected_option_id = request.form.get('option')
        if not selected_option_id:
            flash('Please select an option to vote.')
            return redirect(url_for('view_poll', poll_id=poll.id))
        option = Option.query.filter_by(id=selected_option_id, poll_id=poll.id).first()
        if not option:
            flash('Invalid option selected.')
            return redirect(url_for('view_poll', poll_id=poll.id))
        vote = Vote(voter_id=user.id, poll_id=poll.id, option_id=option.id)
        db.session.add(vote)
        db.session.commit()
        flash('Your vote has been recorded!')
        return redirect(url_for('view_poll', poll_id=poll.id))

    return render_template('view_poll.html', poll=poll, existing_vote=existing_vote, total_votes=total_votes)

@app.route('/delete_poll/<int:poll_id>', methods=['POST'])
@login_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    user = get_current_user()
    if poll.creator_id != user.id:
        flash('You are not authorized to delete this poll.')
        return redirect(url_for('dashboard'))
    db.session.delete(poll)
    db.session.commit()
    flash('Poll deleted successfully!')
    return redirect(url_for('dashboard'))

# ----------------------- ADMIN DASHBOARD -----------------------
# @app.route('/admin_dashboard')
# @login_required
# def admin_dashboard():
#     user = get_current_user()
#     if user.username != 'admin':
#         flash('Access denied. Admins only.')
#         return redirect(url_for('dashboard'))

#     polls_data = []
#     polls = Poll.query.all()
#     for poll in polls:
#         poll_info = {
#             'id': poll.id,
#             'question': poll.question,
#             'total_votes': Vote.query.filter_by(poll_id=poll.id).count(),
#             'options': []
#         }
#         for option in poll.options:
#             votes = Vote.query.filter_by(option_id=option.id).all()
#             voters = [User.query.get(v.voter_id).username for v in votes]
#             poll_info['options'].append({
#                 'option_text': option.option_text,
#                 'agenda': option.agenda,
#                 'vote_count': len(voters),
#                 'voters': voters
#             })
#         polls_data.append(poll_info)

#     return render_template('admin_dashboard.html', polls=polls_data)
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    user = get_current_user()
    if user.username != 'admin':
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))

    polls_data = []
    polls = Poll.query.all()
    for poll in polls:
        poll_info = {
            'id': poll.id,
            'question': poll.question,
            'total_votes': Vote.query.filter_by(poll_id=poll.id).count(),
            'options': []
        }
        for option in poll.options:
            votes = Vote.query.filter_by(option_id=option.id).all()
            voters = [User.query.get(v.voter_id).username for v in votes]  # list of usernames
            poll_info['options'].append({
                'option_text': option.option_text,
                'agenda': option.agenda,
                'vote_count': len(voters),
                'voters': voters
            })
        polls_data.append(poll_info)

    return render_template('admin_dashboard.html', polls=polls_data)


# ----------------------- INITIALIZE DB & ADMIN -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables exist

        # Check if admin exists, if not, create one
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin123')  # <-- Set your admin password here
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with username 'admin' and password 'admin123'")
        else:
            print("Admin user already exists.")

    app.run(debug=True)
