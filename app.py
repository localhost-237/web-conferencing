from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'localcast-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///localcast.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    department = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_permissions(self):
        permissions_map = {
            'admin': ['view', 'broadcast', 'moderate', 'admin'],
            'moderator': ['view', 'broadcast', 'moderate'],
            'broadcaster': ['view', 'broadcast'],
            'viewer': ['view']
        }
        return permissions_map.get(self.role, ['view'])

    def has_permission(self, permission):
        return permission in self.get_permissions()

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'department': self.department,
            'permissions': self.get_permissions(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_active': self.last_active.isoformat() if self.last_active else None,
            'status': self.status
        }

class Stream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    broadcaster_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    broadcaster = db.relationship('User', backref=db.backref('streams', lazy=True))
    viewers = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='scheduled')  # live, scheduled, ended
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))
    quality = db.Column(db.String(10), default='720p')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'broadcaster': self.broadcaster.full_name,
            'viewers': self.viewers,
            'status': self.status,
            'start_time': self.start_time.isoformat(),
            'category': self.category,
            'quality': self.quality
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Permission decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize database and create demo users
def init_db():
    with app.app_context():
        db.create_all()

        # Create demo users if they don't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@localcast.local',
                full_name='System Administrator',
                role='admin',
                department='IT'
            )
            admin.set_password('admin123')
            db.session.add(admin)

            teacher = User(
                username='teacher',
                email='teacher@localcast.local',
                full_name='Sarah Johnson',
                role='broadcaster',
                department='Mathematics'
            )
            teacher.set_password('teacher123')
            db.session.add(teacher)

            student = User(
                username='student',
                email='student@localcast.local',
                full_name='John Smith',
                role='viewer',
                department='Mathematics'
            )
            student.set_password('student123')
            db.session.add(student)

            moderator = User(
                username='moderator',
                email='moderator@localcast.local',
                full_name='Mike Chen',
                role='moderator',
                department='IT'
            )
            moderator.set_password('mod123')
            db.session.add(moderator)

            db.session.commit()
            print("Demo users created successfully!")

        # Create demo streams
        if not Stream.query.first():
            admin_user = User.query.filter_by(username='admin').first()
            teacher_user = User.query.filter_by(username='teacher').first()

            stream1 = Stream(
                title='Mathematics Lecture - Calculus Basics',
                description='Introduction to differential calculus for beginners',
                broadcaster_id=teacher_user.id,
                viewers=45,
                status='live',
                category='Education',
                quality='720p'
            )

            stream2 = Stream(
                title='Community Health Workshop',
                description='Essential health practices and emergency preparedness',
                broadcaster_id=admin_user.id,
                viewers=23,
                status='live',
                category='Health',
                quality='480p'
            )

            stream3 = Stream(
                title='Local News Update',
                description='Daily community announcements and updates',
                broadcaster_id=admin_user.id,
                viewers=0,
                status='scheduled',
                category='News',
                quality='720p'
            )

            db.session.add_all([stream1, stream2, stream3])
            db.session.commit()
            print("Demo streams created successfully!")

# Routes
@app.route('/')
@login_required
def dashboard():
    streams = Stream.query.all()
    live_streams = Stream.query.filter_by(status='live').count()
    total_viewers = sum(stream.viewers for stream in streams)

    return render_template('dashboard.html',
                         streams=streams,
                         live_streams=live_streams,
                         total_viewers=total_viewers,
                         user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        remember_me = data.get('rememberMe', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.status == 'active':
            login_user(user, remember=remember_me)
            user.last_active = datetime.utcnow()
            db.session.commit()

            # Generate JWT token
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'permissions': user.get_permissions(),
                'exp': datetime.utcnow() + timedelta(days=30 if remember_me else 1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'success': True,
                'user': user.to_dict(),
                'token': token,
                'message': 'Login successful'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401

    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check if username or email already exists
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'success': False, 'error': 'Username already exists'}), 409

    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'error': 'Email already exists'}), 409

    user = User(
        username=data.get('username'),
        email=data.get('email'),
        full_name=data.get('fullName'),
        role=data.get('role', 'viewer'),
        department=data.get('department', '')
    )
    user.set_password(data.get('password'))

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'user': user.to_dict(),
        'message': 'Registration successful'
    })

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/streams', methods=['GET', 'POST'])
@login_required
def streams_api():
    if request.method == 'GET':
        streams = Stream.query.all()
        return jsonify({
            'success': True,
            'streams': [stream.to_dict() for stream in streams]
        })

    elif request.method == 'POST':
        data = request.get_json()
        action = data.get('action')

        if action == 'create':
            if not current_user.has_permission('broadcast'):
                return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

            stream_data = data.get('streamData')
            stream = Stream(
                title=stream_data.get('title'),
                description=stream_data.get('description'),
                broadcaster_id=current_user.id,
                category=stream_data.get('category'),
                quality=stream_data.get('quality', '720p'),
                status='live'
            )

            db.session.add(stream)
            db.session.commit()

            return jsonify({
                'success': True,
                'stream': stream.to_dict()
            })

        elif action == 'join':
            stream_id = data.get('streamId')
            stream = Stream.query.get(stream_id)
            if stream:
                stream.viewers += 1
                db.session.commit()
                return jsonify({
                    'success': True,
                    'stream': stream.to_dict()
                })
            return jsonify({'success': False, 'error': 'Stream not found'}), 404

        elif action == 'leave':
            stream_id = data.get('streamId')
            stream = Stream.query.get(stream_id)
            if stream:
                stream.viewers = max(0, stream.viewers - 1)
                db.session.commit()
                return jsonify({
                    'success': True,
                    'stream': stream.to_dict()
                })
            return jsonify({'success': False, 'error': 'Stream not found'}), 404

        elif action == 'end':
            stream_id = data.get('streamId')
            stream = Stream.query.get(stream_id)
            if stream and stream.broadcaster_id == current_user.id:
                stream.status = 'ended'
                db.session.commit()
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

@app.route('/api/users')
@permission_required('admin')
def users_api():
    users = User.query.all()
    return jsonify({
        'success': True,
        'users': [user.to_dict() for user in users]
    })

@app.route('/api/users', methods=['POST'])
@permission_required('admin')
def create_user():
    data = request.get_json()

    # Check if username or email already exists
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'success': False, 'error': 'Username already exists'}), 409

    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'error': 'Email already exists'}), 409

    user = User(
        username=data.get('username'),
        email=data.get('email'),
        full_name=data.get('fullName'),
        role=data.get('role', 'viewer'),
        department=data.get('department', '')
    )
    user.set_password(data.get('password'))

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'user': user.to_dict()
    })

@app.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@permission_required('admin')
def manage_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.full_name = data.get('fullName', user.full_name)
        user.role = data.get('role', user.role)
        user.department = data.get('department', user.department)

        if data.get('password'):
            user.set_password(data.get('password'))

        db.session.commit()
        return jsonify({
            'success': True,
            'user': user.to_dict()
        })

    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/network/status')
@login_required
def network_status():
    return jsonify({
        'connected': True,
        'localIP': '192.168.1.100',
        'networkName': 'LocalCast-Network',
        'connectedDevices': 68
    })

@app.route('/api/network/devices')
@permission_required('admin')
def network_devices():
    devices = [
        {'name': 'Classroom PC-01', 'ip': '192.168.1.101', 'type': 'desktop', 'status': 'active'},
        {'name': 'Teacher Laptop', 'ip': '192.168.1.102', 'type': 'laptop', 'status': 'active'},
        {'name': 'Student Tablet-15', 'ip': '192.168.1.115', 'type': 'tablet', 'status': 'viewing'},
        {'name': 'Mobile Device', 'ip': '192.168.1.120', 'type': 'mobile', 'status': 'idle'},
        {'name': 'Projector System', 'ip': '192.168.1.105', 'type': 'display', 'status': 'active'},
    ]
    return jsonify({'devices': devices})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    print("🎥 LocalCast Platform Starting...")
    print("📡 Private Network Multimedia Broadcasting System")
    print("🔐 Authentication: Enabled")
    print("👥 Demo Accounts:")
    print("   Admin: admin/admin123")
    print("   Broadcaster: teacher/teacher123")
    print("   Viewer: student/student123")
    print("   Moderator: moderator/mod123")
    print("🌐 Server running on http://localhost:5000")

    app.run(debug=True, host='0.0.0.0', port=5000)
