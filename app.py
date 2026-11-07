from flask import Flask, request, redirect, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
from html import escape
import os
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

db = SQLAlchemy(app)

PRIVATE_FOLDER = os.path.join(app.instance_path, "private_uploads")
os.makedirs(PRIVATE_FOLDER, exist_ok=True)


# -------------------- DATABASE TABLES --------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="viewer")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    access_type = db.Column(db.String(10), nullable=False)

    __table_args__ = (db.UniqueConstraint("document_id", "user_id"),)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True)
    document_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500))
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    previous_hash = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64), nullable=False)


# -------------------- AUDIT LOG --------------------

def record_audit(action, details, status, document_id=None):
    previous = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = previous.entry_hash if previous else "GENESIS"

    actor_id = session.get("user_id")
    timestamp = datetime.utcnow()

    data = (
        str(actor_id) + str(document_id) + action + details + status
        + timestamp.isoformat() + previous_hash
    )
    entry_hash = hashlib.sha256(data.encode()).hexdigest()

    log = AuditLog(
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        details=details,
        status=status,
        timestamp=timestamp,
        previous_hash=previous_hash,
        entry_hash=entry_hash
    )
    db.session.add(log)
    db.session.commit()


# -------------------- LOGIN AND ADMIN ACCESS --------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return function(*args, **kwargs)
    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        current_user = db.session.get(User, session.get("user_id"))
        if not current_user or current_user.role != "admin":
            return "Access denied! Admin privileges required.", 403
        return function(*args, **kwargs)
    return wrapper


def ensure_initial_admin():
    """Make the earliest existing account admin if no admin exists yet."""
    if User.query.filter_by(role="admin").first() is None:
        first_user = User.query.order_by(User.id.asc()).first()
        if first_user:
            first_user.role = "admin"
            db.session.commit()
            print("TrustVault initial admin account:", first_user.username)


# -------------------- HOME --------------------

@app.route("/")
def home():
    return """
    <h1>TrustVault</h1>
    <h3>Secure Document Sharing System</h3>
    <a href="/register">Register</a><br><br>
    <a href="/login">Login</a>
    """


# -------------------- REGISTRATION --------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required!", 400

        if User.query.filter_by(username=username).first():
            return "Username already exists!", 409

        user = User(
            username=username,
            password=generate_password_hash(password),
            role="viewer"
        )
        db.session.add(user)
        db.session.commit()
        return "Registration successful! <a href='/login'>Login</a>"

    return """
    <h2>Register</h2>
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <br><br>
        <input name="password" type="password" placeholder="Password" required>
        <br><br>
        <button>Register</button>
    </form>
    """


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            record_audit("LOGIN", "User logged in", "SUCCESS")
            return redirect("/dashboard")

        record_audit("LOGIN", "Invalid login attempt", "DENIED")
        return "Invalid username or password!", 401

    return """
    <h2>TrustVault Login</h2>
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <br><br>
        <input name="password" type="password" placeholder="Password" required>
        <br><br>
        <button>Login</button>
    </form>
    """


# -------------------- USER DASHBOARD --------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        return redirect("/login")

    admin_link = "<a href='/admin'>Admin Dashboard</a><br><br>" if user.role == "admin" else ""
    return f"""
    <h1>Welcome {escape(user.username)}!</h1>
    <h3>TrustVault Dashboard</h3>
    <p>Your role: {escape(user.role)}</p>
    {admin_link}
    <a href="/upload">Upload Document</a><br><br>
    <a href="/documents">My Documents</a><br><br>
    <a href="/shared">Shared With Me</a><br><br>
    <a href="/audit">Audit Trail</a><br><br>
    <a href="/logout">Logout</a>
    """


# -------------------- ADMIN DASHBOARD --------------------

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.id.asc()).all()
    documents = Document.query.order_by(Document.uploaded_at.desc()).limit(50).all()
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(50).all()
    user_names = {user.id: user.username for user in users}

    user_rows = "".join(
        "<tr>"
        f"<td>{user.id}</td>"
        f"<td>{escape(user.username)}</td>"
        f"<td>{escape(user.role)}</td>"
        f"<td>{escape(str(user.created_at))}</td>"
        "</tr>"
        for user in users
    ) or "<tr><td colspan='4'>No users found</td></tr>"

    document_rows = "".join(
        "<tr>"
        f"<td>{doc.id}</td>"
        f"<td>{escape(doc.original_name)}</td>"
        f"<td>{escape(user_names.get(doc.owner_id, 'Unknown user'))}</td>"
        f"<td>{escape(str(doc.uploaded_at))}</td>"
        "</tr>"
        for doc in documents
    ) or "<tr><td colspan='4'>No documents found</td></tr>"

    log_rows = "".join(
        "<tr>"
        f"<td>{log.id}</td>"
        f"<td>{escape(user_names.get(log.actor_id, 'Unknown/Guest'))}</td>"
        f"<td>{escape(log.action)}</td>"
        f"<td>{escape(log.status)}</td>"
        f"<td>{escape(log.details or '')}</td>"
        f"<td>{escape(str(log.timestamp))}</td>"
        "</tr>"
        for log in logs
    ) or "<tr><td colspan='6'>No audit activity found</td></tr>"

    return f"""
    <h1>TrustVault Admin Dashboard</h1>
    <p><b>Total users:</b> {len(users)}</p>
    <p><b>Total documents:</b> {Document.query.count()}</p>
    <p><b>Audit entries:</b> {AuditLog.query.count()}</p>

    <h2>Registered Users</h2>
    <table border="1" cellpadding="7">
        <tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th></tr>
        {user_rows}
    </table>

    <h2>Recent Documents (maximum 50)</h2>
    <table border="1" cellpadding="7">
        <tr><th>ID</th><th>Document</th><th>Owner</th><th>Uploaded</th></tr>
        {document_rows}
    </table>

    <h2>Recent Audit Activity (maximum 50)</h2>
    <table border="1" cellpadding="7">
        <tr><th>Log ID</th><th>User</th><th>Action</th><th>Status</th><th>Details</th><th>Time</th></tr>
        {log_rows}
    </table>
    <br><a href="/dashboard">Back to Dashboard</a>
    """


# -------------------- UPLOAD DOCUMENT --------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("document")

        if not file or not file.filename:
            return "Please select a file!", 400

        filename = secure_filename(file.filename)
        if not filename or not filename.lower().endswith(".pdf"):
            return "Only PDF files are allowed!", 400

        if file.read(5) != b"%PDF-":
            return "Invalid PDF file!", 400

        file.seek(0)
        stored_name = str(uuid.uuid4()) + ".pdf"
        file.save(os.path.join(PRIVATE_FOLDER, stored_name))

        document = Document(
            original_name=filename,
            stored_name=stored_name,
            owner_id=session["user_id"]
        )
        db.session.add(document)
        db.session.commit()

        record_audit("UPLOAD", "Document uploaded: " + filename,
                     "SUCCESS", document.id)
        return "Document uploaded successfully! <a href='/documents'>View Documents</a>"

    return """
    <h2>Upload Document</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="document" accept=".pdf" required>
        <br><br>
        <button>Upload</button>
    </form>
    """


# -------------------- MY DOCUMENTS --------------------

@app.route("/documents")
@login_required
def documents():
    files = Document.query.filter_by(owner_id=session["user_id"]).all()
    result = "<h2>My Documents</h2>"

    for file in files:
        result += f"""
        <p>
        {escape(file.original_name)}
        <a href="/download/{file.id}">Download</a>
        <a href="/share/{file.id}">Share</a>
        <form method="POST" action="/revoke/{file.id}" style="display:inline">
            <button type="submit">Revoke All Access</button>
        </form>
        </p><hr>
        """

    result += "<a href='/dashboard'>Back to Dashboard</a>"
    return result


# -------------------- SHARE DOCUMENT --------------------

@app.route("/share/<int:document_id>", methods=["GET", "POST"])
@login_required
def share(document_id):
    document = db.get_or_404(Document, document_id)

    if document.owner_id != session["user_id"]:
        record_audit("SHARE", "Unauthorized sharing attempt", "DENIED", document.id)
        return "Access denied!", 403

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = User.query.filter_by(username=username).first()

        if not user:
            return "User not found!", 404
        if user.id == document.owner_id:
            return "You already own this document!", 400

        permission = Permission.query.filter_by(
            document_id=document.id,
            user_id=user.id
        ).first()

        if permission:
            permission.access_type = "read"
        else:
            permission = Permission(
                document_id=document.id,
                user_id=user.id,
                access_type="read"
            )
            db.session.add(permission)

        db.session.commit()
        record_audit("SHARE", "Document shared with " + username,
                     "SUCCESS", document.id)
        return "Document shared successfully! <a href='/documents'>Back</a>"

    return """
    <h2>Share Document</h2>
    <form method="POST">
        <input name="username" placeholder="Enter username" required>
        <br><br>
        <p>Permission: Read Only</p>
        <button>Share</button>
    </form>
    """


# -------------------- REVOKE ACCESS --------------------

@app.route("/revoke/<int:document_id>", methods=["POST"])
@login_required
def revoke(document_id):
    document = db.get_or_404(Document, document_id)

    if document.owner_id != session["user_id"]:
        record_audit("REVOKE", "Unauthorized revoke attempt", "DENIED", document.id)
        return "Access denied!", 403

    permissions = Permission.query.filter_by(document_id=document.id).all()
    for permission in permissions:
        db.session.delete(permission)

    db.session.commit()
    record_audit("REVOKE", "All shared permissions removed", "SUCCESS", document.id)
    return "All shared access revoked! <a href='/documents'>Back to Documents</a>"


# -------------------- SHARED WITH ME --------------------

@app.route("/shared")
@login_required
def shared():
    permissions = Permission.query.filter_by(user_id=session["user_id"]).all()
    result = "<h2>Documents Shared With Me</h2>"

    for permission in permissions:
        document = db.session.get(Document, permission.document_id)
        if document:
            result += f"""
            <p>{escape(document.original_name)}
            - Permission: {escape(permission.access_type)}
            <a href="/download/{document.id}">Download</a></p><hr>
            """

    result += "<a href='/dashboard'>Back</a>"
    return result


# -------------------- SECURE DOWNLOAD --------------------

@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    document = db.get_or_404(Document, document_id)
    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=session["user_id"]
    ).first()

    allowed = document.owner_id == session["user_id"] or permission is not None

    if not allowed:
        record_audit("DOWNLOAD", "Unauthorized download attempt", "DENIED", document.id)
        return "Access denied!", 403

    path = os.path.join(PRIVATE_FOLDER, document.stored_name)
    if not os.path.isfile(path):
        return "Document file not found!", 404

    record_audit("DOWNLOAD", "Document downloaded", "SUCCESS", document.id)
    return send_file(path, as_attachment=True, download_name=document.original_name)


# -------------------- AUDIT TRAIL --------------------

@app.route("/audit")
@login_required
def audit():
    owned_ids = [
        doc.id for doc in Document.query.filter_by(owner_id=session["user_id"]).all()
    ]

    logs = AuditLog.query.filter(
        db.or_(
            AuditLog.actor_id == session["user_id"],
            AuditLog.document_id.in_(owned_ids) if owned_ids else False
        )
    ).order_by(AuditLog.id.desc()).all()

    result = "<h2>TrustVault Audit Trail</h2>"
    for log in logs:
        result += f"""
        <p>
        Time: {escape(str(log.timestamp))}<br>
        Action: {escape(log.action)}<br>
        Status: {escape(log.status)}<br>
        Details: {escape(log.details or '')}<br>
        Hash: {escape(log.entry_hash)}
        </p><hr>
        """

    result += "<a href='/dashboard'>Back to Dashboard</a>"
    return result


# -------------------- LOGOUT --------------------

@app.route("/logout")
def logout():
    if "user_id" in session:
        record_audit("LOGOUT", "User logged out", "SUCCESS")
    session.clear()
    return redirect("/login")


# -------------------- RUN APPLICATION --------------------

with app.app_context():
    db.create_all()
    ensure_initial_admin()


if __name__ == "__main__":
    # Debug mode is suitable only for local development, not deployment.
    app.run(debug=True)