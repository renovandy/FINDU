"""
FINDU - Sistem Lost & Found Berbasis QR Code untuk Lingkungan Pendidikan
=========================================================================
Jalankan:
    pip install flask "qrcode[pil]"
    python app.py

Variabel lingkungan (opsional):
    FINDU_ADMIN_PASSWORD  password admin awal (jika kosong -> dibuat acak & dicetak di terminal)
    FINDU_BASE_URL        alamat publik untuk isi QR, mis. http://192.168.1.10:5000
    FINDU_HTTPS=1         aktifkan cookie aman (wajib saat online dengan HTTPS)
    FINDU_BEHIND_PROXY=1  aktifkan bila memakai nginx/reverse proxy (VPS)
    FINDU_HOST / FINDU_PORT / FINDU_DEBUG
"""
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

import qrcode
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_file, session, url_for)
from jinja2 import DictLoader
from PIL import Image
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# ============================== KONFIGURASI ==============================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get('FINDU_DB', os.path.join(BASE_DIR, 'findu.db'))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)

CATEGORIES = ('hilang', 'ditemukan')
STATUSES = ('Open', 'Claimed', 'Returned')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'webp'}
PER_PAGE = 9

# Nomor WhatsApp admin untuk tombol "Hubungi Admin" (format internasional tanpa + atau 0 di depan)
ADMIN_WHATSAPP = os.environ.get('FINDU_ADMIN_WA', '6281357029750')


def load_secret_key():
    """Secret key acak yang disimpan di file agar sesi tetap valid setelah restart."""
    key = os.environ.get('FINDU_SECRET_KEY')
    if key:
        return key
    path = os.path.join(INSTANCE_DIR, 'secret.key')
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # maks. upload 4 MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FINDU_HTTPS', '0') == '1',  # set 1 saat sudah memakai HTTPS
)
if os.environ.get('FINDU_BEHIND_PROXY', '0') == '1':  # set 1 jika di belakang nginx / reverse proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ============================== DATABASE ==============================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA foreign_keys = ON')
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL CHECK (category IN ('hilang','ditemukan')),
            description TEXT,
            location TEXT NOT NULL,
            contact TEXT,
            photo TEXT,
            status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Claimed','Returned')),
            reported_by INTEGER NOT NULL,
            claimed_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (reported_by) REFERENCES users(id),
            FOREIGN KEY (claimed_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            proof TEXT NOT NULL,
            contact TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',  -- Pending / Approved / Rejected
            created_at TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS item_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            actor_id INTEGER,
            action TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
        CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);
        CREATE INDEX IF NOT EXISTS idx_claims_item ON claims(item_id);
        CREATE INDEX IF NOT EXISTS idx_logs_item ON item_logs(item_id);
    ''')
    if not conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
        # Default login admin: username "admin", password "Findu#2026!" (jika FINDU_ADMIN_PASSWORD tidak diisi).
        # SANGAT disarankan mengisi FINDU_ADMIN_PASSWORD sendiri sebelum dipublikasikan secara online.
        password = os.environ.get('FINDU_ADMIN_PASSWORD') or 'Findu#2026!'
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            ('admin', 'Administrator', generate_password_hash(password), 'admin', now()))
        conn.commit()
        print('=' * 60)
        print(' Akun admin dibuat -> username: admin | password:', password)
        print(' Segera login dan ganti password ini jika website sudah publik.')
        print('=' * 60)
    conn.commit()
    conn.close()


def add_log(db, item_id, actor_id, action, note=''):
    db.execute('INSERT INTO item_logs (item_id, actor_id, action, note, created_at) VALUES (?,?,?,?,?)',
               (item_id, actor_id, action, note, now()))


# ============================== KEAMANAN ==============================
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        sent = request.form.get('csrf_token', '')
        if not secrets.compare_digest(sent, session.get('_csrf', '')):
            abort(400, 'Token keamanan (CSRF) tidak valid. Muat ulang halaman dan coba lagi.')


app.jinja_env.globals['csrf_token'] = csrf_token
app.jinja_env.globals['STATUS_BADGE'] = {'Open': 'primary', 'Claimed': 'warning text-dark', 'Returned': 'secondary'}
app.jinja_env.globals['ADMIN_WHATSAPP'] = ADMIN_WHATSAPP

FAILED_LOGINS = {}  # ip -> (jumlah, waktu_awal)


def login_blocked(ip):
    count, start = FAILED_LOGINS.get(ip, (0, 0))
    if time.time() - start > 300:
        FAILED_LOGINS.pop(ip, None)
        return False
    return count >= 5


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.', 'warning')
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def safe_next(target):
    """Hanya izinkan redirect internal."""
    if target and target.startswith('/') and not target.startswith('//') and not urlparse(target).netloc:
        return target
    return url_for('dashboard')


def save_photo(file):
    """Simpan foto yang sudah divalidasi. Mengembalikan nama file atau None."""
    if not file or not file.filename:
        return None
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXT:
        raise ValueError('Format foto harus PNG, JPG, atau WEBP.')
    try:
        Image.open(file.stream).verify()
    except Exception:
        raise ValueError('File foto tidak valid.')
    file.stream.seek(0)
    name = f'{secrets.token_hex(8)}.{ext}'
    file.save(os.path.join(UPLOAD_DIR, name))
    return name


def like_escape(text):
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


# ============================== AUTENTIKASI ==============================
@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        error = None
        if not re.fullmatch(r'[A-Za-z0-9_.]{3,30}', username):
            error = 'Username 3-30 karakter (huruf, angka, titik, underscore).'
        elif not full_name or len(full_name) > 80:
            error = 'Nama lengkap wajib diisi (maks. 80 karakter).'
        elif len(password) < 6:
            error = 'Password minimal 6 karakter.'
        elif password != confirm:
            error = 'Konfirmasi password tidak cocok.'
        if error:
            flash(error, 'danger')
        else:
            db = get_db()
            try:
                db.execute('INSERT INTO users (username, full_name, password_hash, created_at) VALUES (?,?,?,?)',
                           (username, full_name, generate_password_hash(password), now()))
                db.commit()
                flash('Registrasi berhasil! Silakan login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username sudah terdaftar!', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        if login_blocked(ip):
            flash('Terlalu banyak percobaan gagal. Coba lagi dalam 5 menit.', 'danger')
            return render_template('login.html'), 429
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            FAILED_LOGINS.pop(ip, None)
            session.clear()
            session.update(user_id=user['id'], username=user['username'],
                           full_name=user['full_name'], role=user['role'])
            flash('Berhasil login!', 'success')
            return redirect(safe_next(request.args.get('next')))
        count, start = FAILED_LOGINS.get(ip, (0, time.time()))
        FAILED_LOGINS[ip] = (count + 1, start)
        flash('Username atau password salah!', 'danger')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))


# ============================== DASHBOARD & PENCARIAN ==============================
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    q = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    status = request.args.get('status', '')
    page = max(request.args.get('page', 1, type=int), 1)

    # Teks hasil scan QR (mis. FINDU-ITEM-5) langsung diarahkan ke detail barang
    m = re.fullmatch(r'FINDU-ITEM-(\d+)', q, re.I)
    if m:
        return redirect(url_for('item_detail', item_id=int(m.group(1))))

    where, params = [], []
    if q:
        pat = f'%{like_escape(q)}%'
        where.append("(i.title LIKE ? ESCAPE '\\' OR i.description LIKE ? ESCAPE '\\' OR i.location LIKE ? ESCAPE '\\')")
        params += [pat, pat, pat]
        if q.isdigit():
            where[-1] = where[-1][:-1] + ' OR i.id = ?)'
            params.append(int(q))
    if category in CATEGORIES:
        where.append('i.category = ?')
        params.append(category)
    if status in STATUSES:
        where.append('i.status = ?')
        params.append(status)
    clause = ('WHERE ' + ' AND '.join(where)) if where else ''

    total = db.execute(f'SELECT COUNT(*) FROM items i {clause}', params).fetchone()[0]
    items = db.execute(f'''
        SELECT i.*, u.full_name AS reporter FROM items i
        JOIN users u ON u.id = i.reported_by {clause}
        ORDER BY i.id DESC LIMIT ? OFFSET ?''', params + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()

    stats = {
        'total': db.execute('SELECT COUNT(*) FROM items').fetchone()[0],
        'open': db.execute("SELECT COUNT(*) FROM items WHERE status='Open'").fetchone()[0],
        'claimed': db.execute("SELECT COUNT(*) FROM items WHERE status='Claimed'").fetchone()[0],
        'returned': db.execute("SELECT COUNT(*) FROM items WHERE status='Returned'").fetchone()[0],
    }
    pages = max((total + PER_PAGE - 1) // PER_PAGE, 1)
    return render_template('dashboard.html', items=items, stats=stats, q=q, category=category,
                           status=status, page=page, pages=pages, total=total, statuses=STATUSES)


@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')


@app.route('/kontak')
def kontak():
    return render_template('kontak.html')


# ============================== LAPOR BARANG ==============================
@app.route('/lapor/<category>', methods=['GET', 'POST'])
@login_required
def lapor(category):
    if category not in CATEGORIES:
        abort(404)
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        contact = request.form.get('contact', '').strip()
        if not title or not location or len(title) > 100 or len(location) > 150 or len(description) > 1000:
            flash('Nama barang & lokasi wajib diisi dan tidak boleh terlalu panjang.', 'danger')
            return render_template('lapor.html', category=category, form=request.form)
        try:
            photo = save_photo(request.files.get('photo'))
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('lapor.html', category=category, form=request.form)

        db = get_db()
        ts = now()
        cur = db.execute('''INSERT INTO items (title, category, description, location, contact, photo,
                            reported_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)''',
                         (title, category, description, location, contact, photo, session['user_id'], ts, ts))
        item_id = cur.lastrowid
        add_log(db, item_id, session['user_id'], 'Dilaporkan', f'Barang {category} dilaporkan di {location}')
        db.commit()
        flash('Laporan tersimpan! QR Code barang sudah dibuat.', 'success')
        return redirect(url_for('item_detail', item_id=item_id))
    return render_template('lapor.html', category=category, form={})


# ============================== DETAIL, QR, KLAIM ==============================
def item_url(item_id):
    base = os.environ.get('FINDU_BASE_URL', '').rstrip('/') or request.host_url.rstrip('/')
    return f'{base}/item/{item_id}'


@app.route('/qr/<int:item_id>.png')
def qr_code(item_id):
    """QR dibuat langsung (tanpa file), berisi URL halaman pelacakan barang."""
    if not get_db().execute('SELECT 1 FROM items WHERE id = ?', (item_id,)).fetchone():
        abort(404)
    img = qrcode.make(item_url(item_id), box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    resp = send_file(buf, mimetype='image/png', download_name=f'FINDU-ITEM-{item_id}.png')
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/item/<int:item_id>')
def item_detail(item_id):
    """Halaman publik hasil scan QR. Kontak & klaim hanya untuk pengguna login."""
    db = get_db()
    item = db.execute('''SELECT i.*, u.full_name AS reporter FROM items i
                         JOIN users u ON u.id = i.reported_by WHERE i.id = ?''', (item_id,)).fetchone()
    if not item:
        abort(404)
    logs = db.execute('''SELECT l.*, u.full_name AS actor FROM item_logs l
                         LEFT JOIN users u ON u.id = l.actor_id
                         WHERE l.item_id = ? ORDER BY l.id ASC''', (item_id,)).fetchall()
    uid, role = session.get('user_id'), session.get('role')
    claims = []
    if uid and (role == 'admin' or uid == item['reported_by']):
        claims = db.execute('''SELECT c.*, u.full_name AS claimant FROM claims c
                               JOIN users u ON u.id = c.user_id
                               WHERE c.item_id = ? ORDER BY c.id DESC''', (item_id,)).fetchall()
    return render_template('item.html', item=item, logs=logs, claims=claims,
                           can_claim=bool(uid) and item['status'] == 'Open' and uid != item['reported_by'],
                           can_delete=bool(uid) and (role == 'admin' or (uid == item['reported_by'] and item['status'] == 'Open')))


@app.route('/item/<int:item_id>/klaim', methods=['POST'])
@login_required
def klaim(item_id):
    db = get_db()
    item = db.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        abort(404)
    proof = request.form.get('proof', '').strip()
    contact = request.form.get('contact', '').strip()
    if item['status'] != 'Open':
        flash('Barang ini sedang diproses atau sudah dikembalikan.', 'warning')
    elif item['reported_by'] == session['user_id']:
        flash('Anda tidak dapat mengklaim laporan milik sendiri.', 'danger')
    elif len(proof) < 10 or not contact or len(proof) > 1000:
        flash('Isi bukti kepemilikan/keterangan (min. 10 karakter) dan kontak Anda.', 'danger')
    else:
        db.execute('INSERT INTO claims (item_id, user_id, proof, contact, created_at) VALUES (?,?,?,?,?)',
                   (item_id, session['user_id'], proof, contact, now()))
        db.execute("UPDATE items SET status='Claimed', claimed_by=?, updated_at=? WHERE id=? AND status='Open'",
                   (session['user_id'], now(), item_id))
        add_log(db, item_id, session['user_id'], 'Diklaim', 'Pengajuan klaim dikirim, menunggu verifikasi admin')
        db.commit()
        flash('Klaim terkirim! Menunggu verifikasi admin.', 'success')
    return redirect(url_for('item_detail', item_id=item_id))


@app.route('/item/<int:item_id>/hapus', methods=['POST'])
@login_required
def hapus(item_id):
    db = get_db()
    item = db.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        abort(404)
    is_admin = session.get('role') == 'admin'
    if not (is_admin or (item['reported_by'] == session['user_id'] and item['status'] == 'Open')):
        abort(403)
    if item['photo']:
        try:
            os.remove(os.path.join(UPLOAD_DIR, item['photo']))
        except OSError:
            pass
    db.execute('DELETE FROM items WHERE id = ?', (item_id,))
    db.commit()
    flash('Laporan dihapus.', 'info')
    return redirect(url_for('dashboard'))


# ============================== PANEL ADMIN ==============================
@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    pending = db.execute('''
        SELECT c.*, i.title, i.category, i.location, u.full_name AS claimant, r.full_name AS reporter
        FROM claims c JOIN items i ON i.id = c.item_id
        JOIN users u ON u.id = c.user_id JOIN users r ON r.id = i.reported_by
        WHERE c.status = 'Pending' ORDER BY c.id ASC''').fetchall()
    recent = db.execute('''
        SELECT l.*, u.full_name AS actor, i.title FROM item_logs l
        JOIN items i ON i.id = l.item_id LEFT JOIN users u ON u.id = l.actor_id
        ORDER BY l.id DESC LIMIT 15''').fetchall()
    users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    return render_template('admin.html', pending=pending, recent=recent, users=users)


@app.route('/admin/klaim/<int:claim_id>/<decision>', methods=['POST'])
@admin_required
def keputusan_klaim(claim_id, decision):
    if decision not in ('approve', 'reject'):
        abort(404)
    db = get_db()
    claim = db.execute("SELECT * FROM claims WHERE id = ? AND status = 'Pending'", (claim_id,)).fetchone()
    if not claim:
        flash('Klaim tidak ditemukan atau sudah diproses.', 'warning')
        return redirect(url_for('admin'))
    note = request.form.get('note', '').strip()[:300]
    if decision == 'approve':
        db.execute("UPDATE claims SET status='Approved' WHERE id=?", (claim_id,))
        db.execute("UPDATE items SET status='Returned', updated_at=? WHERE id=?", (now(), claim['item_id']))
        add_log(db, claim['item_id'], session['user_id'], 'Dikembalikan', note or 'Klaim diverifikasi admin, barang dikembalikan')
        flash('Klaim disetujui. Status barang: Returned.', 'success')
    else:
        db.execute("UPDATE claims SET status='Rejected' WHERE id=?", (claim_id,))
        db.execute("UPDATE items SET status='Open', claimed_by=NULL, updated_at=? WHERE id=?", (now(), claim['item_id']))
        add_log(db, claim['item_id'], session['user_id'], 'Klaim ditolak', note or 'Klaim ditolak admin, barang kembali Open')
        flash('Klaim ditolak. Barang kembali berstatus Open.', 'info')
    db.commit()
    return redirect(url_for('admin'))


# ============================== ERROR HANDLER ==============================
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def http_error(e):
    msg = {413: 'Ukuran file terlalu besar (maks. 4 MB).', 403: 'Akses ditolak.',
           404: 'Halaman tidak ditemukan.'}.get(e.code, e.description)
    return render_template('error.html', code=e.code, message=msg), e.code


# ============================== TEMPLATE ==============================
TEMPLATES = {
'base.html': '''<!DOCTYPE html>
<html lang="id"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FINDU - Lost &amp; Found</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#f4f6f9}.card{border-radius:12px}.qr-thumb{width:96px;height:96px}
.item-photo{height:150px;object-fit:cover;border-radius:12px 12px 0 0}</style>
</head><body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark"><div class="container">
  <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">&#128269; FINDU</a>
  <button class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#nv"><span class="navbar-toggler-icon"></span></button>
  <div class="collapse navbar-collapse" id="nv">
    <ul class="navbar-nav me-auto">
    {% if session.user_id %}
      <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
      <li class="nav-item"><a class="nav-link" href="{{ url_for('scan') }}">Scan QR</a></li>
      {% if session.role == 'admin' %}<li class="nav-item"><a class="nav-link" href="{{ url_for('admin') }}">Panel Admin</a></li>{% endif %}
    {% endif %}
      <li class="nav-item"><a class="nav-link" href="{{ url_for('kontak') }}">Hubungi Admin</a></li>
    </ul>
    <div class="d-flex align-items-center gap-2">
    {% if session.user_id %}
      <span class="text-white small">{{ session.full_name }} ({{ session.role }})</span>
      <form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button class="btn btn-outline-light btn-sm">Logout</button></form>
    {% else %}
      <a class="btn btn-outline-light btn-sm" href="{{ url_for('login') }}">Login</a>
      <a class="btn btn-light btn-sm" href="{{ url_for('register') }}">Register</a>
    {% endif %}</div>
  </div></div></nav>
<main class="container my-4">
  {% with messages = get_flashed_messages(with_categories=true) %}{% for c, m in messages %}
    <div class="alert alert-{{ c }} alert-dismissible fade show">{{ m }}<button class="btn-close" data-bs-dismiss="alert"></button></div>
  {% endfor %}{% endwith %}
  {% block content %}{% endblock %}
</main>
<footer class="text-center text-muted small pb-5">FINDU &middot; Sistem Lost &amp; Found Berbasis QR Code &middot;
  <a href="{{ url_for('kontak') }}">Hubungi Admin</a></footer>
<a href="https://wa.me/{{ ADMIN_WHATSAPP }}?text={{ 'Halo%20Admin%20FINDU%2C%20saya%20ingin%20bertanya%20tentang%20barang%20hilang%2Fditemukan.' }}"
   target="_blank" rel="noopener" class="position-fixed bottom-0 end-0 m-4 btn btn-success rounded-circle shadow"
   style="width:58px;height:58px;display:flex;align-items:center;justify-content:center;font-size:1.6rem;z-index:1050"
   title="Hubungi Admin lewat WhatsApp">&#128222;</a>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
{% block scripts %}{% endblock %}
</body></html>''',

'kontak.html': '''{% extends "base.html" %}{% block content %}
<div class="row justify-content-center"><div class="col-md-6"><div class="card shadow-sm p-4 text-center">
<h3 class="mb-3">Hubungi Admin FINDU</h3>
<p class="text-muted">Ada kendala login, laporan barang, atau klaim yang perlu dibantu admin? Hubungi kami melalui:</p>
<a class="btn btn-success btn-lg w-100 mb-3" target="_blank" rel="noopener"
   href="https://wa.me/{{ ADMIN_WHATSAPP }}?text=Halo%20Admin%20FINDU%2C%20saya%20ingin%20bertanya%20tentang%20barang%20hilang%2Fditemukan.">
   &#128222; Chat WhatsApp Admin</a>
<p class="small text-muted mb-0">Nomor Admin: 0{{ ADMIN_WHATSAPP[2:] }}</p>
<p class="small text-muted">Jam layanan admin: 08.00 - 20.00 WIB (QR Code &amp; website tetap aktif 24 jam)</p>
</div></div></div>{% endblock %}''',

'login.html': '''{% extends "base.html" %}{% block content %}
<div class="row justify-content-center"><div class="col-md-4"><div class="card shadow-sm p-4">
<h3 class="text-center mb-3">Login FINDU</h3>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input type="password" name="password" class="form-control" required></div>
<button class="btn btn-success w-100">Masuk</button></form>
<div class="text-center mt-3"><small>Belum punya akun? <a href="{{ url_for('register') }}">Register</a></small></div>
</div></div></div>{% endblock %}''',

'register.html': '''{% extends "base.html" %}{% block content %}
<div class="row justify-content-center"><div class="col-md-5"><div class="card shadow-sm p-4">
<h3 class="text-center mb-3">Register FINDU</h3>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-3"><label class="form-label">Nama Lengkap</label><input name="full_name" class="form-control" maxlength="80" required></div>
<div class="mb-3"><label class="form-label">Username (NIM/NIP disarankan)</label><input name="username" class="form-control" maxlength="30" required></div>
<div class="mb-3"><label class="form-label">Password (min. 6 karakter)</label><input type="password" name="password" class="form-control" required></div>
<div class="mb-3"><label class="form-label">Konfirmasi Password</label><input type="password" name="confirm" class="form-control" required></div>
<button class="btn btn-primary w-100">Daftar</button></form>
<div class="text-center mt-3"><small>Sudah punya akun? <a href="{{ url_for('login') }}">Login</a></small></div>
</div></div></div>{% endblock %}''',

'dashboard.html': '''{% extends "base.html" %}{% block content %}
<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
  <h2 class="mb-0">Dashboard Lost &amp; Found</h2>
  <div class="d-flex gap-2 flex-wrap">
    <a href="{{ url_for('lapor', category='hilang') }}" class="btn btn-warning">+ Lapor Barang Hilang</a>
    <a href="{{ url_for('lapor', category='ditemukan') }}" class="btn btn-info">+ Lapor Barang Ditemukan</a>
    <a href="{{ url_for('scan') }}" class="btn btn-dark">&#128247; Scan QR</a>
  </div>
</div>
<div class="row g-3 mb-4">
  {% for label, val, cls in [('Total Laporan', stats.total, 'dark'), ('Open', stats.open, 'primary'), ('Diklaim', stats.claimed, 'warning'), ('Dikembalikan', stats.returned, 'success')] %}
  <div class="col-6 col-md-3"><div class="card shadow-sm text-center p-3 border-{{ cls }}"><div class="fs-3 fw-bold text-{{ cls }}">{{ val }}</div><small>{{ label }}</small></div></div>
  {% endfor %}
</div>
<form class="card shadow-sm p-3 mb-4" method="get"><div class="row g-2">
  <div class="col-md-5"><input name="q" value="{{ q }}" class="form-control" placeholder="Cari nama, lokasi, deskripsi, atau kode QR (FINDU-ITEM-1)"></div>
  <div class="col-md-3"><select name="category" class="form-select"><option value="">Semua kategori</option>
    <option value="hilang" {{ 'selected' if category=='hilang' }}>Hilang</option><option value="ditemukan" {{ 'selected' if category=='ditemukan' }}>Ditemukan</option></select></div>
  <div class="col-md-2"><select name="status" class="form-select"><option value="">Semua status</option>
    {% for s in statuses %}<option {{ 'selected' if status==s }}>{{ s }}</option>{% endfor %}</select></div>
  <div class="col-md-2"><button class="btn btn-primary w-100">Cari</button></div>
</div></form>
{% if not items %}<div class="alert alert-warning text-center">Belum ada barang yang sesuai.</div>{% endif %}
<div class="row">{% for i in items %}
<div class="col-md-4 mb-4"><div class="card shadow-sm h-100">
  {% if i.photo %}<img class="item-photo" src="{{ url_for('static', filename='uploads/' ~ i.photo) }}" alt="Foto">{% endif %}
  <div class="card-body">
    <div class="d-flex justify-content-between mb-2">
      <span class="badge {{ 'bg-danger' if i.category=='hilang' else 'bg-success' }}">{{ i.category|upper }}</span>
      <span class="badge bg-{{ STATUS_BADGE[i.status] }}">{{ i.status }}</span></div>
    <h5 class="card-title">{{ i.title }}</h5>
    <p class="text-muted mb-1"><small>&#128205; {{ i.location }}</small></p>
    <p class="card-text">{{ (i.description or '')|truncate(90) }}</p>
    <div class="d-flex align-items-center gap-3">
      <img class="qr-thumb" src="{{ url_for('qr_code', item_id=i.id) }}" alt="QR"><small class="text-muted">ID #{{ i.id }}<br>Pelapor: {{ i.reporter }}</small></div>
  </div>
  <div class="card-footer bg-white"><a class="btn btn-outline-primary btn-sm w-100" href="{{ url_for('item_detail', item_id=i.id) }}">Detail &amp; Pelacakan</a></div>
</div></div>{% endfor %}</div>
{% if pages > 1 %}<nav><ul class="pagination justify-content-center">
  {% for p in range(1, pages + 1) %}<li class="page-item {{ 'active' if p==page }}">
  <a class="page-link" href="{{ url_for('dashboard', q=q, category=category, status=status, page=p) }}">{{ p }}</a></li>{% endfor %}
</ul></nav>{% endif %}
{% endblock %}''',

'lapor.html': '''{% extends "base.html" %}{% block content %}
<div class="row justify-content-center"><div class="col-md-7"><div class="card shadow-sm p-4">
<h3 class="mb-3">Lapor Barang {{ category.capitalize() }}</h3>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-3"><label class="form-label">Nama Barang</label><input name="title" value="{{ form.get('title','') }}" class="form-control" maxlength="100" placeholder="Contoh: Kunci Motor Honda" required></div>
<div class="mb-3"><label class="form-label">Lokasi ({{ 'Kehilangan' if category=='hilang' else 'Ditemukan' }})</label><input name="location" value="{{ form.get('location','') }}" class="form-control" maxlength="150" placeholder="Contoh: Perpustakaan Lantai 2" required></div>
<div class="mb-3"><label class="form-label">Deskripsi / Ciri Khas</label><textarea name="description" class="form-control" rows="3" maxlength="1000">{{ form.get('description','') }}</textarea>
{% if category == 'ditemukan' %}<div class="form-text">Sebaiknya jangan tulis ciri yang terlalu spesifik agar pemilik asli dapat membuktikan kepemilikan.</div>{% endif %}</div>
<div class="mb-3"><label class="form-label">Kontak (WA/Email, hanya tampil untuk pengguna login)</label><input name="contact" value="{{ form.get('contact','') }}" class="form-control" maxlength="100"></div>
<div class="mb-3"><label class="form-label">Foto (opsional, maks. 4 MB)</label><input type="file" name="photo" accept="image/png,image/jpeg,image/webp" class="form-control"></div>
<button class="btn btn-primary w-100">Simpan &amp; Generate QR Code</button></form>
</div></div></div>{% endblock %}''',

'item.html': '''{% extends "base.html" %}{% block content %}
<div class="row g-4">
<div class="col-lg-7"><div class="card shadow-sm">
  {% if item.photo %}<img class="w-100" style="max-height:320px;object-fit:cover;border-radius:12px 12px 0 0" src="{{ url_for('static', filename='uploads/' ~ item.photo) }}" alt="Foto">{% endif %}
  <div class="card-body">
    <div class="d-flex justify-content-between mb-2">
      <span class="badge {{ 'bg-danger' if item.category=='hilang' else 'bg-success' }}">{{ item.category|upper }}</span>
      <span class="badge bg-{{ STATUS_BADGE[item.status] }}">{{ item.status }}</span></div>
    <h3>{{ item.title }}</h3>
    <p class="text-muted mb-1">&#128205; {{ item.location }}</p>
    <p class="text-muted"><small>Dilaporkan {{ item.created_at }} oleh {{ item.reporter }}</small></p>
    <p>{{ item.description or 'Tidak ada deskripsi.' }}</p>
    {% if session.user_id %}{% if item.contact %}<p><strong>Kontak pelapor:</strong> {{ item.contact }}</p>{% endif %}
    {% else %}<div class="alert alert-info">Login untuk melihat kontak pelapor atau mengajukan klaim.
      <a href="{{ url_for('login', next=request.path) }}">Login</a></div>{% endif %}
    {% if can_delete %}<form method="post" action="{{ url_for('hapus', item_id=item.id) }}" onsubmit="return confirm('Hapus laporan ini?')">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-outline-danger btn-sm">Hapus Laporan</button></form>{% endif %}
  </div></div>

  {% if can_claim %}<div class="card shadow-sm mt-4 p-3"><h5>Ajukan Klaim</h5>
  <form method="post" action="{{ url_for('klaim', item_id=item.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <div class="mb-2"><label class="form-label">Bukti kepemilikan / keterangan</label>
      <textarea name="proof" class="form-control" rows="3" minlength="10" maxlength="1000" placeholder="Ciri khusus, isi barang, waktu &amp; tempat kehilangan, dll." required></textarea></div>
    <div class="mb-2"><label class="form-label">Kontak Anda (WA/Email)</label><input name="contact" class="form-control" maxlength="100" required></div>
    <button class="btn btn-primary">Kirim Klaim</button></form></div>{% endif %}

  {% if claims %}<div class="card shadow-sm mt-4 p-3"><h5>Riwayat Klaim</h5>
  {% for c in claims %}<div class="border-top pt-2 mt-2"><strong>{{ c.claimant }}</strong> <span class="badge bg-secondary">{{ c.status }}</span>
    <div class="small text-muted">{{ c.created_at }} &middot; Kontak: {{ c.contact }}</div><div>{{ c.proof }}</div></div>{% endfor %}</div>{% endif %}
</div>

<div class="col-lg-5">
  <div class="card shadow-sm p-3 text-center mb-4">
    <img src="{{ url_for('qr_code', item_id=item.id) }}" class="mx-auto" style="width:220px" alt="QR Code">
    <div class="small text-muted mb-2">Kode: FINDU-ITEM-{{ item.id }}</div>
    <div class="d-flex gap-2 justify-content-center">
      <a class="btn btn-sm btn-outline-dark" href="{{ url_for('qr_code', item_id=item.id) }}" download="FINDU-ITEM-{{ item.id }}.png">Unduh QR</a>
      <button class="btn btn-sm btn-outline-dark" onclick="window.print()">Cetak</button></div>
  </div>
  <div class="card shadow-sm p-3"><h5>Pelacakan Status</h5>
    <ul class="list-unstyled mb-0">{% for l in logs %}
      <li class="border-start border-3 border-primary ps-3 pb-3"><strong>{{ l.action }}</strong>
        <div class="small text-muted">{{ l.created_at }}{% if l.actor %} &middot; {{ l.actor }}{% endif %}</div>
        {% if l.note %}<div class="small">{{ l.note }}</div>{% endif %}</li>{% endfor %}</ul>
  </div>
</div></div>{% endblock %}''',

'scan.html': '''{% extends "base.html" %}{% block content %}
<div class="row justify-content-center"><div class="col-md-6"><div class="card shadow-sm p-4">
<h3 class="text-center mb-3">Scan QR Code Barang</h3>
<div id="reader" class="mb-3"></div><div id="msg" class="text-center text-muted small mb-3">Arahkan kamera ke QR Code barang.</div>
<form method="get" action="{{ url_for('dashboard') }}" class="d-flex gap-2">
  <input name="q" class="form-control" placeholder="Atau ketik kode: FINDU-ITEM-1" required><button class="btn btn-primary">Cari</button></form>
<div class="form-text mt-2">Kamera browser hanya aktif di HTTPS atau localhost. Alternatif: scan dengan kamera bawaan HP.</div>
</div></div></div>{% endblock %}
{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
<script>
const msg = document.getElementById('msg');
function handle(text) {
  let m = text.match(/^FINDU-ITEM-(\\d+)$/i);
  if (m) { location.href = '/item/' + m[1]; return; }
  try { const u = new URL(text); if (u.origin === location.origin || /^\\/item\\/\\d+$/.test(u.pathname)) { location.href = '/item/' + u.pathname.split('/').pop(); return; } } catch (e) {}
  msg.textContent = 'QR tidak dikenali sebagai barang FINDU.';
}
if (window.Html5Qrcode) {
  const scanner = new Html5Qrcode('reader');
  scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 240 },
    t => { scanner.stop().catch(()=>{}); handle(t); }, () => {})
    .catch(() => { msg.textContent = 'Kamera tidak dapat diakses. Gunakan input kode di bawah.'; });
}
</script>{% endblock %}''',

'admin.html': '''{% extends "base.html" %}{% block content %}
<h2 class="mb-3">Panel Admin</h2>
<p class="text-muted">Total pengguna terdaftar: <strong>{{ users }}</strong></p>
<h4>Klaim Menunggu Verifikasi ({{ pending|length }})</h4>
{% if not pending %}<div class="alert alert-secondary">Tidak ada klaim yang menunggu.</div>{% endif %}
{% for c in pending %}<div class="card shadow-sm mb-3 p-3">
  <div class="d-flex justify-content-between"><div>
    <h5><a href="{{ url_for('item_detail', item_id=c.item_id) }}">#{{ c.item_id }} {{ c.title }}</a>
      <span class="badge {{ 'bg-danger' if c.category=='hilang' else 'bg-success' }}">{{ c.category }}</span></h5>
    <div class="small text-muted">Lokasi: {{ c.location }} &middot; Pelapor: {{ c.reporter }}</div></div>
    <small class="text-muted">{{ c.created_at }}</small></div>
  <hr class="my-2"><div><strong>Pengklaim:</strong> {{ c.claimant }} ({{ c.contact }})</div><div class="mb-2"><strong>Bukti:</strong> {{ c.proof }}</div>
  <form method="post" class="d-flex gap-2 flex-wrap">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="note" class="form-control form-control-sm" style="max-width:320px" placeholder="Catatan (opsional)">
    <button class="btn btn-success btn-sm" formaction="{{ url_for('keputusan_klaim', claim_id=c.id, decision='approve') }}">Setujui &rarr; Returned</button>
    <button class="btn btn-outline-danger btn-sm" formaction="{{ url_for('keputusan_klaim', claim_id=c.id, decision='reject') }}">Tolak</button>
  </form></div>{% endfor %}
<h4 class="mt-4">Aktivitas Terbaru</h4>
<div class="card shadow-sm"><ul class="list-group list-group-flush">{% for l in recent %}
  <li class="list-group-item small"><strong>{{ l.action }}</strong> &ndash; {{ l.title }} <span class="text-muted">({{ l.actor or 'sistem' }}, {{ l.created_at }})</span></li>{% endfor %}</ul></div>
{% endblock %}''',

'error.html': '''{% extends "base.html" %}{% block content %}
<div class="text-center py-5"><h1 class="display-4">{{ code }}</h1><p class="lead">{{ message }}</p>
<a class="btn btn-primary" href="{{ url_for('dashboard') }}">Kembali ke Dashboard</a></div>{% endblock %}''',
}
app.jinja_loader = DictLoader(TEMPLATES)

# ============================== MULAI ==============================
init_db()

if __name__ == '__main__':
    app.run(host=os.environ.get('FINDU_HOST', '127.0.0.1'),
            port=int(os.environ.get('FINDU_PORT', 5000)),
            debug=os.environ.get('FINDU_DEBUG', '0') == '1')
