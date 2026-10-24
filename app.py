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
os.makedirs(os.path.join(BASE_DIR, 'static', 'img'), exist_ok=True)  # taruh logo-um.png di sini
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)

CATEGORIES = ('hilang', 'ditemukan')
STATUSES = ('Open', 'Claimed', 'Returned')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'webp'}
PER_PAGE = 9

# Nomor WhatsApp admin untuk tombol "Hubungi Admin" (format internasional tanpa + atau 0 di depan)
ADMIN_WHATSAPP = os.environ.get('FINDU_ADMIN_WA', '6281357029750')

# Link Google Form evaluasi website
EVALUASI_URL = 'https://forms.gle/FzEgqVcrF3W7YwLk9'


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
            reporter_name TEXT,
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
    # Migrasi: tambah kolom reporter_name pada database lama
    cols = [r[1] for r in conn.execute('PRAGMA table_info(items)').fetchall()]
    if 'reporter_name' not in cols:
        conn.execute('ALTER TABLE items ADD COLUMN reporter_name TEXT')
    # Akun sistem untuk laporan tanpa login (tidak bisa dipakai login)
    if not conn.execute("SELECT 1 FROM users WHERE role = 'system'").fetchone():
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            ('pelapor_tamu_sistem', 'Pelapor Tamu', generate_password_hash(secrets.token_hex(16)), 'system', now()))
        conn.commit()
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
app.jinja_env.globals['EVALUASI_URL'] = EVALUASI_URL

FAILED_LOGINS = {}  # ip -> (jumlah, waktu_awal)
ANON_REPORTS = {}   # ip -> [timestamp, ...]  (batas laporan tanpa login)


def anon_report_limited(ip, limit=5, window=600):
    """Maks. 5 laporan tanpa login per 10 menit per IP (anti-spam)."""
    t = time.time()
    hits = [x for x in ANON_REPORTS.get(ip, []) if t - x < window]
    ANON_REPORTS[ip] = hits
    return len(hits) >= limit


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
            return redirect(url_for('login', next=request.path if request.method == 'GET' else None))
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


@app.route('/register')
def register():
    """Pendaftaran ditiadakan: pengguna umum cukup login dengan username & password bebas."""
    return redirect(url_for('login'))


def start_session(user):
    session.clear()
    session.update(user_id=user['id'], username=user['username'],
                   full_name=user['full_name'], role=user['role'])
    flash(f"Selamat datang, {user['full_name']}!", 'success')
    return redirect(safe_next(request.args.get('next')))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    - Pengguna umum: username BEBAS (2-30 karakter), password BEBAS (boleh kosong). Tanpa daftar.
    - Admin: username & password harus benar.
    """
    if request.method == 'POST':
        ip = request.remote_addr
        if login_blocked(ip):
            flash('Terlalu banyak percobaan gagal. Coba lagi dalam 5 menit.', 'danger')
            return render_template('login.html'), 429
        username = ' '.join(request.form.get('username', '').split())
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()

        if user and user['role'] == 'system':
            flash('Username tidak tersedia, gunakan username lain.', 'danger')
        elif user and user['role'] == 'admin':
            if check_password_hash(user['password_hash'], password):
                FAILED_LOGINS.pop(ip, None)
                return start_session(user)
            count, start = FAILED_LOGINS.get(ip, (0, time.time()))
            FAILED_LOGINS[ip] = (count + 1, start)
            flash('Password admin salah!', 'danger')
        elif not re.fullmatch(r'[A-Za-z0-9_. ]{2,30}', username):
            flash('Username 2-30 karakter (huruf, angka, spasi, titik, underscore).', 'danger')
        else:
            if not user:  # akun pengguna umum dibuat otomatis saat pertama login
                cur = db.execute(
                    'INSERT INTO users (username, full_name, password_hash, role, created_at) VALUES (?,?,?,?,?)',
                    (username, username, generate_password_hash(secrets.token_hex(16)), 'user', now()))
                db.commit()
                user = db.execute('SELECT * FROM users WHERE id = ?', (cur.lastrowid,)).fetchone()
            return start_session(user)
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))


# ============================== DASHBOARD & PENCARIAN ==============================
@app.route('/dashboard')
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
        SELECT i.*, COALESCE(i.reporter_name, u.full_name) AS reporter FROM items i
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
def scan():
    return render_template('scan.html')


@app.route('/kontak')
def kontak():
    return render_template('kontak.html')


# ============================== LAPOR BARANG ==============================
@app.route('/lapor/<category>', methods=['GET', 'POST'])
def lapor(category):
    """Lapor barang hilang/ditemukan: TIDAK perlu login. (Klaim tetap wajib login.)"""
    if category not in CATEGORIES:
        abort(404)
    uid = session.get('user_id')
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        contact = request.form.get('contact', '').strip()
        reporter_name = ' '.join(request.form.get('reporter_name', '').split())
        error = None
        if not title or not location or len(title) > 100 or len(location) > 150 or len(description) > 1000:
            error = 'Nama barang & lokasi wajib diisi dan tidak boleh terlalu panjang.'
        elif not uid and not (2 <= len(reporter_name) <= 50):
            error = 'Nama pelapor wajib diisi (2-50 karakter).'
        elif not uid and not contact:
            error = 'Kontak (WA/Email) wajib diisi agar pemilik/penemu dapat dihubungi.'
        elif len(contact) > 100:
            error = 'Kontak terlalu panjang (maks. 100 karakter).'
        elif not uid and anon_report_limited(request.remote_addr):
            error = 'Terlalu banyak laporan dalam waktu singkat. Coba lagi beberapa menit lagi atau login.'
        if error:
            flash(error, 'danger')
            return render_template('lapor.html', category=category, form=request.form)
        try:
            photo = save_photo(request.files.get('photo'))
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('lapor.html', category=category, form=request.form)

        db = get_db()
        if uid:
            reported_by, name_col, actor, note_by = uid, None, uid, ''
        else:
            reported_by = db.execute("SELECT id FROM users WHERE role = 'system'").fetchone()['id']
            name_col, actor, note_by = reporter_name, None, f' oleh {reporter_name} (tanpa login)'
            ANON_REPORTS.setdefault(request.remote_addr, []).append(time.time())
        ts = now()
        cur = db.execute('''INSERT INTO items (title, category, description, location, contact, photo,
                            reporter_name, reported_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                         (title, category, description, location, contact, photo, name_col, reported_by, ts, ts))
        item_id = cur.lastrowid
        add_log(db, item_id, actor, 'Dilaporkan', f'Barang {category} dilaporkan di {location}{note_by}')
        db.commit()
        flash('Laporan tersimpan! QR Code barang sudah dibuat. Simpan/cetak QR agar mudah dilacak.', 'success')
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
    item = db.execute('''SELECT i.*, COALESCE(i.reporter_name, u.full_name) AS reporter FROM items i
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
        SELECT c.*, i.title, i.category, i.location, u.full_name AS claimant, COALESCE(i.reporter_name, r.full_name) AS reporter
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
<title>{% block head_title %}FINDU{% endblock %} - FINDU Lost &amp; Found</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--blue:#0b4fa8;--ink:#12305c;--bg:#eef3fa;--shadow:0 2px 10px rgba(16,42,90,.07)}
body{font-family:'Poppins',system-ui,sans-serif;background:var(--bg);color:#1f2d3d}
.sidebar{position:fixed;top:0;bottom:0;left:0;width:250px;background:linear-gradient(180deg,#0b57c0,#083a7d);color:#fff;padding:22px 16px;display:flex;flex-direction:column;z-index:1040;overflow-y:auto}
.brand{padding:4px 10px 18px;border-bottom:1px solid rgba(255,255,255,.18);margin-bottom:16px}
.brand h4{font-weight:700;margin:0;font-size:1.4rem}.brand small{opacity:.8;font-size:.72rem}
.side-link{display:flex;align-items:center;gap:12px;color:#e6efff;text-decoration:none;padding:10px 14px;border-radius:10px;font-size:.88rem;font-weight:500;margin-bottom:6px;border:0;background:none;width:100%;text-align:left}
.side-link:hover{background:rgba(255,255,255,.14);color:#fff}
.side-link.active{background:#fff;color:var(--blue);font-weight:600}
.side-link i{font-size:1.05rem}
.side-user{margin-top:auto;font-size:.78rem;opacity:.92;padding:12px 10px 0;border-top:1px solid rgba(255,255,255,.18)}
.main{margin-left:250px;padding:22px 26px 70px}
.topcard,.panel-card,.stat-card,.card{background:#fff;border:0;border-radius:16px;box-shadow:var(--shadow)}
.topcard{padding:18px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}
.topcard h1{font-size:1.35rem;font-weight:700;color:var(--ink);margin:0;letter-spacing:.4px}
.topcard p{margin:0;font-size:.8rem;color:#7b8aa3}
.clock{background:#fff4e5;color:#e07b00;border:1px solid #ffd7a1;border-radius:8px;padding:4px 12px;font-size:.78rem;font-weight:600;white-space:nowrap}
.logo-um{width:50px;height:50px;object-fit:contain}
.logo-fallback,.logo-findu{width:46px;height:46px;border-radius:50%;background:var(--blue);color:#fff;align-items:center;justify-content:center;font-weight:700;font-size:.95rem}
.logo-fallback{display:none}.logo-findu{display:flex;background:#fff;border:2px solid var(--blue);font-size:1.3rem}
.stat-card{padding:16px 20px}
.stat-card .lbl{font-size:.82rem;font-weight:600;color:var(--ink);display:flex;gap:8px;align-items:center}
.stat-card .lbl i{color:var(--blue)}
.stat-card .num{font-size:2.1rem;font-weight:700;color:#0e2a55;line-height:1.25}
.panel-card{padding:20px 24px}
.panel-card h5{font-weight:700;color:var(--ink);font-size:1rem}
.table-findu th{font-size:.75rem;color:#7b8aa3;font-weight:600;background:#f5f8fd;border:0;white-space:nowrap}
.table-findu td{font-size:.84rem;vertical-align:middle}
.btn-primary{background:var(--blue);border-color:var(--blue)}
.qr-thumb{width:96px;height:96px}.qr-mini{width:46px;height:46px}
.menu-toggle{display:none}
@media (max-width:991px){.sidebar{transform:translateX(-100%);transition:transform .25s}.sidebar.open{transform:none}
.main{margin-left:0;padding:14px}.menu-toggle{display:inline-flex}.topcard{padding:14px 16px}}
@media print{.sidebar,.topcard,footer,.wa-float,.menu-toggle{display:none!important}.main{margin:0}}
</style>
</head><body>
{% set ep = request.endpoint %}{% set cat = (request.view_args or {}).get('category') %}
<aside class="sidebar" id="sidebar">
  <div class="brand"><h4>&#128269; FINDU</h4><small>Lost &amp; Found Berbasis QR Code</small></div>
  <a class="side-link {{ 'active' if ep=='dashboard' }}" href="{{ url_for('dashboard') }}"><i class="bi bi-speedometer2"></i> Dashboard</a>
  <a class="side-link {{ 'active' if ep=='lapor' and cat=='hilang' }}" href="{{ url_for('lapor', category='hilang') }}"><i class="bi bi-exclamation-circle"></i> Lapor Barang Hilang</a>
  <a class="side-link {{ 'active' if ep=='lapor' and cat=='ditemukan' }}" href="{{ url_for('lapor', category='ditemukan') }}"><i class="bi bi-box-seam"></i> Lapor Barang Ditemukan</a>
  <a class="side-link {{ 'active' if ep=='scan' }}" href="{{ url_for('scan') }}"><i class="bi bi-qr-code-scan"></i> Scan QR Code</a>
  {% if session.role == 'admin' %}<a class="side-link {{ 'active' if ep in ('admin','keputusan_klaim') }}" href="{{ url_for('admin') }}"><i class="bi bi-shield-check"></i> Panel Admin</a>{% endif %}
  <a class="side-link {{ 'active' if ep=='kontak' }}" href="{{ url_for('kontak') }}"><i class="bi bi-telephone"></i> Hubungi Admin</a>
  <a class="side-link" target="_blank" rel="noopener" href="{{ EVALUASI_URL }}"><i class="bi bi-clipboard2-check"></i> Evaluasi Website</a>
  {% if session.user_id %}
  <form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="side-link"><i class="bi bi-box-arrow-left"></i> Logout</button></form>
  {% else %}<a class="side-link {{ 'active' if ep=='login' }}" href="{{ url_for('login') }}"><i class="bi bi-box-arrow-in-right"></i> Masuk</a>{% endif %}
  <div class="side-user">{% if session.user_id %}Halo, <strong>{{ session.full_name }}</strong><br>({{ session.role }}){% else %}Belum login<br>Klaim barang butuh login{% endif %}</div>
</aside>
<div class="main">
  <div class="topcard">
    <div class="d-flex align-items-center gap-3">
      <button class="btn btn-outline-primary btn-sm menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')" aria-label="Menu"><i class="bi bi-list"></i></button>
      <div><h1>{% block page_title %}FINDU{% endblock %}</h1><p>{% block page_sub %}Sistem Lost &amp; Found Berbasis QR Code &middot; Universitas Negeri Malang{% endblock %}</p></div>
    </div>
    <div class="d-flex align-items-center gap-2">
      <span class="clock d-none d-sm-inline" id="jam">--.--.-- WIB</span>
      <img class="logo-um" src="{{ url_for('static', filename='img/logo-um.png') }}" alt="Logo Universitas Negeri Malang"
           onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
      <div class="logo-fallback">UM</div>
      <div class="logo-findu" title="FINDU">&#128269;</div>
    </div>
  </div>
  {% with messages = get_flashed_messages(with_categories=true) %}{% for c, m in messages %}
    <div class="alert alert-{{ c }} alert-dismissible fade show">{{ m }}<button class="btn-close" data-bs-dismiss="alert"></button></div>
  {% endfor %}{% endwith %}
  {% block content %}{% endblock %}
  <footer class="text-center text-muted small mt-4">FINDU &middot; Sistem Lost &amp; Found Berbasis QR Code &middot; Universitas Negeri Malang &middot;
    <a href="{{ url_for('kontak') }}">Hubungi Admin</a> &middot;
    <a target="_blank" rel="noopener" href="{{ EVALUASI_URL }}">Isi Evaluasi Website</a></footer>
</div>
<a href="https://wa.me/{{ ADMIN_WHATSAPP }}?text=Halo%20Admin%20FINDU%2C%20saya%20ingin%20bertanya%20tentang%20barang%20hilang%2Fditemukan." target="_blank" rel="noopener"
   class="wa-float position-fixed bottom-0 end-0 m-4 btn btn-success rounded-circle shadow"
   style="width:56px;height:56px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;z-index:1050" title="Hubungi Admin lewat WhatsApp"><i class="bi bi-whatsapp"></i></a>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
function tick(){var el=document.getElementById('jam');if(!el)return;
  var t=new Date().toLocaleTimeString('id-ID',{timeZone:'Asia/Jakarta',hour12:false});el.textContent=t.split(':').join('.')+' WIB';}
tick();setInterval(tick,1000);
</script>
{% block scripts %}{% endblock %}
</body></html>''',

'kontak.html': '''{% extends "base.html" %}{% block page_title %}HUBUNGI ADMIN{% endblock %}{% block page_sub %}Bantuan untuk kendala login, laporan, dan klaim{% endblock %}{% block content %}
<div class="row justify-content-center"><div class="col-md-6"><div class="card shadow-sm p-4 text-center">
<h3 class="mb-3">Hubungi Admin FINDU</h3>
<p class="text-muted">Ada kendala login, laporan barang, atau klaim yang perlu dibantu admin? Hubungi kami melalui:</p>
<a class="btn btn-success btn-lg w-100 mb-3" target="_blank" rel="noopener"
   href="https://wa.me/{{ ADMIN_WHATSAPP }}?text=Halo%20Admin%20FINDU%2C%20saya%20ingin%20bertanya%20tentang%20barang%20hilang%2Fditemukan.">
   &#128222; Chat WhatsApp Admin</a>
<p class="small text-muted mb-0">Nomor Admin: 0{{ ADMIN_WHATSAPP[2:] }}</p>
<p class="small text-muted">Jam layanan admin: 08.00 - 20.00 WIB (QR Code &amp; website tetap aktif 24 jam)</p>
</div></div></div>{% endblock %}''',

'login.html': '''{% extends "base.html" %}{% block page_title %}MASUK{% endblock %}{% block page_sub %}Pengguna umum bebas login, admin wajib password{% endblock %}{% block content %}
<div class="row justify-content-center"><div class="col-md-5"><div class="card shadow-sm p-4">
<h3 class="text-center mb-1">Masuk ke FINDU</h3>
<p class="text-center text-muted small">Tanpa daftar. Isi username bebas (misal nama Anda), lalu masuk.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" maxlength="30" required autofocus placeholder="Contoh: Budi"></div>
<div class="mb-3"><label class="form-label">Password <span class="text-muted small">(bebas / boleh kosong; khusus admin wajib benar)</span></label>
  <input type="password" name="password" class="form-control"></div>
<button class="btn btn-success w-100">Masuk</button></form>
<hr><a class="btn btn-outline-primary btn-sm w-100" target="_blank" rel="noopener" href="{{ EVALUASI_URL }}">&#128221; Isi Evaluasi Website</a>
</div></div></div>{% endblock %}''',

'dashboard.html': '''{% extends "base.html" %}
{% block head_title %}Dashboard{% endblock %}
{% block page_title %}DASHBOARD{% endblock %}
{% block page_sub %}Lost &amp; Found Kampus &middot; Universitas Negeri Malang{% endblock %}
{% block content %}
<div class="row g-3 mb-4">
  {% for label, val, icon in [('Total Laporan', stats.total, 'bi-clipboard-data'), ('Masih Open', stats.open, 'bi-search'), ('Sedang Diklaim', stats.claimed, 'bi-hourglass-split'), ('Dikembalikan', stats.returned, 'bi-check2-circle')] %}
  <div class="col-6 col-lg-3"><div class="stat-card"><div class="lbl"><i class="bi {{ icon }}"></i> {{ label }}</div><div class="num">{{ val }}</div></div></div>
  {% endfor %}
</div>

<div class="alert alert-info d-flex flex-wrap justify-content-between align-items-center gap-2 border-0">
  <span><i class="bi bi-clipboard2-check"></i> Bantu kami meningkatkan FINDU dengan mengisi formulir evaluasi website.</span>
  <a class="btn btn-primary btn-sm" target="_blank" rel="noopener" href="{{ EVALUASI_URL }}">Isi Evaluasi</a></div>

<div class="panel-card mb-4">
  <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
    <h5 class="mb-0">Status Barang Terbaru</h5>
    <div class="d-flex gap-2 flex-wrap">
      <a href="{{ url_for('lapor', category='hilang') }}" class="btn btn-warning btn-sm">+ Lapor Hilang</a>
      <a href="{{ url_for('lapor', category='ditemukan') }}" class="btn btn-info btn-sm text-white">+ Lapor Ditemukan</a>
      <a href="{{ url_for('scan') }}" class="btn btn-dark btn-sm"><i class="bi bi-qr-code-scan"></i> Scan QR</a>
    </div>
  </div>
  <form method="get" class="row g-2 mb-3">
    <div class="col-md-5"><input name="q" value="{{ q }}" class="form-control form-control-sm" placeholder="Cari nama, lokasi, deskripsi, atau kode QR (FINDU-ITEM-1)"></div>
    <div class="col-md-3"><select name="category" class="form-select form-select-sm"><option value="">Semua kategori</option>
      <option value="hilang" {{ 'selected' if category=='hilang' }}>Hilang</option><option value="ditemukan" {{ 'selected' if category=='ditemukan' }}>Ditemukan</option></select></div>
    <div class="col-md-2"><select name="status" class="form-select form-select-sm"><option value="">Semua status</option>
      {% for s in statuses %}<option {{ 'selected' if status==s }}>{{ s }}</option>{% endfor %}</select></div>
    <div class="col-md-2"><button class="btn btn-primary btn-sm w-100">Cari</button></div>
  </form>
  <div class="table-responsive">
    <table class="table table-findu align-middle mb-0">
      <thead><tr><th>QR</th><th>Barang</th><th>Kategori</th><th>Lokasi</th><th>Pelapor</th><th>Status</th><th></th></tr></thead>
      <tbody>
      {% for i in items %}
      <tr>
        <td><img class="qr-mini" src="{{ url_for('qr_code', item_id=i.id) }}" alt="QR #{{ i.id }}"></td>
        <td><strong>{{ i.title }}</strong><div class="small text-muted">#{{ i.id }} &middot; {{ (i.description or '')|truncate(50) }}</div></td>
        <td><span class="badge {{ 'bg-danger' if i.category=='hilang' else 'bg-success' }}">{{ i.category|upper }}</span></td>
        <td>{{ i.location }}</td>
        <td>{{ i.reporter }}</td>
        <td><span class="badge bg-{{ STATUS_BADGE[i.status] }}">{{ i.status }}</span></td>
        <td class="text-end"><a class="btn btn-outline-primary btn-sm" href="{{ url_for('item_detail', item_id=i.id) }}">Detail</a></td>
      </tr>
      {% else %}
      <tr><td colspan="7" class="text-center text-muted py-4">Belum ada barang yang sesuai.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% if pages > 1 %}<nav class="mt-3"><ul class="pagination pagination-sm justify-content-center mb-0">
    {% for p in range(1, pages + 1) %}<li class="page-item {{ 'active' if p==page }}">
    <a class="page-link" href="{{ url_for('dashboard', q=q, category=category, status=status, page=p) }}">{{ p }}</a></li>{% endfor %}
  </ul></nav>{% endif %}
</div>
{% endblock %}''',

'lapor.html': '''{% extends "base.html" %}{% block page_title %}LAPOR BARANG{% endblock %}{% block page_sub %}Laporkan barang hilang atau ditemukan, tanpa login{% endblock %}{% block content %}
<div class="row justify-content-center"><div class="col-md-7"><div class="card shadow-sm p-4">
<h3 class="mb-3">Lapor Barang {{ category.capitalize() }}</h3>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
{% if not session.user_id %}<div class="alert alert-info py-2 small">Anda melapor <strong>tanpa login</strong>. Untuk <em>mengklaim</em> barang, Anda tetap perlu login.</div>
<div class="mb-3"><label class="form-label">Nama Pelapor</label><input name="reporter_name" value="{{ form.get('reporter_name','') }}" class="form-control" maxlength="50" placeholder="Nama Anda" required></div>{% endif %}
<div class="mb-3"><label class="form-label">Nama Barang</label><input name="title" value="{{ form.get('title','') }}" class="form-control" maxlength="100" placeholder="Contoh: Kunci Motor Honda" required></div>
<div class="mb-3"><label class="form-label">Lokasi ({{ 'Kehilangan' if category=='hilang' else 'Ditemukan' }})</label><input name="location" value="{{ form.get('location','') }}" class="form-control" maxlength="150" placeholder="Contoh: Perpustakaan Lantai 2" required></div>
<div class="mb-3"><label class="form-label">Deskripsi / Ciri Khas</label><textarea name="description" class="form-control" rows="3" maxlength="1000">{{ form.get('description','') }}</textarea>
{% if category == 'ditemukan' %}<div class="form-text">Sebaiknya jangan tulis ciri yang terlalu spesifik agar pemilik asli dapat membuktikan kepemilikan.</div>{% endif %}</div>
<div class="mb-3"><label class="form-label">Kontak (WA/Email, hanya tampil untuk pengguna login){% if not session.user_id %} <span class="text-danger">*wajib</span>{% endif %}</label><input name="contact" value="{{ form.get('contact','') }}" class="form-control" maxlength="100" {{ 'required' if not session.user_id }}></div>
<div class="mb-3"><label class="form-label">Foto (opsional, maks. 4 MB)</label><input type="file" name="photo" accept="image/png,image/jpeg,image/webp" class="form-control"></div>
<button class="btn btn-primary w-100">Simpan &amp; Generate QR Code</button></form>
</div></div></div>{% endblock %}''',

'item.html': '''{% extends "base.html" %}{% block page_title %}DETAIL BARANG{% endblock %}{% block page_sub %}Pelacakan status dan QR Code barang{% endblock %}{% block content %}
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
    {% else %}<div class="alert alert-info d-flex flex-wrap justify-content-between align-items-center gap-2">
      <span>Untuk <strong>mengklaim</strong> barang dan melihat kontak pelapor, silakan login terlebih dahulu.</span>
      <a class="btn btn-primary btn-sm" href="{{ url_for('login', next=request.path) }}">Login untuk Klaim</a></div>{% endif %}
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

'scan.html': '''{% extends "base.html" %}{% block page_title %}SCAN QR CODE{% endblock %}{% block page_sub %}Pindai QR Code untuk membuka halaman barang{% endblock %}{% block content %}
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

'admin.html': '''{% extends "base.html" %}{% block page_title %}PANEL ADMIN{% endblock %}{% block page_sub %}Verifikasi klaim dan pantau aktivitas{% endblock %}{% block content %}
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

'error.html': '''{% extends "base.html" %}{% block page_title %}TERJADI KESALAHAN{% endblock %}{% block page_sub %}Halaman tidak dapat ditampilkan{% endblock %}{% block content %}
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
