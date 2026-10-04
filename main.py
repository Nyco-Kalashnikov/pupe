import os
try:
    import libsql_experimental as sqlite3
except ImportError:
    import sqlite3
import secrets
import base64
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'pupe-dark-secret-key-2026')

# Configurações do Resend API
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
SENDER_EMAIL = 'noreply@pupe.lovie.me'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_PAGE_SIZE_BYTES = 20 * 1024  # 20 KB


# ==========================================
# BANCO DE DADOS & INICIALIZAÇÃO (TURSO / SQLITE)
# ==========================================
TURSO_DATABASE_URL = os.environ.get('TURSO_DATABASE_URL', 'pupe.db')
TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '')

def get_db():
    if 'db' not in g:
        if TURSO_DATABASE_URL.startswith(('libsql://', 'https://')):
            g.db = sqlite3.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)
        else:
            g.db = sqlite3.connect(TURSO_DATABASE_URL)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Cria e atualiza o esquema do banco de dados SQLite / Turso."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                avatar_url TEXT DEFAULT '/static/default-avatar.png',
                reset_token TEXT DEFAULT NULL,
                reset_token_expires TEXT DEFAULT NULL,
                is_verified INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Posts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                group_id INTEGER DEFAULT NULL,
                content TEXT NOT NULL,
                image_url TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
            )
        ''')

        # Comentários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT NULL,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Reações (Suporta nomes de ícones como 'heart', 'like', 'star', 'fire', 'laugh')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reaction_type TEXT DEFAULT 'heart',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(post_id, user_id, reaction_type),
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Seguidores
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER NOT NULL,
                followed_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (follower_id, followed_id),
                FOREIGN KEY (follower_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (followed_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Grupos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                avatar_url TEXT DEFAULT '/static/default-group.png',
                theme_color TEXT DEFAULT '#6366f1',
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Membros de Grupos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT DEFAULT 'member',
                status TEXT DEFAULT 'approved',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Pupe Pages (FASE 4)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pupe_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                html_content TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Notificações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                actor_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                target_id INTEGER DEFAULT NULL,
                message TEXT DEFAULT '',
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (actor_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        try:
            cursor.execute("ALTER TABLE groups ADD COLUMN theme_color TEXT DEFAULT '#6366f1'")
        except Exception:
            pass

        # Adiciona colunas de verificação de e-mail
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN verification_code TEXT DEFAULT NULL")
            cursor.execute("ALTER TABLE users ADD COLUMN code_expires TEXT DEFAULT NULL")
        except Exception:
            pass

        db.commit()


# ==========================================
# SANITIZAÇÃO PUPE PAGES & DECORADORES
# ==========================================
def sanitize_html(html_str):
    """Sanitiza HTML bloqueando completamente scripts, eventos inline e links externos."""
    if not html_str:
        return ""

    # 1. Remove todas as tags <script> e seu conteúdo interno
    clean = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', html_str, flags=re.IGNORECASE)

    # 2. Converte tags de link <a> em <span> para desativar qualquer hiperlink
    clean = re.sub(r'<a\b[^>]*>', '<span>', clean, flags=re.IGNORECASE)
    clean = re.sub(r'</a>', '</span>', clean, flags=re.IGNORECASE)

    # 3. Remove elementos perigosos ou de carregamento externo perigoso
    clean = re.sub(r'<(iframe|object|embed|form|base|meta|link|applet)\b[^>]*>', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'</(iframe|object|embed|form|base|meta|link|applet)>', '', clean, flags=re.IGNORECASE)

    # 4. Bloqueia todos os atributos de evento JavaScript inline (onclick, onload, onerror, etc.)
    clean = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'\son\w+\s*=\s*[^"\s>]+', '', clean, flags=re.IGNORECASE)

    # 5. Remove qualquer tentativa de uso do protocolo javascript:
    clean = re.sub(r'(src|href|style)\s*=\s*["\']?\s*javascript:[^"\'>\s]*["\']?', '', clean, flags=re.IGNORECASE)

    return clean

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Faça login para continuar.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def image_to_base64(file):
    file_bytes = file.read()
    encoded = base64.b64encode(file_bytes).decode('utf-8')
    mime_type = file.mimetype or 'image/png'
    return f"data:{mime_type};base64,{encoded}"

def send_email_resend(to_email, subject, html_content):
    if not RESEND_API_KEY:
        print(f"[DEV MAIL LOG] Para: {to_email} | Assunto: {subject}")
        return True
    try:
        res = requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {RESEND_API_KEY}', 'Content-Type': 'application/json'},
            json={'from': f'Pupe <{SENDER_EMAIL}>', 'to': [to_email], 'subject': subject, 'html': html_content},
            timeout=10
        )
        return res.status_code in (200, 201)
    except Exception as e:
        print(f"[ERRO RESEND] {e}")
        return False

def create_notification(user_id, actor_id, notif_type, target_id=None, message=""):
    if user_id == actor_id:
        return
    db = get_db()
    db.execute(
        'INSERT INTO notifications (user_id, actor_id, type, target_id, message) VALUES (?, ?, ?, ?, ?)',
        (user_id, actor_id, notif_type, target_id, message)
    )
    db.commit()

@app.context_processor
def inject_user_context():
    if 'user_id' in session:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        unread_count = db.execute(
            "SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0",
            (session['user_id'],)
        ).fetchone()['count']
        return dict(current_user=user, unread_notifications=unread_count)
    return dict(current_user=None, unread_notifications=0)


# ==========================================
# ROTAS DE AUTENTICAÇÃO E PERFIL
# ==========================================
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        display_name = request.form.get('display_name', '').strip() or username
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not username or not email or not password:
            flash('Preencha todos os campos obrigatórios.', 'error')
            return render_template('cadastro.html')

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone():
            flash('Nome de utilizador ou e-mail já registado.', 'error')
            return render_template('cadastro.html')

        # Gera código numérico de 6 dígitos e validade de 15 minutos
        code = f"{secrets.randbelow(1000000):06d}"
        expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        pwd_hash = generate_password_hash(password)

        cursor = db.execute(
            """INSERT INTO users (username, display_name, email, password_hash, is_verified, verification_code, code_expires)
               VALUES (?, ?, ?, ?, 0, ?, ?)""",
            (username, display_name, email, pwd_hash, code, expires)
        )
        db.commit()

        user_id = cursor.lastrowid
        session['pending_user_id'] = user_id

        # Envia e-mail com o código via Resend
        body = f"""
        <div style="font-family: sans-serif; background: #0d0e12; color: #e6e8eb; padding: 20px; border-radius: 8px;">
            <h2>Código de Verificação - Pupe</h2>
            <p>O seu código de verificação é:</p>
            <h1 style="color: #6366f1; letter-spacing: 4px;">{code}</h1>
            <p>Este código expira em 15 minutos.</p>
        </div>
        """
        send_email_resend(email, "Código de Verificação - Pupe", body)

        flash('Código de verificação enviado para o seu e-mail!', 'info')
        return redirect(url_for('verificar_email'))

    return render_template('cadastro.html')


@app.route('/verificar-email', methods=['GET', 'POST'])
def verificar_email():
    user_id = session.get('pending_user_id') or session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        return redirect(url_for('login'))

    if user['is_verified'] == 1:
        session.pop('pending_user_id', None)
        session['user_id'] = user['id']
        return redirect(url_for('index'))

    if request.method == 'POST':
        input_code = request.form.get('code', '').strip()

        if not user['verification_code'] or input_code != user['verification_code']:
            flash('Código incorreto. Verifique e tente novamente.', 'error')
            return render_template('verificar_email.html', email=user['email'])

        if datetime.utcnow() > datetime.fromisoformat(user['code_expires']):
            flash('Este código expirou. Solicite um novo código.', 'error')
            return render_template('verificar_email.html', email=user['email'])

        # Confirma verificação
        db.execute(
            "UPDATE users SET is_verified = 1, verification_code = NULL, code_expires = NULL WHERE id = ?",
            (user['id'],)
        )
        db.commit()

        session.pop('pending_user_id', None)
        session['user_id'] = user['id']

        flash('E-mail verificado com sucesso! Bem-vindo ao Pupe.', 'success')
        return redirect(url_for('index'))

    return render_template('verificar_email.html', email=user['email'])


@app.route('/reenviar-codigo', methods=['POST'])
def reenviar_codigo():
    user_id = session.get('pending_user_id') or session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user and user['is_verified'] == 0:
        new_code = f"{secrets.randbelow(1000000):06d}"
        expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

        db.execute(
            "UPDATE users SET verification_code = ?, code_expires = ? WHERE id = ?",
            (new_code, expires, user['id'])
        )
        db.commit()

        body = f"""
        <div style="font-family: sans-serif; background: #0d0e12; color: #e6e8eb; padding: 20px; border-radius: 8px;">
            <h2>Novo Código de Verificação - Pupe</h2>
            <h1 style="color: #6366f1; letter-spacing: 4px;">{new_code}</h1>
            <p>Válido por 15 minutos.</p>
        </div>
        """
        send_email_resend(user['email'], "Novo Código de Verificação - Pupe", body)
        flash('Novo código enviado para o seu e-mail!', 'info')

    return redirect(url_for('verificar_email'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", (login_input, login_input)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Sessão iniciada com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada.', 'info')
    return redirect(url_for('login'))


@app.route('/configuracoes', methods=['GET', 'POST'])
@login_required
def configuracoes():
    db = get_db()
    user_id = session['user_id']

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            display_name = request.form.get('display_name', '').strip()
            bio = request.form.get('bio', '').strip()
            db.execute("UPDATE users SET display_name = ?, bio = ? WHERE id = ?", (display_name, bio, user_id))
            db.commit()
            flash('Perfil atualizado com sucesso!', 'success')

        elif action == 'update_avatar':
            file = request.files.get('avatar')
            if file and allowed_file(file.filename):
                avatar_base64 = image_to_base64(file)
                db.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_base64, user_id))
                db.commit()
                flash('Foto de perfil alterada!', 'success')
            else:
                flash('Ficheiro de imagem inválido.', 'error')

        elif action == 'change_password':
            current_pwd = request.form.get('current_password', '')
            new_pwd = request.form.get('new_password', '')
            user = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
            if user and check_password_hash(user['password_hash'], current_pwd):
                if len(new_pwd) >= 6:
                    hashed = generate_password_hash(new_pwd)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
                    db.commit()
                    flash('Palavra-passe alterada!', 'success')
                else:
                    flash('A nova palavra-passe deve conter pelo menos 6 caracteres.', 'error')
            else:
                flash('Palavra-passe atual incorreta.', 'error')

        return redirect(url_for('configuracoes'))

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return render_template('configuracoes.html', user=user)


@app.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        db = get_db()
        user = db.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            db.execute("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?", (token, expires, user['id']))
            db.commit()

            reset_url = url_for('redefinir_senha', token=token, _external=True)
            body = f"<h3>Recuperação de Senha - Pupe</h3><p>Acesse o link para redefinir sua senha: <a href='{reset_url}'>{reset_url}</a></p>"
            send_email_resend(email, "Redefinição de Senha - Pupe", body)

        flash('Se o e-mail estiver registado, enviámos as instruções de recuperação.', 'info')
        return redirect(url_for('login'))

    return render_template('esqueci_senha.html')


@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()

    if not user:
        flash('Link de redefinição inválido ou expirado.', 'error')
        return redirect(url_for('esqueci_senha'))

    if datetime.utcnow() > datetime.fromisoformat(user['reset_token_expires']):
        db.execute("UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?", (user['id'],))
        db.commit()
        flash('Link expirado.', 'error')
        return redirect(url_for('esqueci_senha'))

    if request.method == 'POST':
        new_pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')

        if len(new_pwd) < 6 or new_pwd != confirm_pwd:
            flash('Validação de palavra-passe falhou.', 'error')
            return render_template('redefinir_senha.html', token=token)

        hashed = generate_password_hash(new_pwd)
        db.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?", (hashed, user['id']))
        db.commit()
        flash('Palavra-passe alterada! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('redefinir_senha.html', token=token)


# ==========================================
# FEED & POSTS
# ==========================================
@app.route('/')
def index():
    db = get_db()
    posts_raw = db.execute('''
        SELECT p.*, u.username, u.display_name, u.avatar_url 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.group_id IS NULL
        ORDER BY p.created_at DESC
    ''').fetchall()

    posts = []
    current_uid = session.get('user_id')

    for p in posts_raw:
        reactions_raw = db.execute(
            "SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (p['id'],)
        ).fetchall()
        reactions_map = {r['reaction_type']: r['count'] for r in reactions_raw}

        user_reaction = None
        if current_uid:
            u_react = db.execute("SELECT reaction_type FROM reactions WHERE post_id = ? AND user_id = ?", (p['id'], current_uid)).fetchone()
            if u_react:
                user_reaction = u_react['reaction_type']

        comments = db.execute('''
            SELECT c.*, u.username, u.display_name, u.avatar_url
            FROM comments c JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ? ORDER BY c.created_at ASC
        ''', (p['id'],)).fetchall()

        posts.append({
            'id': p['id'], 'user_id': p['user_id'], 'username': p['username'],
            'display_name': p['display_name'], 'avatar_url': p['avatar_url'],
            'content': p['content'], 'image_url': p['image_url'],
            'created_at': p['created_at'], 'updated_at': p['updated_at'],
            'reactions': reactions_map, 'user_reaction': user_reaction, 'comments': comments
        })

    return render_template('index.html', posts=posts)


@app.route('/post/criar', methods=['POST'])
@login_required
def criar_post():
    content = request.form.get('content', '').strip()
    group_id = request.form.get('group_id', None)
    file = request.files.get('image')
    image_base64 = None

    if file and allowed_file(file.filename):
        image_base64 = image_to_base64(file)

    if content or image_base64:
        db = get_db()
        db.execute(
            "INSERT INTO posts (user_id, group_id, content, image_url) VALUES (?, ?, ?, ?)",
            (session['user_id'], group_id if group_id else None, content, image_base64)
        )
        db.commit()
        flash('Publicado com sucesso!', 'success')

    return redirect(request.referrer or url_for('index'))


@app.route('/post/<int:post_id>/editar', methods=['POST'])
@login_required
def editar_post(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post or post['user_id'] != session['user_id']:
        flash('Sem permissão para editar.', 'error')
        return redirect(url_for('index'))

    new_content = request.form.get('content', '').strip()
    if new_content:
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("UPDATE posts SET content = ?, updated_at = ? WHERE id = ?", (new_content, now, post_id))
        db.commit()
        flash('Publicação atualizada!', 'success')

    return redirect(request.referrer or url_for('index'))


@app.route('/post/<int:post_id>/deletar', methods=['POST'])
@login_required
def deletar_post(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post or post['user_id'] != session['user_id']:
        flash('Permissão negada.', 'error')
        return redirect(url_for('index'))

    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash('Publicação removida.', 'success')
    return redirect(request.referrer or url_for('index'))


# ==========================================
# REAÇÕES E COMENTÁRIOS
# ==========================================
@app.route('/post/<int:post_id>/reagir', methods=['POST'])
@login_required
def reagir(post_id):
    reaction_type = request.form.get('reaction_type', 'heart')
    db = get_db()
    user_id = session['user_id']

    existing = db.execute("SELECT * FROM reactions WHERE post_id = ? AND user_id = ?", (post_id, user_id)).fetchone()

    if existing:
        if existing['reaction_type'] == reaction_type:
            db.execute("DELETE FROM reactions WHERE id = ?", (existing['id'],))
        else:
            db.execute("UPDATE reactions SET reaction_type = ? WHERE id = ?", (reaction_type, existing['id']))
    else:
        db.execute("INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)", (post_id, user_id, reaction_type))
        post = db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,)).fetchone()
        if post:
            create_notification(post['user_id'], user_id, 'reaction', post_id, f"reagiu à sua publicação.")

    db.commit()
    return redirect(request.referrer or url_for('index'))


@app.route('/post/<int:post_id>/comentar', methods=['POST'])
@login_required
def comentar(post_id):
    content = request.form.get('content', '').strip()
    if content:
        db = get_db()
        post = db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,)).fetchone()
        if post:
            db.execute("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)", (post_id, session['user_id'], content))
            db.commit()
            create_notification(post['user_id'], session['user_id'], 'comment', post_id, "comentou na sua publicação.")
            flash('Comentário enviado!', 'success')

    return redirect(request.referrer or url_for('index'))


@app.route('/comment/<int:comment_id>/deletar', methods=['POST'])
@login_required
def deletar_comentario(comment_id):
    db = get_db()
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()

    if not comment or comment['user_id'] != session['user_id']:
        flash('Permissão negada.', 'error')
        return redirect(url_for('index'))

    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    flash('Comentário apagado.', 'success')
    return redirect(request.referrer or url_for('index'))


# ==========================================
# PERFIL PÚBLICO & SEGUIDORES
# ==========================================

@app.route('/@<username>')
@app.route('/user/<username>')
def perfil_usuario(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        flash('Utilizador não encontrado.', 'error')
        return redirect(url_for('index'))

    posts = db.execute("SELECT * FROM posts WHERE user_id = ? AND group_id IS NULL ORDER BY created_at DESC", (user['id'],)).fetchall()
    followers_count = db.execute("SELECT COUNT(*) as count FROM follows WHERE followed_id = ?", (user['id'],)).fetchone()['count']
    following_count = db.execute("SELECT COUNT(*) as count FROM follows WHERE follower_id = ?", (user['id'],)).fetchone()['count']

    is_following = False
    if 'user_id' in session:
        is_following = bool(db.execute("SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?", (session['user_id'], user['id'])).fetchone())

    # Procura a Pupe Page ativa do utilizador
    pupe_page = db.execute("SELECT * FROM pupe_pages WHERE user_id = ? AND is_active = 1", (user['id'],)).fetchone()

    return render_template(
        'perfil.html',
        profile_user=user,
        posts=posts,
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
        pupe_page=pupe_page
    )

@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def seguir_usuario(user_id):
    if user_id != session['user_id']:
        db = get_db()
        try:
            db.execute("INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)", (session['user_id'], user_id))
            db.commit()
            create_notification(user_id, session['user_id'], 'follow', message="começou a seguir-te.")
        except Exception:
            pass
    return redirect(request.referrer or url_for('index'))


@app.route('/user/<int:user_id>/unfollow', methods=['POST'])
@login_required
def deixar_de_seguir(user_id):
    db = get_db()
    db.execute("DELETE FROM follows WHERE follower_id = ? AND followed_id = ?", (session['user_id'], user_id))
    db.commit()
    return redirect(request.referrer or url_for('index'))


# ==========================================
# PUPE PAGES (FEATURE 6 - FUNCIONAL)
# ==========================================
@app.route('/pages/editor', methods=['GET', 'POST'])
@login_required
def pupe_page_editor():
    db = get_db()
    user_id = session['user_id']
    
    # Procura o utilizador para obter o username correto
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    page = db.execute("SELECT * FROM pupe_pages WHERE user_id = ?", (user_id,)).fetchone()

    if request.method == 'POST':
        html_raw = request.form.get('html_content', '')

        # Limite de 20 KB
        if len(html_raw.encode('utf-8')) > MAX_PAGE_SIZE_BYTES:
            flash('O tamanho máximo permitido para a sua Pupe Page é 20 KB.', 'error')
            return render_template('pupe_page_editor.html', page=page, html_content=html_raw)

        # Sanitização contra XSS / Script Ingestion
        clean_html = sanitize_html(html_raw)

        if page:
            db.execute(
                "UPDATE pupe_pages SET html_content = ?, is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (clean_html, user_id)
            )
        else:
            db.execute(
                "INSERT INTO pupe_pages (user_id, html_content) VALUES (?, ?)",
                (user_id, clean_html)
            )
        db.commit()
        flash('Pupe Page guardada e publicada com sucesso!', 'success')
        
        # Redirecionamento corrigido usando user['username']
        return redirect(url_for('ver_pupe_page', username=user['username']))

    return render_template('pupe_page_editor.html', page=page)


@app.route('/@<username>/page')
def ver_pupe_page(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return "Utilizador não encontrado", 404

    page = db.execute("SELECT * FROM pupe_pages WHERE user_id = ? AND is_active = 1", (user['id'],)).fetchone()
    if not page:
        return "Página não encontrada", 404

    # Documento HTML isolado para o iframe
    wrapper = f"""<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            margin: 0;
            padding: 1.25rem;
            background: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 0.92rem;
            line-height: 1.6;
            word-break: break-word;
        }}
        img {{
            max-width: 100%;
            border-radius: 6px;
        }}
    </style>
</head>
<body>
    {page['html_content']}
</body>
</html>"""
    return render_template_string(wrapper)


# ==========================================
# GRUPOS (SISTEMA COM CORES E DETALHES)
# ==========================================
@app.route('/grupos')
def lista_grupos():
    db = get_db()
    groups = db.execute("SELECT g.*, u.username as owner_name FROM groups g JOIN users u ON g.owner_id = u.id ORDER BY g.created_at DESC").fetchall()
    return render_template('grupos.html', groups=groups)


@app.route('/grupo/criar', methods=['POST'])
@login_required
def criar_grupo():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    theme_color = request.form.get('theme_color', '#6366f1')

    if name:
        db = get_db()
        cursor = db.execute(
            "INSERT INTO groups (name, description, theme_color, owner_id) VALUES (?, ?, ?, ?)",
            (name, description, theme_color, session['user_id'])
        )
        group_id = cursor.lastrowid
        db.execute(
            "INSERT INTO group_members (group_id, user_id, role, status) VALUES (?, ?, 'owner', 'approved')",
            (group_id, session['user_id'])
        )
        db.commit()
        flash('Grupo criado com sucesso!', 'success')
        return redirect(url_for('detalhes_grupo', group_id=group_id))

    return redirect(url_for('lista_grupos'))


@app.route('/grupo/<int:group_id>')
def detalhes_grupo(group_id):
    db = get_db()
    group = db.execute("SELECT g.*, u.username as owner_name FROM groups g JOIN users u ON g.owner_id = u.id WHERE g.id = ?", (group_id,)).fetchone()
    if not group:
        flash('Grupo não encontrado.', 'error')
        return redirect(url_for('lista_grupos'))

    members_count = db.execute("SELECT COUNT(*) as count FROM group_members WHERE group_id = ?", (group_id,)).fetchone()['count']

    is_member = False
    if 'user_id' in session:
        is_member = bool(db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, session['user_id'])).fetchone())

    posts = db.execute('''
        SELECT p.*, u.username, u.display_name, u.avatar_url 
        FROM posts p JOIN users u ON p.user_id = u.id 
        WHERE p.group_id = ? ORDER BY p.created_at DESC
    ''', (group_id,)).fetchall()

    return render_template('grupo_detalhes.html', group=group, members_count=members_count, is_member=is_member, posts=posts)


@app.route('/grupo/<int:group_id>/entrar', methods=['POST'])
@login_required
def entrar_grupo(group_id):
    db = get_db()
    try:
        db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, session['user_id']))
        db.commit()
        flash('Entrou no grupo!', 'success')
    except Exception:
        pass
    return redirect(url_for('detalhes_grupo', group_id=group_id))


@app.route('/grupo/<int:group_id>/sair', methods=['POST'])
@login_required
def sair_grupo(group_id):
    db = get_db()
    db.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, session['user_id']))
    db.commit()
    flash('Saiu do grupo.', 'info')
    return redirect(url_for('detalhes_grupo', group_id=group_id))


# ==========================================
# NOTIFICAÇÕES
# ==========================================
@app.route('/notificacoes')
@login_required
def notificacoes():
    db = get_db()
    notifs = db.execute('''
        SELECT n.*, u.username, u.display_name, u.avatar_url
        FROM notifications n JOIN users u ON n.actor_id = u.id
        WHERE n.user_id = ? ORDER BY n.created_at DESC
    ''', (session['user_id'],)).fetchall()

    db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
    db.commit()

    return render_template('notificacoes.html', notifications=notifs)


# Execução do Servidor
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
