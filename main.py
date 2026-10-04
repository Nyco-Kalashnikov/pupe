import os
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
# BANCO DE DADOS & INICIALIZAÇÃO
# ==========================================
DATABASE = 'pupe.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Cria e atualiza o esquema do banco de dados SQLite."""
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

        db.commit()


# ==========================================
# SANITIZAÇÃO PUPE PAGES & DECORADORES
# ==========================================
def sanitize_html(html_str):
    """Sanitiza HTML removendo JavaScript, scripts, e tags perigosas para Pupe Pages."""
    if not html_str:
        return ""
    # Remove tags <script>
    clean = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', html_str, flags=re.IGNORECASE)
    # Remove tags perigosas
    clean = re.sub(r'<(iframe|object|embed|form|base|meta)\b[^>]*>', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'</(iframe|object|embed|form|base|meta)>', '', clean, flags=re.IGNORECASE)
    # Remove manipuladores de evento inline (onclick, onload, onerror, etc.)
    clean = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'\son\w+\s*=\s*[^"\s>]+', '', clean, flags=re.IGNORECASE)
    # Remove links javascript:
    clean = re.sub(r'href\s*=\s*["\']\s*javascript:[^"\']*["\']', 'href="#"', clean, flags=re.IGNORECASE)
    clean = re.sub(r'src\s*=\s*["\']\s*javascript:[^"\']*["\']', 'src="#"', clean, flags=re.IGNORECASE)
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

        pwd_hash = generate_password_hash(password)
        cursor = db.execute(
            "INSERT INTO users (username, display_name, email, password_hash) VALUES (?, ?, ?, ?)",
            (username, display_name, email, pwd_hash)
        )
        db.commit()

        session['user_id'] = cursor.lastrowid
        flash('Conta criada com sucesso! Bem-vindo ao Pupe.', 'success')
        return redirect(url_for('index'))

    return render_template('cadastro.html')


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
        except sqlite3.IntegrityError:
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
        flash('Utilizador não encontrado.', 'error')
        return redirect(url_for('index'))

    page = db.execute("SELECT * FROM pupe_pages WHERE user_id = ? AND is_active = 1", (user['id'],)).fetchone()
    if not page:
        flash('Este utilizador ainda não criou uma Pupe Page.', 'info')
        return redirect(url_for('perfil_usuario', username=username))

    # Renderiza com sandbox básico e estilo escuro padrão de isolamento
    wrapper = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
        <meta charset="UTF-8">
        <title>Pupe Page - @{username}</title>
        <style>
            body {{ margin: 0; padding: 20px; background: #0b0c10; color: #e6e8eb; font-family: sans-serif; }}
            .pupe-page-bar {{ background: #16181e; padding: 10px 20px; border-bottom: 1px solid #272a34; display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem; }}
            .pupe-page-bar a {{ color: #6366f1; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="pupe-page-bar">
            <span>Pupe Page de <strong>@{username}</strong></span>
            <a href="/@{username}">← Voltar ao Perfil</a>
        </div>
        <div class="pupe-page-container">
            {page['html_content']}
        </div>
    </body>
    </html>
    """
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
    except sqlite3.IntegrityError:
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