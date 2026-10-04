import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'pupe-secret-key-change-in-production')

# Configurações de Upload
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de 16MB por upload

# Configurações do Resend
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
SENDER_EMAIL = 'noreply@pupe.lovie.me'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ==========================================
# BANCO DE DADOS & MIGRAÇÕES
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

        # Tabela de Usuários
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

        # Tabela de Posts
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

        # Tabela de Comentários
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

        # Tabela de Reações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reaction_type TEXT DEFAULT '🤍',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(post_id, user_id, reaction_type),
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Tabela de Seguidores
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

        # Tabela de Grupos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                avatar_url TEXT DEFAULT '/static/default-group.png',
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Membros dos Grupos
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

        # Tabela de Notificações
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
# DECORADORES E AUXILIARES
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para continuar.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email_resend(to_email, subject, html_content):
    """Envia e-mails utilizando a API HTTP oficial do Resend."""
    if not RESEND_API_KEY:
        print(f"[DEV MAIL LOG] Para: {to_email} | Assunto: {subject}\nConteúdo: {html_content}")
        return True

    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {RESEND_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'from': f'Pupe <{SENDER_EMAIL}>',
                'to': [to_email],
                'subject': subject,
                'html': html_content
            },
            timeout=10
        )
        return response.status_code in (200, 201)
    except Exception as e:
        print(f"[ERRO RESEND] Falha no envio para {to_email}: {e}")
        return False

def create_notification(user_id, actor_id, notif_type, target_id=None, message=""):
    """Gera uma notificação no sistema para o usuário destino."""
    if user_id == actor_id:
        return  # Não notifica a si mesmo
    db = get_db()
    db.execute(
        '''INSERT INTO notifications (user_id, actor_id, type, target_id, message) 
           VALUES (?, ?, ?, ?, ?)''',
        (user_id, actor_id, notif_type, target_id, message)
    )
    db.commit()

@app.context_processor
def inject_user_context():
    """Injeta o usuário logado e notificações não lidas em todos os templates."""
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
# ROTAS DE AUTENTICAÇÃO E CONTA
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
        existing = db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
        if existing:
            flash('Nome de usuário ou e-mail já cadastrado.', 'error')
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
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (login_input, login_input)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas. Tente novamente.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))


@app.route('/configuracoes', methods=['GET', 'POST'])
@login_required
def configuracoes():
    db = get_db()
    user_id = session['user_id']

    if request.method == 'POST':
        action = request.form.get('action')

        # Alterar Nome e Bio
        if action == 'update_profile':
            display_name = request.form.get('display_name', '').strip()
            bio = request.form.get('bio', '').strip()
            db.execute(
                "UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                (display_name, bio, user_id)
            )
            db.commit()
            flash('Perfil atualizado com sucesso!', 'success')

        # Alterar Foto de Perfil
        elif action == 'update_avatar':
            file = request.files.get('avatar')
            if file and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"avatar_{user_id}_{secrets.token_hex(4)}.{ext}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                avatar_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"
                db.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
                db.commit()
                flash('Foto de perfil alterada com sucesso!', 'success')
            else:
                flash('Arquivo de imagem inválido.', 'error')

        # Alterar Senha
        elif action == 'change_password':
            current_pwd = request.form.get('current_password', '')
            new_pwd = request.form.get('new_password', '')

            user = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
            if user and check_password_hash(user['password_hash'], current_pwd):
                if len(new_pwd) >= 6:
                    hashed = generate_password_hash(new_pwd)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
                    db.commit()
                    flash('Senha alterada com sucesso!', 'success')
                else:
                    flash('A nova senha deve conter pelo menos 6 caracteres.', 'error')
            else:
                flash('Senha atual incorreta.', 'error')

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
            db.execute(
                "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
                (token, expires, user['id'])
            )
            db.commit()

            reset_url = url_for('redefinir_senha', token=token, _external=True)
            body = f"""
            <h3>Recuperação de Senha - Pupe</h3>
            <p>Clique no link abaixo para criar uma nova senha para sua conta:</p>
            <p><a href="{reset_url}">{reset_url}</a></p>
            <p>Este link expira em 1 hora.</p>
            """
            send_email_resend(email, "Redefinição de Senha - Pupe", body)

        flash('Se o e-mail estiver cadastrado, enviamos as instruções de recuperação.', 'info')
        return redirect(url_for('login'))

    return render_template('esqueci_senha.html')


@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()

    if not user:
        flash('Link de redefinição inválido ou expirado.', 'error')
        return redirect(url_for('esqueci_senha'))

    expires_at = datetime.fromisoformat(user['reset_token_expires'])
    if datetime.utcnow() > expires_at:
        db.execute("UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?", (user['id'],))
        db.commit()
        flash('Este link de redefinição expirou. Solicite um novo.', 'error')
        return redirect(url_for('esqueci_senha'))

    if request.method == 'POST':
        new_pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')

        if len(new_pwd) < 6:
            flash('A senha deve ter no mínimo 6 caracteres.', 'error')
            return render_template('redefinir_senha.html', token=token)

        if new_pwd != confirm_pwd:
            flash('As senhas não coincidem.', 'error')
            return render_template('redefinir_senha.html', token=token)

        hashed = generate_password_hash(new_pwd)
        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            (hashed, user['id'])
        )
        db.commit()

        flash('Senha redefinida com sucesso! Faça login.', 'success')
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
        # Busca reações por tipo para o post
        reactions_raw = db.execute('''
            SELECT reaction_type, COUNT(*) as count 
            FROM reactions WHERE post_id = ? 
            GROUP BY reaction_type
        ''', (p['id'],)).fetchall()

        reactions_map = {r['reaction_type']: r['count'] for r in reactions_raw}

        # Verifica qual reação o usuário logado deu
        user_reaction = None
        if current_uid:
            u_react = db.execute('''
                SELECT reaction_type FROM reactions WHERE post_id = ? AND user_id = ?
            ''', (p['id'], current_uid)).fetchone()
            if u_react:
                user_reaction = u_react['reaction_type']

        # Busca comentários
        comments = db.execute('''
            SELECT c.*, u.username, u.display_name, u.avatar_url
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        ''', (p['id'],)).fetchall()

        posts.append({
            'id': p['id'],
            'user_id': p['user_id'],
            'username': p['username'],
            'display_name': p['display_name'],
            'avatar_url': p['avatar_url'],
            'content': p['content'],
            'image_url': p['image_url'],
            'created_at': p['created_at'],
            'updated_at': p['updated_at'],
            'reactions': reactions_map,
            'user_reaction': user_reaction,
            'comments': comments
        })

    return render_template('index.html', posts=posts)


@app.route('/post/criar', methods=['POST'])
@login_required
def criar_post():
    content = request.form.get('content', '').strip()
    file = request.files.get('image')
    image_url = None

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"post_{session['user_id']}_{secrets.token_hex(4)}.{ext}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        image_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"

    if content or image_url:
        db = get_db()
        db.execute(
            "INSERT INTO posts (user_id, content, image_url) VALUES (?, ?, ?)",
            (session['user_id'], content, image_url)
        )
        db.commit()
        flash('Publicado!', 'success')
    else:
        flash('O post não pode estar vazio.', 'error')

    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_post(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post:
        flash('Post não encontrado.', 'error')
        return redirect(url_for('index'))

    # Validação de Propriedade
    if post['user_id'] != session['user_id']:
        flash('Você não tem permissão para editar este post.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_content = request.form.get('content', '').strip()
        if new_content:
            now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            db.execute(
                "UPDATE posts SET content = ?, updated_at = ? WHERE id = ?",
                (new_content, now, post_id)
            )
            db.commit()
            flash('Post atualizado!', 'success')
            return redirect(url_for('index'))
        else:
            flash('O conteúdo não pode ser vazio.', 'error')

    return render_template('editar_post.html', post=post)


@app.route('/post/<int:post_id>/deletar', methods=['POST'])
@login_required
def deletar_post(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post:
        flash('Post não encontrado.', 'error')
        return redirect(url_for('index'))

    # Validação de Propriedade
    if post['user_id'] != session['user_id']:
        flash('Permissão negada.', 'error')
        return redirect(url_for('index'))

    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash('Post removido.', 'success')
    return redirect(url_for('index'))


# ==========================================
# COMENTÁRIOS & REAÇÕES
# ==========================================
@app.route('/post/<int:post_id>/comentar', methods=['POST'])
@login_required
def comentar(post_id):
    content = request.form.get('content', '').strip()
    if content:
        db = get_db()
        post = db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,)).fetchone()
        if post:
            db.execute(
                "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
                (post_id, session['user_id'], content)
            )
            db.commit()

            # Notificar autor do post
            create_notification(post['user_id'], session['user_id'], 'comment', post_id, "comentou no seu post.")
            flash('Comentário publicado!', 'success')

    return redirect(url_for('index'))


@app.route('/comment/<int:comment_id>/editar', methods=['POST'])
@login_required
def editar_comentario(comment_id):
    db = get_db()
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()

    if not comment or comment['user_id'] != session['user_id']:
        flash('Ação não permitida.', 'error')
        return redirect(url_for('index'))

    new_content = request.form.get('content', '').strip()
    if new_content:
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("UPDATE comments SET content = ?, updated_at = ? WHERE id = ?", (new_content, now, comment_id))
        db.commit()
        flash('Comentário atualizado!', 'success')

    return redirect(url_for('index'))


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
    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/reagir', methods=['POST'])
@login_required
def reagir(post_id):
    reaction_type = request.form.get('reaction_type', '🤍')
    db = get_db()
    user_id = session['user_id']

    existing = db.execute(
        "SELECT * FROM reactions WHERE post_id = ? AND user_id = ?",
        (post_id, user_id)
    ).fetchone()

    if existing:
        if existing['reaction_type'] == reaction_type:
            # Remove reação idêntica
            db.execute("DELETE FROM reactions WHERE id = ?", (existing['id'],))
        else:
            # Atualiza tipo de reação
            db.execute("UPDATE reactions SET reaction_type = ? WHERE id = ?", (reaction_type, existing['id']))
    else:
        # Adiciona nova reação
        db.execute(
            "INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
            (post_id, user_id, reaction_type)
        )
        post = db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,)).fetchone()
        if post:
            create_notification(post['user_id'], user_id, 'reaction', post_id, f"reagiu com {reaction_type} ao seu post.")

    db.commit()
    return redirect(url_for('index'))


# ==========================================
# PERFIL PÚBLICO & SEGUIDORES
# ==========================================
@app.route('/@<username>')
@app.route('/user/<username>')
def perfil_usuario(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        flash('Usuário não encontrado.', 'error')
        return redirect(url_for('index'))

    posts = db.execute(
        "SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC",
        (user['id'],)
    ).fetchall()

    followers_count = db.execute(
        "SELECT COUNT(*) as count FROM follows WHERE followed_id = ?", (user['id'],)
    ).fetchone()['count']

    following_count = db.execute(
        "SELECT COUNT(*) as count FROM follows WHERE follower_id = ?", (user['id'],)
    ).fetchone()['count']

    is_following = False
    if 'user_id' in session:
        check_follow = db.execute(
            "SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?",
            (session['user_id'], user['id'])
        ).fetchone()
        is_following = bool(check_follow)

    return render_template(
        'perfil.html',
        profile_user=user,
        posts=posts,
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following
    )


@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def seguir_usuario(user_id):
    if user_id != session['user_id']:
        db = get_db()
        try:
            db.execute(
                "INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)",
                (session['user_id'], user_id)
            )
            db.commit()
            create_notification(user_id, session['user_id'], 'follow', message="começou a seguir você.")
        except sqlite3.IntegrityError:
            pass  # Já segue
    return redirect(request.referrer or url_for('index'))


@app.route('/user/<int:user_id>/unfollow', methods=['POST'])
@login_required
def deixar_de_seguir(user_id):
    db = get_db()
    db.execute(
        "DELETE FROM follows WHERE follower_id = ? AND followed_id = ?",
        (session['user_id'], user_id)
    )
    db.commit()
    return redirect(request.referrer or url_for('index'))


# ==========================================
# NOTIFICAÇÕES
# ==========================================
@app.route('/notificacoes')
@login_required
def notificacoes():
    db = get_db()
    notifs = db.execute('''
        SELECT n.*, u.username, u.display_name, u.avatar_url
        FROM notifications n
        JOIN users u ON n.actor_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
    ''', (session['user_id'],)).fetchall()

    # Marca como lidas ao visualizar
    db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
    db.commit()

    return render_template('notificacoes.html', notifications=notifs)


# ==========================================
# GRUPOS
# ==========================================
@app.route('/grupos')
def lista_grupos():
    db = get_db()
    groups = db.execute("SELECT * FROM groups ORDER BY created_at DESC").fetchall()
    return render_template('grupos.html', groups=groups)


@app.route('/grupo/criar', methods=['POST'])
@login_required
def criar_grupo():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()

    if name:
        db = get_db()
        cursor = db.execute(
            "INSERT INTO groups (name, description, owner_id) VALUES (?, ?, ?)",
            (name, description, session['user_id'])
        )
        group_id = cursor.lastrowid
        # Adiciona o criador como admin do grupo
        db.execute(
            "INSERT INTO group_members (group_id, user_id, role, status) VALUES (?, ?, 'owner', 'approved')",
            (group_id, session['user_id'])
        )
        db.commit()
        flash('Grupo criado com sucesso!', 'success')

    return redirect(url_for('lista_grupos'))


# ==========================================
# EXECUÇÃO DO SERVIDOR
# ==========================================
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
