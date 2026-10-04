import os
import sqlite3
from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Importação condicional do LibSQL (Turso)
try:
    import libsql
    USING_LIBSQL = True
except ImportError:
    USING_LIBSQL = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave-secreta-dev-pupe-2026')

# ==========================================
# BANCO DE DADOS & INICIALIZAÇÃO
# ==========================================
TURSO_DATABASE_URL = os.environ.get('TURSO_DATABASE_URL', 'pupe.db')
TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '')


class DictRow(dict):
    """Permite aceder aos campos tanto por chave dict['campo'] como por índice dict[0]."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def fetchone_dict(cursor):
    """Executa fetchone e converte o resultado num dicionário acessível por chave e índice."""
    row = cursor.fetchone()
    if not row:
        return None
    if isinstance(row, sqlite3.Row):
        return row
    if isinstance(row, dict):
        return row
    cols = [column[0] for column in cursor.description]
    return DictRow(zip(cols, row))


def fetchall_dict(cursor):
    """Executa fetchall e converte todos os resultados em dicionários acessíveis por chave."""
    rows = cursor.fetchall()
    if not rows:
        return []
    if cursor.description:
        cols = [column[0] for column in cursor.description]
        return [DictRow(zip(cols, r)) if not isinstance(r, (sqlite3.Row, dict)) else r for r in rows]
    return rows


def get_db():
    """Retorna a conexão ativa do banco de dados (SQLite local ou Turso remoto)."""
    if 'db' not in g:
        is_remote = TURSO_DATABASE_URL.startswith(('libsql://', 'https://'))

        if is_remote:
            if not USING_LIBSQL:
                raise ImportError("O pacote 'libsql' não está instalado no ambiente.")
            g.db = libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)
        else:
            g.db = sqlite3.connect(TURSO_DATABASE_URL)
            g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Fecha a conexão do banco de dados ao encerrar o request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Cria as tabelas iniciais caso não existam."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_code TEXT,
            code_expires TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    db.commit()


# ==========================================
# CONTEXT PROCESSORS & INJEÇÃO GLOBAL
# ==========================================
@app.context_processor
def inject_user_context():
    """Injeta as variáveis `current_user` e `unread_notifications` nos templates Jinja2."""
    if 'user_id' in session:
        try:
            db = get_db()
            cursor = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
            user = fetchone_dict(cursor)

            if not user:
                session.pop('user_id', None)
                return dict(current_user=None, unread_notifications=0)

            unread_cursor = db.execute(
                "SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0",
                (session['user_id'],)
            )
            unread_row = fetchone_dict(unread_cursor)

            unread_count = unread_row['count'] if unread_row else 0
            return dict(current_user=user, unread_notifications=unread_count)
        except Exception as e:
            app.logger.error(f"Erro no context_processor: {e}")
            return dict(current_user=None, unread_notifications=0)

    return dict(current_user=None, unread_notifications=0)


# ==========================================
# ROTAS DA APLICAÇÃO
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash('Preencha todos os campos obrigatórios.', 'error')
            return render_template('cadastro.html')

        db = get_db()
        cursor = db.execute("SELECT id FROM users WHERE email = ?", (email,))
        if fetchone_dict(cursor):
            flash('Este e-mail já está cadastrado.', 'error')
            return render_template('cadastro.html')

        # Gerar código de verificação simples (ex: 6 dígitos)
        verification_code = '123456'  # Substituir por gerador aleatório na produção
        code_expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

        cursor = db.execute(
            """INSERT INTO users (name, email, password, is_verified, verification_code, code_expires)
               VALUES (?, ?, ?, 0, ?, ?)""",
            (name, email, password, verification_code, code_expires)
        )
        db.commit()

        # Obter ID do usuário recém-criado
        new_user_id = cursor.lastrowid
        if not new_user_id:
            c = db.execute("SELECT id FROM users WHERE email = ?", (email,))
            user_rec = fetchone_dict(c)
            new_user_id = user_rec['id']

        session['pending_user_id'] = new_user_id
        flash('Cadastro realizado! Verifique seu e-mail para ativar a conta.', 'info')
        return redirect(url_for('verificar_email'))

    return render_template('cadastro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        cursor = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = fetchone_dict(cursor)

        if not user or user['password'] != password:
            flash('E-mail ou senha incorretos.', 'error')
            return render_template('login.html')

        if user['is_verified'] == 0:
            session['pending_user_id'] = user['id']
            flash('Por favor, verifique seu e-mail antes de fazer login.', 'warning')
            return redirect(url_for('verificar_email'))

        session['user_id'] = user['id']
        flash('Login realizado com sucesso!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/verificar-email', methods=['GET', 'POST'])
def verificar_email():
    user_id = session.get('pending_user_id') or session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = fetchone_dict(cursor)

    if not user:
        return redirect(url_for('login'))

    # Se já estiver verificado, redireciona para a página principal
    if user['is_verified'] == 1:
        session.pop('pending_user_id', None)
        session['user_id'] = user['id']
        return redirect(url_for('index'))

    if request.method == 'POST':
        input_code = request.form.get('code', '').strip()

        if not user['verification_code'] or input_code != user['verification_code']:
            flash('Código incorreto. Verifique e tente novamente.', 'error')
            return render_template('verificar_email.html', email=user['email'])

        if user['code_expires'] and datetime.utcnow() > datetime.fromisoformat(user['code_expires']):
            flash('Este código expirou. Solicite um novo código.', 'error')
            return render_template('verificar_email.html', email=user['email'])

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


@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))


# ==========================================
# INICIALIZAÇÃO DO SERVIDOR
# ==========================================
with app.app_context():
    try:
        init_db()
    except Exception as e:
        app.logger.warning(f"Não foi possível inicializar o banco automaticamente: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
