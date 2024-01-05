import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from passbox.db import get_db

# Definizione del Blueprint per l'autenticazione
bp = Blueprint('auth', __name__, url_prefix='/auth')

# Route per la registrazione di un nuovo utente
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        # Ottenimento dei dati dal modulo di registrazione
        email = request.form['email']
        username = request.form['username']
        cell = request.form['cell']
        nome = request.form['nome']
        cognome = request.form['cognome']
        birth = request.form['birth']
        password1 = request.form['pwd']
        password2 = request.form['pwd_repeat']

        db = get_db()
        error = None

        # Verifica se le password corrispondono
        if not password1 == password2:
            error = 'Passwords do not match'
        # Altre verifiche dei dati inseriti
        elif not username:
            error = 'Username is required.'
        elif not password1:
            error = 'Password is required.'

        if error is None:
            try:
                # Inserimento dei dati nel database
                db.execute(
                    "INSERT INTO UTENTE (NOME, COGNOME, USERNAME, EMAIL, N_TEL, DATA_DI_NASCITA, PASSWORD) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (nome, cognome, username, email, cell, birth, generate_password_hash(password1)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

# Route per l'accesso di un utente esistente
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['pwd']
        db = get_db()
        error = None

        # Recupero dell'utente dal database
        user = db.execute(
            'SELECT * FROM UTENTE WHERE EMAIL = ?', (email,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        # Verifica della corrispondenza della password
        elif not check_password_hash(user['PASSWORD'], password):
            error = 'Incorrect password.'

        if error is None:
            # Autenticazione dell'utente e reindirizzamento alla pagina principale
            session.clear()
            session['user_id'] = user['ID_USER']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

# Funzione eseguita prima di ogni richiesta per caricare l'utente autenticato
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM UTENTE WHERE ID_USER = ?', (user_id,)
        ).fetchone()

# Route per il logout dell'utente
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

# Decoratore che assicura che solo gli utenti autenticati possano accedere a determinate route
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

# Funzione che verifica se un utente è un'azienda
def is_business(id):
    business = get_db().execute(
        'SELECT * FROM BUSINESS WHERE ID_BUSINESS = ?', (id,)
    ).fetchone()
    return business

# Funzione che verifica se un utente ha un account premium
def is_premium(id):
    premium = get_db().execute(
        'SELECT * FROM PREMIUM WHERE ID_PREMIUM = ?', (id,)
    ).fetchone()
    return premium

# Decoratore che assicura che solo gli utenti con account Business possano accedere a determinate route
def business_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if is_business(g.user['ID_USER']) is None:
            flash('You need a business account.', 'noBusiness')
            return redirect(url_for('vault.pricing'))

        return view(**kwargs)

    return wrapped_view

# Decoratore che assicura che solo gli utenti con account Premium o Business possano accedere a determinate route
def premium_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if is_premium(g.user['ID_USER']) is None and is_business(g.user['ID_USER']) is None:
            flash('You need a premium account.', 'noPremium')
            return redirect(url_for('vault.pricing'))

        return view(**kwargs)

    return wrapped_view