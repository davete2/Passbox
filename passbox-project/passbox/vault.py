from datetime import datetime
import hashlib
import requests
import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, make_response, jsonify, session,
)
from werkzeug.exceptions import abort
from werkzeug.utils import secure_filename

from passbox.auth import login_required
from passbox.auth import business_required
from passbox.auth import premium_required
from passbox.db import get_db

# Definizione del Blueprint per le funzionalità della "vault"
bp = Blueprint('vault', __name__)


# Route per il generatore di password
@bp.route('/password_generator')
@login_required
@premium_required
def password_generator():
    return render_template("vault/password_generator.html")


# Route per il controllo della sicurezza di una password
@bp.route('/password_checker', methods=('GET', 'POST'))
@login_required
@premium_required
def password_checker():
    if request.method == 'POST':
        password = request.form['password']
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        prefix = sha1_password[:5]

        api_url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(api_url)

        if response.status_code == 200:
            pwned = False
            hashes = response.text.splitlines()
            for hash in hashes:
                if sha1_password[5:] in hash:
                    flash('La password è stata compromessa! Cambiala al più presto.', 'pwned')
                    pwned = True
            if not pwned:
                flash('La password è sicura.', 'secure')
        else:
            flash('Errore durante la verifica della password.', 'error')

    return render_template("vault/password_checker.html")


# Route per visualizzare il profilo dell'utente
@bp.route('/profilo')
@login_required
def profilo():
    return render_template("vault/profilo.html")


# Route principale
@bp.route('/')
def index():
    return render_template('vault/index.html')


# Route per visualizzare la "password vault" dell'utente
@bp.route('/password_vault')
@login_required
def password_vault():
    db = get_db()
    id = session['user_id']
    passwords = db.execute(
        'SELECT * FROM CREDENZIALI WHERE ID_UTENTE = (?)',
        (id,)
    ).fetchall()
    return render_template("vault/password_vault.html", passwords=passwords)


# Route per aggiungere una nuova password alla "password vault"
@bp.route('/password_vault/create', methods=['POST'])
def add_password():
    db = get_db()
    req = request.get_json()

    email = req['email']
    password = req['password']
    url = req['url']
    titolo = req['titolo']
    note = req['note']
    id_utente = session['user_id']

    try:
        db.execute(
            "INSERT INTO CREDENZIALI (TITOLO, EMAIL_CRED, PASSWORD_CRED, URL,NOTE, ID_UTENTE) VALUES (?, ?, ?, ?, ?, ?)",
            (titolo, email, password, url, note, id_utente),
        )
        db.commit()
    except db.IntegrityError:
        print("Error in add-password query")
    else:
        print("Password added to database")
        return redirect(url_for("vault.password_vault"))

    res = make_response(jsonify({"message": "JSON received"}), 200)
    return redirect(url_for('vault.password_vault'))


# Route per visualizzare i dettagli di una singola password
@bp.route('/password/<int:id>', methods=['GET'])
@login_required
def render_password(id):
    cred = get_credential(id)
    return render_template("vault/password.html", cred=cred)


# Route per aggiornare una password esistente
@bp.route('/password/update', methods=['POST'])
@login_required
def update_password():
    req = request.get_json()
    email = req['email']
    password = req['password']
    url = req['url']
    titolo = req['titolo']
    id = req['id']
    note = req['note']

    db = get_db()
    db.execute(
        'UPDATE CREDENZIALI SET TITOLO = ?, EMAIL_CRED = ?,URL = ?,PASSWORD_CRED = ?, NOTE = ?'
        ' WHERE ID_CRED = ?',
        (titolo, email, url, password, note, id)
    )
    db.commit()
    return redirect(url_for("vault.password_vault"))


# Route per eliminare una password dalla "password vault"
@bp.route('/password_vault/delete/<int:id>', methods=['POST'])
@login_required
def delete_from_vault(id):
    db = get_db()
    db.execute('DELETE FROM CREDENZIALI WHERE ID_CRED = ?', (id,))
    db.commit()
    return redirect(url_for('vault.password_vault'))


# Route per cercare le password nella "password vault"
@bp.route('/password_vault/search', methods=['POST'])
@login_required
def password_search():
    db = get_db()
    if request.method == 'POST':
        titolo = request.form['titoloSearch']
        user_id = g.user['ID_USER']
        passwords = db.execute(
            'SELECT * FROM CREDENZIALI WHERE TITOLO = (?) AND  ID_UTENTE = (?)',
            (titolo, user_id,)
        ).fetchall()

    return render_template("vault/password_vault.html", passwords=passwords)


# Route per aggiornare l'account a un piano Premium
@bp.route('/add_premium', methods=['POST'])
@login_required
def add_premium():
    id = g.user['ID_USER']
    data_inizio = datetime.now().strftime("%Y-%m-%d")
    prezzo = 15

    db = get_db()
    try:
        db.execute(
            'INSERT INTO PREMIUM (ID_PREMIUM, DATA_INIZIO, PREZZO) VALUES (?, ?, ?)',
            (id, data_inizio, prezzo),
        )
        db.commit()

    except db.IntegrityError:
        error = "error"
    return render_template("vault/pricing.html")


# Route per aggiornare l'account a un piano Business
@bp.route('/add_business', methods=['POST'])
@login_required
def add_business():
    id = g.user['ID_USER']
    data_inizio = datetime.now().strftime("%Y-%m-%d")
    prezzo = 30

    db = get_db()

    try:
        db.execute(
            'INSERT INTO BUSINESS (ID_BUSINESS, DATA_INIZIO, PREZZO) VALUES (?, ?, ?)',
            (id, data_inizio, prezzo),
        )

        db.commit()
    except db.IntegrityError:
        error = "error"

    return render_template("vault/pricing.html")


# Route per creare un nuovo gruppo
@bp.route('/group_list', methods=['GET', 'POST'])
@login_required
@business_required
def create_group():
    db = get_db()
    id = g.user['ID_USER']

    if request.method == 'POST':
        titolo = request.form['titoloGruppo']

        try:
            db.execute(
                'INSERT INTO GRUPPO (ID_ADMIN, NOME_GRUPPO) VALUES (?, ?)',
                (id, titolo),
            )
            db.commit()
        except db.IntegrityError:
            error = "error"

        rows = db.execute(
            'SELECT ID_GRUPPO FROM GRUPPO ORDER BY ID_GRUPPO DESC'
        ).fetchone()

        for row in rows:
            group_id = row

        db.execute(
            'INSERT INTO USERGROUP (ID_US, ID_GROUP) VALUES (?, ?)',
            (id, group_id),
        )
        db.commit()

    group_title_list = db.execute("""
                        SELECT G.ID_GRUPPO, U.USERNAME AS ADMIN_USERNAME, G.NOME_GRUPPO
                        FROM UTENTE U
                        JOIN GRUPPO G ON G.ID_ADMIN = U.ID_USER
                        JOIN (
                            SELECT GR.ID_GRUPPO
                            FROM GRUPPO GR
                            JOIN USERGROUP UG ON GR.ID_GRUPPO = UG.ID_GROUP
                            WHERE UG.ID_US = (?)
                        ) AS Subquery ON G.ID_GRUPPO = Subquery.ID_GRUPPO
                    """,
                                  (id,)
                                  ).fetchall()

    return render_template("vault/group_list.html", group_title_list=group_title_list)


# Funzione che verifica se un utente è l'amministratore di un gruppo
def is_admin(group_id):
    id = g.user['ID_USER']
    db = get_db()
    admin = db.execute('SELECT * FROM GRUPPO WHERE ID_ADMIN=(?) AND ID_GRUPPO=(?)',
                       (id, group_id)
                       ).fetchone()
    return admin


# Route per visualizzare la "group vault" di un gruppo
@bp.route('/group_vault/<group_name>/<int:group_id>')
@login_required
@business_required
def group_vault(group_name, group_id):
    admin = False
    admin = is_admin(group_id)

    db = get_db()
    group_passwords = db.execute(
        'SELECT * FROM CREDENZIALI_GRUPPO WHERE ID_GR = (?)',
        (group_id,)
    ).fetchall()

    return render_template("vault/group_vault.html", name=group_name, admin=admin, group_id=group_id,
                           group_passwords=group_passwords)


# Route per eliminare una password dalla "group vault"
@bp.route('/group_vault/delete/<int:id>', methods=['POST'])
@login_required
def delete_from_group_vault(id):
    db = get_db()
    db.execute('DELETE FROM CREDENZIALI_GRUPPO WHERE ID_CREDG = ?', (id,))
    db.commit()
    return redirect(request.referrer)


# Route per eliminare un gruppo
@bp.route('/group_vault/delete_group/<int:id>', methods=['POST'])
@login_required
def delete_group(id):
    db = get_db()
    db.execute('DELETE FROM GRUPPO WHERE ID_GRUPPO = ?', (id,))
    db.commit()
    return redirect(request.referrer)


# Route per aggiungere un membro a un gruppo
@bp.route('/addMember/<group_name>/<int:group_id>', methods=['POST'])
@login_required
@business_required
def addMember(group_name, group_id):
    if request.method == 'POST':
        memberEmail = request.form['emailUtente']

        db = get_db()

        rows = db.execute(
            'SELECT ID_USER FROM UTENTE WHERE EMAIL=(?)',
            (memberEmail,)
        ).fetchone()

        if rows is None:
            return redirect(request.referrer)

        for row in rows:
            memberID = row

        try:
            db.execute('INSERT INTO USERGROUP (ID_US, ID_GROUP ) VALUES (?, ?)',
                       (memberID, group_id),
                       )
            db.commit()

        except db.IntegrityError:
            error = "error"

    return redirect(request.referrer)


# Route per visualizzare i membri di un gruppo
@bp.route('/group_vault/<group_name>/<int:group_id>/members', methods=['GET', 'POST'])
def group_members(group_name, group_id):
    # Ottieni l'accesso al database
    db = get_db()

    # Ottieni le informazioni sugli amministratori del gruppo
    admin_rows = db.execute(
        'SELECT DISTINCT NOME, EMAIL, USERNAME FROM UTENTE JOIN (SELECT ID_ADMIN FROM BUSINESS JOIN GRUPPO WHERE ID_GRUPPO=(?)) AS SUB ON ID_USER=SUB.ID_ADMIN',
        (group_id,))

    # Estrai la riga del primo amministratore trovato
    for row in admin_rows:
        admin = row

    # Ottieni la lista dei membri del gruppo
    membri_list = db.execute(
        'SELECT NOME, EMAIL, USERNAME, ID_UG, ID_GROUP FROM UTENTE JOIN (SELECT ID_US, ID_UG, ID_GROUP FROM USERGROUP WHERE ID_GROUP = (?)) AS SUB1 ON UTENTE.ID_USER = SUB1.ID_US WHERE UTENTE.ID_USER NOT IN ( SELECT ID_ADMIN FROM UTENTE JOIN GRUPPO ON UTENTE.ID_USER = GRUPPO.ID_ADMIN WHERE GRUPPO.ID_GRUPPO = (?))',
        (group_id, group_id))

    # Stampa la lista dei membri sul terminale (a scopo di debug)
    print(membri_list)

    # Rendi la pagina HTML con le informazioni del gruppo
    return render_template("vault/members.html", name=group_name, membri_list=membri_list, admin=admin,
                           is_admin=is_admin(group_id), group_id=group_id)


# Route per eliminare un membro dal gruppo
@bp.route('/group_vault/delete/<int:id>', methods=['POST'])
@login_required
def delete_group_member(id):
    # Ottieni l'accesso al database
    db = get_db()

    # Esegui la query per eliminare il membro dal gruppo
    db.execute('DELETE FROM USERGROUP WHERE ID_UG = ?', (id,))

    # Conferma la modifica nel database
    db.commit()

    # Reindirizza l'utente alla pagina precedente
    return redirect(request.referrer)


# Route per visualizzare la password di un gruppo
@bp.route('/group_vault/group_password/<int:id>', methods=['GET'])
@login_required
def render_group_password(id):
    # Ottieni le informazioni sulla password del gruppo dal database
    cred = get_group_credential(id)

    # Rendi la pagina HTML con le informazioni sulla password del gruppo
    return render_template("vault/group_password.html", cred=cred)


# Route per visualizzare la pagina di pricing
@bp.route('/pricing')
def pricing():
    return render_template("vault/pricing.html")


# Funzione per ottenere le informazioni su una credenziale utente
def get_credential(id, check_user=True):
    # Ottieni le informazioni sulla credenziale dal database
    cred = get_db().execute(
        'SELECT * FROM CREDENZIALI WHERE ID_CRED = ?', (id,)
    ).fetchone()

    # Gestisci errori nel caso la credenziale non esista o l'utente non sia autorizzato
    if cred is None:
        abort(404, f"Credential id {id} doesn't exist.")
    if check_user and cred['ID_UTENTE'] != g.user['ID_USER']:
        abort(403)

    return cred


# Funzione per ottenere le informazioni su una credenziale di gruppo
def get_group_credential(id, check_user=True):
    # Ottieni le informazioni sulla credenziale di gruppo dal database
    cred = get_db().execute(
        'SELECT * FROM CREDENZIALI_GRUPPO WHERE ID_CREDG  = ?', (id,)
    ).fetchone()

    # Gestisci errori nel caso la credenziale non esista o l'utente non sia autorizzato
    if cred is None:
        abort(404, f"Credential id {id} doesn't exist.")

    return cred


# Route per aggiungere una nuova password di gruppo al database
@bp.route('/group_vault/createGroupCredentials/<int:group_id>', methods=['POST'])
def add_group_password(group_id):
    # Ottieni l'accesso al database
    db = get_db()

    # Ottieni i dati JSON dalla richiesta
    req = request.get_json()

    # Estrai i dettagli dalla richiesta
    email = req['email']
    password = req['password']
    url = req['url']
    titolo = req['titolo']
    note = req['note']

    try:
        # Esegui la query per aggiungere la nuova password di gruppo al database
        db.execute(
            "INSERT INTO CREDENZIALI_GRUPPO (TIT_GROUP, EMAIL_GROUP, PASSWORD_GROUP, URL_GROUP,NOTE_GROUP, ID_GR) VALUES (?, ?, ?, ?, ?, ?)",
            (titolo, email, password, url, note, group_id),
        )
        # Conferma la modifica nel database
        db.commit()
    except db.IntegrityError:
        print("error in add-password query")
    else:
        print("password added to db")

    # Reindirizza l'utente alla pagina precedente
    return redirect(request.referrer)


# Route per aggiornare una password di gruppo nel database
@bp.route('/group_vault/group_password/update', methods=['POST'])
@login_required
def update_group_password():
    # Ottieni i dati JSON dalla richiesta
    req = request.get_json()
    email = req['email']
    password = req['password']
    url = req['url']
    titolo = req['titolo']
    id = req['id']
    note = req['note']

    # Ottieni l'accesso al database
    db = get_db()

    # Esegui la query per aggiornare la password di gruppo nel database
    db.execute(
        'UPDATE CREDENZIALI_GRUPPO SET TIT_GROUP = (?), EMAIL_GROUP = (?),URL_GROUP = (?),PASSWORD_GROUP = (?), NOTE_GROUP = (?)'
        ' WHERE ID_CREDG = ?',
        (titolo, email, url, password, note, id)
    )

    # Conferma la modifica nel database
    db.commit()

    # Reindirizza l'utente alla pagina precedente
    return redirect(request.referrer)



