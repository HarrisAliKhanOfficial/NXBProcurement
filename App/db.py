import datetime
import sqlite3
import uuid
from flaskext.mysql import MySQL
import click
from flask import current_app, g
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash


def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf-8'))
    return db


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]

    return d


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@click.command('init-db')
@with_appcontext
def init_db_command():
    init_db()

    conn = get_db()
    conn.row_factory = dict_factory

    conn.execute(
        'INSERT INTO user(id,name,email,phone,password, role_id, created_at, verification_code, status, '
        'is_verified) '
        'VALUES (?,?,?,?,?,?,?,?,?,?)',
        (str(uuid.uuid4()), "Manager", "manager.procurement@nxb.com.pk", "contact", generate_password_hash("tester123"),
         1, datetime.datetime.now(), None,
         True, True,))
    conn.commit()

    click.echo('Initialized the database.')


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
