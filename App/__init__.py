import os

from flask import Flask, render_template

from . import db

# from flaskext.mysql import MySQL

from App.celeryFile import make_celery

UPLOAD_FOLDER = os.path.join(os.getcwd(), "App", "uploads")
priv_key = 'pppppppppqqqqqqqqqqqqqqeeeeeeeeeee'

# CELERY_BROKER_BACKEND = "sqlakombu.transport.Transport"

CELERY_BROKER_BACKEND = "db+sqlite:///celery.sqlite"
CELERY_BROKER_URL = "db+sqlite:///results.sqlite"
CELERY_CACHE_BACKEND = "db+sqlite:///celery.sqlite"
CELERY_RESULT_BACKEND = "db+sqlite:///celery.sqlite"

from . import api as Api


def create_app(test_config=None):
    # create and configure the app
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "App", "uploads")

    app = Flask(__name__, instance_relative_config=True, static_url_path=UPLOAD_FOLDER)

    # assign a secret key also connect it with the database
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config,if it exists
        app.config.from_pyfile('config.py', silent=True)

    else:
        # load the test config if passed on
        app.config.from_mapping(test_config)

    # Check if instance folder does exist
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(Api.bp)

    db.init_app(app)

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'ashketchumreal4life@gmail.com'
    app.config['MAIL_PASSWORD'] = 'Boomanlames@12345'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['SECRET_KEY'] = "pppppppppqqqqqqqqqqqqqqeeeeeeeeeee"

    app.config['MYSQL_DATABASE_USER'] = 'root'
    app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
    app.config['MYSQL_DATABASE_DB'] = 'NXBProcurement'
    app.config['MYSQL_DATABASE_HOST'] = 'localhost'

    # app.config['CELERY_BROKER_BACKEND'] = "sqlakombu.transport.Transport"

    app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
    app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
    app.config['CELERY_BROKER_BACKEND'] = "db+sqlite:///celery.sqlite"
    app.config['CELERY_CACHE_BACKEND'] = "db+sqlite:///celery.sqlite"

    # app.config['CELERY_RESULT_BACKEND'] = "db+sqlite:///celery.sqlite"
    # app.config['CELERY_BROKER_URL'] = "db+sqlite:///results.sqlite"

    celery = make_celery(app)

    # auth.mail.init_app(app)
    Api.mail.init_app(app)

    @app.route('/')
    def index():
        return render_template('/home/harrisali/Downloads/PMS/storage/frontend/index.html')

    return app
