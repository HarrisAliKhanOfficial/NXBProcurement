import os
from flask import Flask
from . import db
import os
from flask_mail import Mail, Message

from . import api as Api

priv_key = os.urandom(24)


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

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

        # Registering the app for authentication
    # app.register_blueprint(auth.bp)
    #
    # app.register_blueprint(user.bp)
    app.register_blueprint(Api.bp)

    db.init_app(app)
    UPLOAD_FOLDER = '/home/harrisali/PycharmProjects/NXBProcurement'

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'ashketchumreal4life@gmail.com'
    app.config['MAIL_PASSWORD'] = 'Boomanlames@12345'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['SECRET_KEY'] = priv_key


    # auth.mail.init_app(app)
    Api.mail.init_app(app)


    return app
