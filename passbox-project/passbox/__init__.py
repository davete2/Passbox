import os

from flask import Flask, make_response, send_from_directory



def create_app(test_config=None):

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'passbox.sqlite'),
    )

    @app.route('/mainfest.json')
    def get_mainfest():
        return send_from_directory('static', 'mainfest.json')

    @app.route('/sw.js')
    def sw():
        response = make_response(send_from_directory('static', filename='sw.js'))
        response.headers['Content-Type'] = 'application/javascript'
        return response

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import auth
    app.register_blueprint(auth.bp)

    from . import vault
    app.register_blueprint(vault.bp)
    app.add_url_rule('/', endpoint='index')

    from . import db
    db.init_app(app)

    return app
