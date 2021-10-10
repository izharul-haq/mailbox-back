from flask import Flask
from flask_cors import CORS
from logging import basicConfig
from routes import RSA, Elgamal, DiffieHellman

basicConfig(
    filename='app.log', filemode='w',
    format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)

app.register_blueprint(RSA)
app.register_blueprint(Elgamal)
app.register_blueprint(DiffieHellman)

CORS(app)


@app.route('/', methods=['GET'])
def index():
    return 'OK'


if __name__ == '__main__':
    app.run(debug=True)
