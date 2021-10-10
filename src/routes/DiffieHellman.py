from logging import exception
from json import loads

from flask import Blueprint, request, jsonify

from services import dh

DiffieHellman = Blueprint('diffie-hellman', __name__, url_prefix='/dh')


@DiffieHellman.route('/key', methods=['POST'])
def generate_key():
    try:
        req_body = loads(request.data)

        p = req_body['p']
        q = req_body['q']
        x = req_body['x']
        y = req_body['y']

        X, Y, K = dh.generate_key(p, q, x, y)

        return jsonify({'X': X, 'Y': Y, 'K': K}), 200

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
