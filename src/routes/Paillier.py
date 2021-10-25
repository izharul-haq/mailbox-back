from io import BytesIO
from json import loads
from logging import exception
from math import ceil

from flask import Blueprint, Response, request, jsonify
from werkzeug.wsgi import FileWrapper

from services import pa
from .utils import bytes_to_ints

Paillier = Blueprint('paillier', __name__, url_prefix='/paillier')


@Paillier.route('/key/<string:key_type>', methods=['POST'])
def create_key(key_type: str):
    req_body = loads(request.data)

    p = req_body['p']
    q = req_body['q']

    try:
        g, n, l, m = pa.generate_key(p, q)
        res = {}

        if key_type == 'public':
            res = {'g': g, 'n': n}

        elif key_type == 'private':
            res = {'l': l, 'm': m}

        elif key_type == 'all':
            res = {'g': g, 'n': n, 'l': l, 'm': m}

        else:
            raise Exception(f'key type {key_type} is not supported')

        return jsonify(res), 200

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Paillier.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    pass


@Paillier.route('/decrypt/<string:input_type>', methods=['POST'])
def decrypt(input_type: str):
    pass
