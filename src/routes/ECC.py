from io import BytesIO
from json import loads
from logging import exception
from math import ceil

from flask import Blueprint, Response, request, jsonify
from werkzeug.wsgi import FileWrapper

from services import ecc
from .utils import bytes_to_ints


ECC = Blueprint('ecc', __name__, url_prefix='/ecc')

@ECC.route('/key/<string:key_type>', methods=['POST'])
def generate_key(key_type: str):
    req_body = loads(request.data)

    a = req_body['a']
    b = req_body['b']
    p = req_body['p']
    n = req_body['n']
    G_x, G_y = req_body['Base Point']


    try:
        curve = ecc.Curve(a, b, p, n, G_x, G_y)

        pri_key, pub_key = ecc.generate_key(curve)
        res = {}

        if key_type == 'all':
            res = {'public key': pub_key, 'private key': pri_key}

        elif key_type == 'public':
            res = {'public key': pub_key}

        elif key_type == 'private':
            res = {'private key': pri_key}

        else:
            raise Exception(f'key type {key_type} is not supported')

        return jsonify(res), 200

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@ECC.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    try:
        if input_type == 'text':
            req_body = loads(request.data)

            a = req_body['a']
            b = req_body['b']
            p = req_body['p']
            n = req_body['n']
            G_x, G_y = req_body['Base Point']
            
            curve = ecc.Curve(a, b, p, n, G_x, G_y)

            message = req_body['message']
            x,y = req_body['key']

            pub_key = ecc.Point(x,y,curve)

            message_buffer = bytes(message, 'utf-8')

            res = ecc.encrypt(curve, message_buffer, pub_key)

            return jsonify(res), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@ECC.route('/decrypt/<string:input_type>', methods=['POST'])
def decrypt(input_type: str):
    try:
        if input_type == 'text':
            req_body = loads(request.data)

            a = req_body['a']
            b = req_body['b']
            p = req_body['p']
            n = req_body['n']
            G_x, G_y = req_body['Base Point']

            x1,y1 = req_body['C1']
            x2,y2 = req_body['C2']

            
            
            curve = ecc.Curve(a, b, p, n, G_x, G_y)

            C1 = ecc.Point(x1,y1, curve)
            C2 = ecc.Point(x2,y2, curve)

            pri_key = req_body['key']
            
            res = ecc.decrypt(curve, pri_key, C1, C2)

            return res.replace(b'\x00', b'').decode('utf-8'), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
