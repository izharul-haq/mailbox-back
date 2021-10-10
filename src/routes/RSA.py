from io import BytesIO
from json import loads
from logging import exception
from math import ceil

from flask import Blueprint, Response, request, jsonify
from werkzeug.wsgi import FileWrapper

from services import rsa
from .utils import bytes_to_ints

RSA = Blueprint('rsa', __name__, url_prefix='/rsa')


@RSA.route('/key/<string:key_type>', methods=['POST'])
def generate_key(key_type: str):
    req_body = loads(request.data)

    p = req_body['p']
    q = req_body['q']
    e = req_body['e']

    try:
        e, d, n = rsa.generate_key(p, q, e)
        res = {}

        if key_type == 'public':
            res = {'e': e, 'n': n}

        elif key_type == 'private':
            res = {'d': d, 'n': n}

        elif key_type == 'all':
            res = {'e': e, 'd': d, 'n': n}

        else:
            raise Exception(f'key type {key_type} is not supported')

        return jsonify(res), 201

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@RSA.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            e, n = list(map(int, request.form.get('key').split(', ')))

            res = rsa.encrypt(file_buffer, e, n)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            e, n = req_body['key']

            message_buffer = bytes(message, 'utf-8')

            res = rsa.encrypt(message_buffer, e, n)

            group_size = ceil((n.bit_length() - 1) / 8)

            return jsonify(bytes_to_ints(res, group_size)), 200

        else:
            raise Exception(f'input type {input_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@RSA.route('/decrypt/<string:input_type>', methods=['POST'])
def decrypt(input_type: str):
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            d, n = list(map(int, request.form.get('key').split(', ')))

            res = rsa.decrypt(file_buffer, d, n)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            d, n = req_body['key']

            res = rsa.decrypt(message, d, n)

            return res.replace(b'\x00', b'').decode('utf-8'), 200

        else:
            raise Exception(f'input type {input_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
