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
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            g, n = list(map(int, request.form.get('key').split(', ')))

            res = pa.encrypt(file_buffer, g, n)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            g, n = req_body['key']

            message_buffer = bytes(message, 'utf-8')

            res = pa.encrypt(message_buffer, g, n)

            group_size = ceil(((n*n).bit_length() - 1) / 8)

            return jsonify(bytes_to_ints(res, group_size)), 200

        else:
            raise Exception(f'input type {input_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Paillier.route('/decrypt/<string:input_type>', methods=['POST'])
def decrypt(input_type: str):
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            g, n, l, m = list(map(int, request.form.get('key').split(', ')))

            res = pa.decrypt(file_buffer, g, n, l, m)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            g, n, l, m = req_body['key']

            res = pa.decrypt(message, g, n, l, m)

            return res.replace(b'\x00', b'').decode('utf-8'), 200

        else:
            raise Exception(f'input type {input_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
