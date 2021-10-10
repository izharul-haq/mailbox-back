from io import BytesIO
from json import loads
from logging import exception
from math import ceil

from flask import Blueprint, request, Response, jsonify
from werkzeug.wsgi import FileWrapper

from services import elgamal
from .utils import bytes_to_ints

Elgamal = Blueprint('elgamal', __name__, url_prefix='/elgamal')


@Elgamal.route('/key/<string:key_type>', methods=['POST'])
def generate_key(key_type: str):
    req_body = loads(request.data)

    p = req_body['p']
    g = req_body['g']
    x = req_body['x']

    try:
        y, g, x, p = elgamal.generate_key(p, g, x)
        res = {}

        if key_type == 'all':
            res = {'y': y, 'g': g, 'x': x, 'p': p}

        elif key_type == 'public':
            res = {'y': y, 'g': g, 'p': p}

        elif key_type == 'private':
            res = {'x': x, 'p': p}

        else:
            raise Exception(f'key type {key_type} is not supported')

        return jsonify(res), 201

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            y, g, p = list(map(int, request.form.get('key').split(', ')))

            res = elgamal.encrypt(file_buffer, y, g, p)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            y, g, p = req_body['key']

            message_buffer = bytes(message, 'utf-8')

            res = elgamal.encrypt(message_buffer, y, g, p)

            group_size = ceil((p.bit_length() - 1) / 8)

            return jsonify(bytes_to_ints(res, group_size)), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/decrypt/<string:input_type>', methods=['POST'])
def decrypt(input_type: str):
    try:
        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()
            x, p = list(map(int, request.form.get('key').split(', ')))

            res = elgamal.decrypt(file_buffer, x, p)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']
            x, p = req_body['key']

            res = elgamal.decrypt(message, x, p)

            return res.replace(b'\x00', b'').decode('utf-8'), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
