from io import BytesIO
from json import loads
from logging import exception
from math import ceil
import os

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
            with open(f'bin/Elgamal/public.key', 'w') as f:
                f.writelines(str(y) + '\n')
                f.writelines(str(g) + '\n')
                f.writelines(str(p) + '\n')
                f.close()

            with open(f'bin/Elgamal/private.key', 'w') as f:
                f.writelines(str(x) + '\n')
                f.writelines(str(p) + '\n')
                f.close()

            res = {'y': y, 'g': g, 'x': x, 'p': p}

        elif key_type == 'public':
            with open(f'bin/Elgamal/public.key', 'w') as f:
                f.writelines(str(y) + '\n')
                f.writelines(str(g) + '\n')
                f.writelines(str(p) + '\n')
                f.close()

            res = {'y': y, 'g': g, 'p': p}

        elif key_type == 'private':
            with open(f'bin/Elgamal/private.key', 'w') as f:
                f.writelines(str(x) + '\n')
                f.writelines(str(p) + '\n')
                f.close()

            res = {'x': x, 'p': p}

        else:
            raise Exception(f'key type {key_type} is not supported')

        return jsonify(res), 201

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/key/<string:key_type>', methods=['DELETE'])
def delete_key(key_type: str):
    try:
        msg = ''

        if key_type == 'all':
            os.remove('bin/Elgamal/public.key')
            os.remove('bin/Elgamal/private.key')

            msg = 'All keys deleted'

        elif key_type == 'public' or key_type == 'private':
            os.remove(f'bin/Elgamal/{key_type}.key')

            msg = f'{key_type.capitalize()} key deleted'

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/key/<string:key_type>/check/', methods=['GET'])
def check_key(key_type: str):
    try:
        if key_type == 'all':
            return jsonify(
                os.path.exists('bin/Elgamal/public.key')
                and os.path.exists('bin/Elgamal/private.key')
            ), 200

        elif key_type == 'public' or key_type == 'private':
            return jsonify(os.path.exists(f'bin/Elgamal/{key_type}.key')), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    try:
        with open('bin/Elgamal/public.key', 'r') as f:
            y = int(f.readline())
            g = int(f.readline())
            p = int(f.readline())

            f.close()

        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()

            res = elgamal.encrypt(file_buffer, y, g, p)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']

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
        with open('bin/Elgamal/private.key', 'r') as f:
            x = int(f.readline())
            p = int(f.readline())

            f.close()

        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()

            res = elgamal.decrypt(file_buffer, x, p)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']

            res = elgamal.decrypt(message, x, p)

            return res.replace(b'\x00', b'').decode('utf-8'), 200

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
