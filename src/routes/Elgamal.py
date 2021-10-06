from io import BytesIO
from json import loads
from logging import exception
from math import ceil
from os import remove

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
        if key_type == 'public' or key_type == 'private':
            key = elgamal.generate_key(key_type, p, g, x)

            with open(f'bin/Elgamal/{key_type}.key', 'w') as f:
                f.writelines(str(key[0]) + '\n')
                f.writelines(str(key[1]) + '\n')

                if key_type == 'public':
                    f.writelines(str(key[2]) + '\n')

                f.close()

            return f'{key_type.capitalize()} key created', 201

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@Elgamal.route('/key/delete', methods=['DELETE'])
def delete_key():
    try:
        remove('bin/Elgamal/public.key')
        remove('bin/Elgamal/private.key')

        return 'Created key has been deleted', 204

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
