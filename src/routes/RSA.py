from io import BytesIO
from json import loads
from logging import exception
from math import ceil
import os

from flask import Blueprint, Response, request, jsonify
from werkzeug.wsgi import FileWrapper

from services import rsa
from .utils import bytes_to_ints

RSA = Blueprint('rsa', __name__, url_prefix='/rsa/')


@RSA.route('/key/<string:key_type>', methods=['POST'])
def generate_key(key_type: str):
    req_body = loads(request.data)

    p = req_body['p']
    q = req_body['q']
    e = req_body['e']

    try:
        if key_type == 'public' or key_type == 'private':
            key = rsa.generate_key(key_type, p, q, e)

            with open(f'bin/RSA/{key_type}.key', 'w') as f:
                f.writelines(str(key[0]) + '\n')
                f.writelines(str(key[1]) + '\n')
                f.close()

            return f'{key_type.capitalize()} key created', 201

        else:
            raise Exception(f'key type {key_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@RSA.route('/key/delete', methods=['DELETE'])
def delete_key():
    try:
        os.remove('bin/RSA/public.key')
        os.remove('bin/RSA/private.key')

        return 'Created key has been deleted', 204

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400


@RSA.route('/encrypt/<string:input_type>', methods=['POST'])
def encrypt(input_type: str):
    try:
        with open('bin/RSA/public.key', 'r') as f:
            e = int(f.readline())
            n = int(f.readline())

            f.close()

        if input_type == 'file':
            req_file = request.files['message']

            file_buffer = req_file.read()

            res = rsa.encrypt(file_buffer, e, n)

            res_buffer = BytesIO(res)
            wrapper = FileWrapper(res_buffer)

            return Response(wrapper, mimetype=req_file.mimetype,
                            direct_passthrough=True), 200

        elif input_type == 'text':
            req_body = loads(request.data)

            message = req_body['message']

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
        with open('bin/RSA/private.key', 'r') as f:
            d = int(f.readline())
            n = int(f.readline())

            f.close()

            if input_type == 'file':
                req_file = request.files['message']

                file_buffer = req_file.read()

                res = rsa.decrypt(file_buffer, d, n)

                res_buffer = BytesIO(res)
                wrapper = FileWrapper(res_buffer)

                return Response(wrapper, mimetype=req_file.mimetype,
                                direct_passthrough=True), 200

            elif input_type == 'text':
                req_body = loads(request.data)

                message = req_body['message']

                res = rsa.decrypt(message, d, n)

                return res.replace(b'\x00', b'').decode('utf-8'), 200

            else:
                raise Exception(f'input type {input_type} is not supported')

    except Exception as e:
        err_message = str(e)
        exception(err_message)

        return jsonify({'code': 400, 'message': err_message}), 400
