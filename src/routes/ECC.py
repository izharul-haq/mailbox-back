from io import BytesIO
from json import loads
from logging import exception
from math import ceil

from flask import Blueprint, Response, request, jsonify
from werkzeug.wsgi import FileWrapper

from services import ecc
from .utils import bytes_to_ints


ECC = Blueprint('ecc', __name__, url_prefix='/ecc')

