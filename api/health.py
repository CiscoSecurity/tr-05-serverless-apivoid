from flask import Blueprint

from api.utils import get_jwt, jsonify_data
from api.client import APIVoidClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt()
    client = APIVoidClient(key)
    client.check_health()

    return jsonify_data({'status': 'ok'})
