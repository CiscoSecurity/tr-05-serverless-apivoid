from flask import Blueprint

from api.utils import get_jwt, jsonify_data
from api.client import APIVoidClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    payload = get_jwt()
    client = APIVoidClient(payload)
    client.check_health()

    return jsonify_data({'status': 'ok'})
