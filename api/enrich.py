from functools import partial
from uuid import uuid4
from datetime import datetime

from flask import Blueprint, g, current_app

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data, jsonify_result
from api.client import APIVoidClient

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


def get_confidence(engine):
    if engine.get('confidence'):
        return engine.get('confidence').capitalize()
    else:
        return 'High'


def extract_indicator(engine):
    return {
        'confidence': get_confidence(engine),
        'tlp': 'white',
        'valid_time': {},
        'short_description': f"Feed: {engine['engine']}",
        'type': 'indicator',
        'id': f'transient:indicator-{uuid4()}',
        'producer': 'APIVoid',
        **current_app.config['CTIM_DEFAULTS'],
    }


def extract_sighting(engine):
    time_now = datetime.utcnow().isoformat() + 'Z'
    return {
        'count': 1,
        'confidence': get_confidence(engine),
        'description': 'Detected on blocklist',
        'source': engine['engine'],
        'source_uri': engine['reference'],
        'type': 'sighting',
        'observed_time': {
            'start_time': time_now,
            'end_time': time_now
        },
        'id': f'transient:sighting-{uuid4()}',
        **current_app.config['CTIM_DEFAULTS'],
    }


def extract_relationship(sighting_id, indicator_id):
    return {
        'type': 'relationship',
        'relationship_type': 'member-of',
        'id': f'transient:relationship-{uuid4()}',
        'source_ref': sighting_id,
        'target_ref': indicator_id,
        **current_app.config['CTIM_DEFAULTS'],
    }


def get_engines(output):
    result = []
    engines = output['data']['report']['blacklists']['engines'].values()
    limit = current_app.config['CTR_ENTITIES_LIMIT']
    for engine in engines:
        if engine['detected'] and len(result) < limit:
            result.append(engine)
    return result


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    payload = get_jwt()
    client = APIVoidClient(payload)
    observables = get_observables()
    g.sightings = []
    g.indicators = []
    g.relationships = []
    for observable in observables:
        output = client.get_data(observable)
        if output:
            for engine in get_engines(output):
                sighting = extract_sighting(engine)
                g.sightings.append(extract_sighting(engine))
                indicator = extract_indicator(engine)
                g.indicators.append(extract_indicator(engine))
                g.relationships.append(
                    extract_relationship(sighting['id'], indicator['id'])
                )

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented.
    return jsonify_data([])
