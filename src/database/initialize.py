from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from settings.config import DOMAIN_CONFIG, DATABASE_CONFIG
from argparse import ArgumentParser

import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class INITIALIZE:
    def __init__(self):
        self.host = DATABASE_CONFIG['es_host']
        self.indicies = [
            DATABASE_CONFIG['domains_index'],
            DATABASE_CONFIG['watchlist_index'],
            DATABASE_CONFIG['alerts_index'],
            DATABASE_CONFIG['registered_index'],
            DATABASE_CONFIG['certificate_index'],
            DATABASE_CONFIG['whois_index'],
            DATABASE_CONFIG['pdns_index'],
            DATABASE_CONFIG['scoring_index']
        ]
        self.mappings = {
            DATABASE_CONFIG['domains_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'ip_address': {'type': 'ip'},
                'keywords': {'type': 'keyword'},
            },
            DATABASE_CONFIG['watchlist_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'parent': {'type': 'keyword'},
                'fuzzer': {'type': 'keyword'},
            },
            DATABASE_CONFIG['alerts_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'parent': {'type': 'keyword'},
                'processed': {'type': 'keyword'},
                'source': {'type': 'keyword'},
                'match': {'type': 'keyword'},
            },
            DATABASE_CONFIG['registered_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'source': {'type': 'keyword'},
            },
            DATABASE_CONFIG['whois_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'registrant_org': {'type': 'keyword'},
                'registrant_country': {'type': 'keyword'},
                'registrar': {'type': 'text'},
                'registrar_status': {'type': 'keyword'},
                'registrar_created_on': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'registrar_expires_on': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'registrar_updated_on': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'nameservers': {'type': 'keyword'},
                'registrant_contact': {'type': 'nested'},
                'technical_contact': {'type': 'nested'},
                'admin_contact': {'type': 'nested'},
                'billing_contact': {'type': 'nested'},
                'ip_address': {'type': 'ip'},
                'ip_location': {'type': 'keyword'},
                'asn': {'type': 'keyword'},
                'whois_server': {'type': 'keyword'},
                'email_address': {'type': 'keyword'},
            },
            DATABASE_CONFIG['pdns_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'first_seen': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'last_seen': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'parent': {'type': 'keyword'},
                'ip_address': {'type': 'ip'},
            },
            DATABASE_CONFIG['scoring_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'score': {'type': 'integer', 'null_value': 0},
                'data': {'type': 'nested'},
            },
            DATABASE_CONFIG['certificate_index']: {
                'created_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'updated_at': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'value': {'type': 'keyword'},
                'cert_link': {'type': 'keyword'},
                'source': {'type': 'nested'},
                'cert_subject': {'type': 'nested'},
                'cert_not_before': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'cert_not_after': {'type': 'date', "format": DATABASE_CONFIG['es_timeformat']},
                'cert_serial': {'type': 'keyword'},
                'cert_domains': {'type': 'keyword'},
                'cert_fingerprint': {'type': 'keyword'},
                'cert_as_der': {'type': 'text'},
            }
        }

        self.es = Elasticsearch(self.host)

    def create_indicies(self):
        for index in self.indicies:
            body = {
                "mappings": {
                    index: {
                        "properties":
                            self.mappings[index]
                    }
                }
            }
            res = self.es.indices.create(index=index, body=body, ignore=400)
            logging.info(res)

    def delete_indicies(self):
        for index in self.indicies:
            try:
                res = self.es.indices.delete(index)
                logging.debug(res)
            except NotFoundError:
                logger.info('Skipping deleting index: {}'.format(index))


if __name__ == '__main__':
    parser = ArgumentParser()
    # create
    parser.add_argument('-c', '--create', action='store_true', default=False, dest='create',
                        help='Create Indicies')
    # delete
    parser.add_argument('-d', '--delete', action='store_true', default=False, dest='delete',
                        help='Delete Indicies')

    opts = parser.parse_args()

    i = INITIALIZE()

    if opts.delete:
        i.delete_indicies()
    if opts.create:
        i.create_indicies()
