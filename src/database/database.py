from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from exceptions.exceptions import MissingParameters
from settings.config import DOMAIN_CONFIG, DATABASE_CONFIG, TIMEFORMAT
from collections import defaultdict
import datetime

import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class DatabaseUtils:
    def __init__(self):
        self.es = Elasticsearch(DATABASE_CONFIG['es_host'])
        self.time_format = TIMEFORMAT

    @staticmethod
    def get_hits(res):
        if not res.get('hits', {}).get('total', 0):
            return []
        hits = list()
        for hit in res.get('hits', {}).get('hits', []):
            data = hit.get('_source')
            data['id'] = hit.get('_id')
            hits.append(data)
        return hits

    @staticmethod
    def check_response(res):
        # TODO: should raise exception when error
        return {'success': True, 'msg': None, 'parent': res.get('_id'), 'res': res, 'id': res.get('_id')}

    @staticmethod
    def check_data(data, required_fields):
        for required_field in required_fields:
            if required_field not in data:
                raise MissingParameters(required_field)

    def _parse_ts(self, ts):
        return datetime.datetime.fromtimestamp(ts).strftime(self.time_format)

    def add_new_domain(self, data):
        """
        this method can be used to add a new domain
        :param data: domain data (created_ad and updated_at auto generated)
        :return:
        """
        if isinstance(data, list):
            ids = list()
            for d in data:
                i = self.add_new_domain(d)
                ids.extend(i)
            return ids
        else:
            self.check_data(data, ['value', 'ip_address'])
            now = datetime.datetime.now().strftime(self.time_format)
            data['created_at'] = now
            data['updated_at'] = now
            status = self.check_response(self.es.index(body=data, index=DATABASE_CONFIG['domains_index'],
                                                       doc_type=DATABASE_CONFIG['domains_index']))
            return [status.get('id')]

    def add_watchlist_domains(self, parent, watchlist):
        """
        this method can be used to add new typo domains
        :param watchlist: domain data (created_ad and updated_at auto generated)
        :return:
        """
        data = list()
        now = datetime.datetime.now().strftime(self.time_format)
        for d in watchlist:
            self.check_data(d, ['value', 'fuzzer'])
            tmp = {
                "_index": DATABASE_CONFIG['watchlist_index'],
                "_type": DATABASE_CONFIG['watchlist_index'],
                "_source": {
                    'created_at': now,
                    'updated_at': now,
                    'value': d['value'],
                    'parent': parent,
                    'fuzzer': d['fuzzer'],
                }
            }
            data.append(tmp)

        # status = self.check_response(bulk(self.es, b))
        status = bulk(self.es, data)
        return status

    def create_alerts(self, parent, value, source, match):
        """
        this method can be used to crate new alerts for domains
        :param data: domain data (created_ad and updated_at auto generated)
        :return:
        """
        now = datetime.datetime.now().strftime(self.time_format)
        data = dict()
        data['created_at'] = now
        data['updated_at'] = now if not data.get('updated_at', None) else None
        data['parent'] = parent
        data['value'] = value
        data['match'] = match
        data['source'] = source
        data['status'] = 'open'
        status = self.check_response(self.es.index(body=data, index=DATABASE_CONFIG['alerts_index'],
                                                   doc_type=DATABASE_CONFIG['alerts_index']))
        return [status.get('id')]

    def update_alert_status(self, a_id, status='closed'):
        if isinstance(a_id, list):
            for a in a_id:
                self.update_alert_status(a, status=status)
            return
        if isinstance(a_id, dict):
            a_id = a_id.get('id')
        now = datetime.datetime.now().strftime(self.time_format)
        body = {
            'doc': {
                'status': status,
                'updated_at': now
            }}
        res = self.es.update(id=a_id, body=body, index=DATABASE_CONFIG['alerts_index'],
                             doc_type=DATABASE_CONFIG['alerts_index'])
        logger.debug(res)

    def add_keywords_per_domain(self, keywords, domain):
        """
        this method can be used to insert new keywords for fuzzy search for main domains
        :param keywords: list of keywords
        :return:
        """
        data = list()
        now = datetime.datetime.now().strftime(self.time_format)
        for d in keywords:
            tmp = {
                "_index": DATABASE_CONFIG['keywords_index'],
                "_type": DATABASE_CONFIG['keywords_index'],
                "_source": {
                    'created_at': now,
                    'value': d,
                    'parent': domain,
                }
            }
            data.append(tmp)
        status = bulk(self.es, data)
        return status

    def add_registered_domains(self, registered):
        """
        this method can be used to add new recently registered domains
        :param registered: domain data (created_ad and updated_at auto generated)
        :return:
        """

        data = list()
        now = datetime.datetime.now().strftime(self.time_format)
        for d in registered:
            self.check_data(d, ['value', 'source'])
            added_at = d.get('added_at', now)
            tmp = {
                "_index": DATABASE_CONFIG['registered_index'],
                "_type": DATABASE_CONFIG['registered_index'],
                "_source": {
                    'created_at': added_at,
                    'updated_at': added_at,
                    'value': d['value'],
                    'source': d['source'],
                }
            }
            data.append(tmp)
        status = bulk(self.es, data)
        return status

    def add_enrichments(self, enrichtments):
        """
        this method can be used to add new recently registered domains
        :param data: domain data (created_ad and updated_at auto generated)
        :return:
        """
        status = list()
        for enrichtment in enrichtments:
            data = list()
            now = datetime.datetime.now().strftime(self.time_format)
            index = DATABASE_CONFIG['{}_index'.format(enrichtment)]
            for d in enrichtments[enrichtment]:
                # self.check_data(d, ['value'])
                added_at = d.get('added_at', now)
                tmp = {
                    "_index": index,
                    "_type": index,
                    "_source": d,
                }
                tmp["_source"]["created_at"] = added_at
                tmp["_source"]["updated_at"] = added_at
                data.append(tmp)

            s = bulk(self.es, data)
            status.append(s)
        return status

    def add_scores(self, scores):
        data = list()
        now = datetime.datetime.now().strftime(self.time_format)
        for d in scores:
            self.check_data(d, ['value', 'score'])
            added_at = d.get('added_at', now)
            tmp = {
                "_index": DATABASE_CONFIG['scoring_index'],
                "_type": DATABASE_CONFIG['scoring_index'],
                "_source": {
                    'created_at': added_at,
                    'updated_at': added_at,
                    'value': d['value'],
                    'score': d['score'],
                    'data': d['data']
                }
            }
            data.append(tmp)
        status = bulk(self.es, data)
        return status

    def get_score(self, domain=False, score=0, start=False, end=False):
        should = list()

        if domain:
            should.append(
                {
                    "match": {
                        "value": domain
                    }
                }
            )
        if score:
            should.append(
                {
                    "range": {
                        "score": {
                            "gte": score
                        }
                    }
                }
            )
        if start and end:
            should.append(
                {
                    "range": {
                        "created_at": {
                            "gte": start,
                            "lte": end,
                            "format": "yyyy-mm-dd"
                        }
                    }
                }
            )

        body = {
            "query": {
                "bool": {
                    "should": should
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['scoring_index'], body)
        return hits

    def add_certificate_watch_data(self, certificates):
        data = list()
        now = datetime.datetime.now().strftime(self.time_format)
        for d in certificates:
            # self.check_data(d, ['value', 'score'])
            added_at = d.get('added_at', now)
            tmp = {
                "_index": DATABASE_CONFIG['certificate_index'],
                "_type": DATABASE_CONFIG['certificate_index'],
                "_source": {
                    'created_at': added_at,
                    'updated_at': added_at,
                    'value': d.get('value'),
                    'cert_link': d.get('cert_link'),
                    'source': d.get('source'),
                    'cert_subject': d.get('leaf_cert', {}).get('subject'),
                    'cert_not_before': self._parse_ts(d.get('leaf_cert', {}).get('not_before')),
                    'cert_not_after': self._parse_ts(d.get('leaf_cert', {}).get('not_after')),
                    'cert_serial':  d.get('leaf_cert', {}).get('serial_number'),
                    'cert_domains':  d.get('leaf_cert', {}).get('all_domains'),
                    'cert_fingerprint':  d.get('leaf_cert', {}).get('fingerprint'),
                    'cert_as_der': d.get('leaf_cert', {}).get('as_der'),
                }
            }
            data.append(tmp)
        status = bulk(self.es, data)
        return status

    def get_certificates(self, domain=False, start=False, end=False):
        should = list()
        if domain:
            should.append(
                {
                    "match": {
                        "value": domain
                    }
                }
            )
        if start and end:
            should.append(
                {
                    "range": {
                        "created_at": {
                            "gte": start,
                            "lte": end,
                            "format": "yyyy-mm-dd"
                        }
                    }
                }
            )
        body = {
            "query": {
                "bool": {
                    "should": should
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['certificate_index'], body)
        return hits

    def get_domain(self, domain):
        body = {
            "query": {"match": {"value": domain}}
        }
        hits = self.scroll(DATABASE_CONFIG['domains_index'], body)
        return hits

    def get_domains(self):
        """
        This method returns all main domains which are monitored for.
        :return: list of domains
        """
        body = {
            "query": {"match_all": {}}
        }
        hits = self.scroll(DATABASE_CONFIG['domains_index'], body)
        return hits

    def get_watchlist_by_parent(self, parent):
        """
        This method returns a list of typo domains depending on the main/parent domain
        :param parent: main domain to monitor for
        :return: list of watchlist domains
        """
        body = {
            "query": {
                "match": {
                    "parent": parent
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['watchlist_index'], body)
        return hits

    def get_registered_by_date(self, start, end):
        body = {
            "query": {
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end,
                        "format": "yyyy-mm-dd"
                    }
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['registered_index'], body)
        return hits

    def get_missing_enrichments(self, domains, start, end):
        # body = {
        #         "query": {
        #             "bool": {
        #                 "must_not": {
        #                     "terms": {
        #                         "value": domains
        #                     }
        #                 }
        #             }
        #         }
        #     }
        # hits = self.scroll(DATABASE_CONFIG['whois_index'], body)
        body = {
            "query": {
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end,
                        "format": "yyyy-mm-dd"
                    }
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['whois_index'], body)
        hit_values = [h.get('value') for h in hits]
        return list(set(domains) - set(hit_values))

    def get_keywords_by_parent(self, parent):
        """
        This method returns a list of keywords to alert on pending on the main/parent domain
        :param parent: main domain to monitor for
        :return: list of watchlist domains
        """
        body = {
            "query": {
                "match": {
                    "parent": parent
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['keywords_index'], body)
        return hits

    def get_registered_by_keyword(self, keyword):
        """
        This method returns a list of registered domains matching a fuzzy search for given keyword
        :param keyword: keyword for fuzzy search
        :return: matching domains
        """
        # make sure keyword is a plain string
        if isinstance(keyword, dict):
            keyword = keyword.get('value')

        body = {
            "query": {
                "wildcard": {
                    "value": "*{}*".format(keyword)
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['registered_index'], body)
        return hits

    def get_alerts(self, value='*', status='open'):
        body = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"value": value}},
                        {"match": {"status": status}},
                    ]
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG['alerts_index'], body)
        return hits

    def exists(self, keys, index):
        """
        helper method for fast searches whehter a given key already exists in index or not
        :param key: list of dicts for value to search for
        :param index: index to search in
        :return:
        """
        must = list()
        for key in keys:
            must.append({'match': key})

        body = {
            "query": {
                "bool": {
                    "must": must
                }
            }
        }
        hits = self.scroll(DATABASE_CONFIG[index], body)
        return hits

    def scroll(self, index, body):
        """
        dummy scroll implementation method
        :param index: index to be searched in
        :param body: body to match
        :return: full list of hits
        """
        page = self.es.search(
            index=index,
            scroll='1m',
            size=1000,
            body=body)
        hits = self.get_hits(page)
        sid = page['_scroll_id']
        scroll_size = page['hits']['total']

        # Start scrolling
        while scroll_size:
            page = self.es.scroll(scroll_id=sid, scroll='2m')
            # Update the scroll ID
            sid = page['_scroll_id']
            # Get the number of results that we returned in the last scroll
            hits.extend(self.get_hits(page))
            scroll_size = len(page['hits']['hits'])

        return hits
