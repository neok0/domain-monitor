from settings.config import DOMAIN_CONFIG
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class pDNS:
    def __init__(self, limit=0):
        self.source = 'pdns'
        self.limit = limit
        self.results = list()

    def _get(self, data):
        pass

    def run(self, data):
        if isinstance(data, list):
            for domain in data:
                self._get(domain)
        else:
            self._get(data)
