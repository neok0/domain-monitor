# from enrichers import whois
from enrichers import pdns
from settings.config import DOMAIN_CONFIG, TIMEFORMAT
import datetime
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Enrichment:
    def __init__(self, domains, limit=0):
        self.limit = limit
        self.data = self._make_a_plain_list(domains)
        self.now = datetime.datetime.now().strftime(TIMEFORMAT)
        self.enrichments = dict()

    def _make_a_plain_list(self, data):
        if isinstance(data, list):
            if isinstance(data[0], dict):
                return [d.get('value') for d in data]
            return data
        if isinstance(data, str):
            return data

    def _prepare_data(self, c):
        """
        this helper method normalizes add incoming collector data
        :param c: collector
        :return: normalized data
        """

        self.enrichments[c.source] = c.results

    def enrich(self):
        """
        main method for collector all different collector data
        :return:
        """
        p = pdns.pDNS(limit=self.limit)
        p.run(self.data)
        self._prepare_data(p)

        # w = whois.WHOIS(limit=self.limit)
        # w.run(self.data)
        # self._prepare_data(w)
