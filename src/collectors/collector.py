from collectors import whoisds
from settings.config import TIMEFORMAT, DOMAIN_CONFIG
import datetime
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Collector:
    def __init__(self):
        self.collected = None
        self.now = datetime.datetime.now().strftime(TIMEFORMAT)
        self.domains = list()
        self.plain_domains = list()

    def _prepare_data(self, c):
        """
        this helper method normalizes add incoming collector data
        :param c: collector
        :return: normalized data
        """
        parsed = list()
        plain = list()
        for domain in c.domains:
            plain_domain = domain.replace('\n', '')
            plain.append(plain_domain)
            parsed.append({'value': plain_domain, 'source': c.source, 'added_at': self.now})

        self.domains.extend(parsed)
        self.plain_domains.extend(plain)

    def collect(self, download=True):
        """
        main method for collector all different collector data
        :return:
        """
        # get data from whoisds collector
        c = whoisds.Collect(get_new=download)
        c.get()
        self._prepare_data(c)
