from core.generator import Generator
from database.database import DatabaseUtils
from collectors.collector import Collector
from enrichers.enrichments import Enrichment
from core.alerts import Alerts
from scoring.scoring import Scoring
from settings.config import DOMAIN_CONFIG
from argparse import ArgumentParser
import datetime
import socket
import logging


logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class DomainWatcher:
    def __init__(self):
        self._logger()

    def _logger(self):
        # create logger with 'spam_application'
        logger.setLevel(logging.INFO)
        # create file handler which logs even debug messages
        fh = logging.FileHandler(DOMAIN_CONFIG['log_file'])
        fh.setLevel(logging.INFO)
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        logger.addHandler(fh)
        logger.addHandler(ch)

    def generate(self, domain, store=True):
        """
        this method generates typo domains for watchlist
        :param domain: new domain to watch out for
        :param store: store generated typo domains in watchlisth
        :return:
        """

        logger.info("Start generating watchlist for domain: {}".format(domain.get('value')))
        g = Generator()
        g.generate(domain.get('value'))

        logger.info("Completed generation: {} new watchlist domains".format(len(g.typo_domains)))
        if store:
            db = DatabaseUtils()

            # check if domain already exits
            if db.get_domain(domain.get('value')):
                logger.error("Domain {} already exits..skipping.".format(domain.get('value')))
                return g.typo_domains

            # make sure ip is set, if not get it
            if not domain.get('ip_address', False):
                try:
                    domain['ip_address'] = socket.gethostbyname(domain['value'])
                except Exception as e:
                    logger.info("Cannot retrieve IP for {}".format(domain['value']))

            # add new domain to monitor for
            domain_id = db.add_new_domain(domain)

            # add typo domains for this domain
            db.add_watchlist_domains(domain_id[0], g.typo_domains)

        return g.typo_domains

    def collect(self, download=False):
        """
        calls collector module for collecting all domains from various sources and uploads them into database.
        :return:
        """
        logger.info("Start collecting new domains")
        c = Collector()
        c.collect(download=download)

        db = DatabaseUtils()
        db.add_registered_domains(c.domains)
        logger.info("Completed collecting new domains: {}".format(len(c.domains)))
        return c.domains

    def score(self, domains=None, start=False, end=False):
        """
        scoring module for calculating a dedicated score for each domain.
        :param domains: list of domains to check for alerts
        :param start: Start date for creating alerts (default: last 24h). Format: YYYY-MM-DD
        :param end: End date for creating alerts (default: now). Format: YYYY-MM-DD
        :return:
        """
        db = DatabaseUtils()
        if not domains:
            if not start:
                start = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

            if not end:
                end = datetime.datetime.now().strftime('%Y-%m-%d')
            domains = db.get_registered_by_date(start, end)

        if not isinstance(domains, list):
            domains = [domains]

        logger.info("Start Scoring ({} domains)".format(len(domains)))
        scoring = Scoring()
        s = scoring.score(domains)

        db.add_scores(s)
        logger.info("Completed Scoring")

    def alert(self, domains=None, start=False, end=False):
        """
        check recently collected data for matches with watchlist
        :param domains: list of domains to check for alerts
        :param start: Start date for creating alerts (default: last 24h). Format: YYYY-MM-DD
        :param end: End date for creating alerts (default: now). Format: YYYY-MM-DD
        :return:
        """
        db = DatabaseUtils()
        if not domains:
            if not start:
                start = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

            if not end:
                end = datetime.datetime.now().strftime('%Y-%m-%d')
            domains = db.get_registered_by_date(start, end)

        logger.info("Start Alerting ({} domains)".format(len(domains)))
        alerts = Alerts()
        matches = list()

        # create alerts on watchlist
        matches.extend(alerts.check_watchlist(domains))

        # create alerts on keywords
        matches.extend(alerts.check_keywords())

        # create alerts on heuristics
        matches.extend(alerts.check_heuristics(domains))

        # create alerts on certificates
        matches.extend(alerts.check_certificates(start=start, end=end))

        alert_ids = alerts.create(matches)
        logger.info("Alerts created: {}".format(len(alert_ids)))

    def resolve(self):
        logger.info("Start resolving main domains")
        alerts = Alerts()
        matches = alerts.check_ip()
        alert_ids = alerts.create(matches)
        logger.info("Alerts created: {}".format(len(alert_ids)))

    def get_alerts(self, status='open'):
        alerts = Alerts()
        hits = alerts.get_alerts(status=status)
        logger.info("Found open alerts (total): {}".format(len(hits)))

        hits_by_value = alerts.get_alerts_grouped_by_value(hits)
        logger.info("Found open alerts (unique): {}".format(len(hits_by_value)))

        hits_by_category = alerts.get_alerts_grouped_by_category(hits)
        for category in hits_by_category:
            category_by_value = alerts.get_alerts_grouped_by_value(hits_by_category[category])
            logger.info("Found open alerts with category {} (unique): {}".format(category, len(category_by_value)))
        return hits

    def close_alert(self, alert):
        alerts = Alerts()
        alerts.close(alert)

    def enrich(self, domains=None, start=False, end=False, limit=0, missing_only=False):
        db = DatabaseUtils()
        if not domains:
            if not start:
                start = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

            if not end:
                end = datetime.datetime.now().strftime('%Y-%m-%d')
            domains = db.get_registered_by_date(start, end)
            if missing_only:
                domains = db.get_missing_enrichments([x.get('value') for x in domains], start, end)
        logger.info("Start Enrichment ({} domains)".format(len(domains)))
        e = Enrichment(domains, limit=limit)
        e.enrich()

        db.add_enrichments(e.enrichments)
        logger.info("Completed enrichment.")


if __name__ == '__main__':
    parser = ArgumentParser()
    # adding
    parser.add_argument('-d', '--domain', action='store', default=False, dest='domain',
                        help='Add new domain to watchlist')
    parser.add_argument('-g', '--generate', action='store', default=False, dest='generate',
                        help='Only generate typo domains for domain, results are not stored in watchlist')

    # collecting
    parser.add_argument('-c', '--collect', action='store_true', default=False, dest='collect',
                        help='Collect recently registered domains')

    # alerting
    parser.add_argument('-a', '--alert', action='store_true', default=False, dest='alert',
                        help='Create alerts by checking watchlist and keywords')
    parser.add_argument('--start', action='store', default=False, dest='start',
                        help='Start date for creating alerts (default: last 24h)')
    parser.add_argument('--end', action='store', default=False, dest='end',
                        help='End date for creating alerts (default: now)')
    parser.add_argument('--get_alerts', action='store_true', default=False, dest='get_alerts',
                        help='Get all alerts (default: open only)')

    # resolve
    parser.add_argument('-r', '--resolve', action='store_true', default=False, dest='resolve',
                        help='Create alerts by resolving domain names')

    # enrich
    parser.add_argument('-e', '--enrich', action='store_true', default=False, dest='enrich',
                        help='Only perform enrichment for domain(s)')
    parser.add_argument('--e_domain', action='store', default=False, dest='enrich_domain',
                        help='Only perform enrichment for domain(s)')

    # score
    parser.add_argument('-s', '--score', action='store_true', default=False, dest='score',
                        help='Only perform scoring for domain(s)')
    parser.add_argument('--s_domain', action='store', default=False, dest='score_domain',
                        help='Only perform enrichment for given domain')

    # run mode
    parser.add_argument('-f', '--full', action='store_true', default=False, dest='full',
                        help='Perform full set up actions: Collect, Enrich, Score, Alert')

    parser.add_argument('-u', '--update', action='store_true', default=False, dest='update',
                        help='Perform following actions: Collect, Score, Alert')

    opts = parser.parse_args()

    start_time = datetime.datetime.now()

    d = DomainWatcher()
    logger.info("--- Start Processing ---")

    if opts.domain:
        d.generate(opts.domain)

    if opts.generate:
        d.generate(opts.generate, store=False)

    if opts.collect:
        d.collect(download=False)

    if opts.score:
        d.score(domains=opts.score_domain, start=opts.start, end=opts.end)

    if opts.alert:
        d.alert(start=opts.start, end=opts.end)

    if opts.resolve:
        d.resolve()

    if opts.get_alerts:
        alert_list = d.get_alerts()
        for a in alert_list:
            d.close_alert(a)

    if opts.enrich:
        d.enrich(domains=opts.enrich_domain, limit=1000, missing_only=True)

    if opts.full:
        res = d.collect()
        d.enrich(res)
        d.score()
        d.alert(res)

    if opts.update:
        res = d.collect()
        d.score(res)
        d.alert(res)
        d.resolve()

    delta = datetime.datetime.now() - start_time
    logger.info("--- Processing took {} seconds ---".format(delta.total_seconds()))
