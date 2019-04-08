from database.database import DatabaseUtils
from collections import defaultdict
from settings.config import DOMAIN_CONFIG, SCORING_CONFIG
import datetime
import socket
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Alerts:
    def __init__(self):
        pass

    def _make_list(self, data):
        tmp = list()
        for d in data:
            if isinstance(d, str):
                return data
            tmp.append(d.get('value'))
        return tmp

    def _sorted(self, data, field='value'):
        sorted_dict = defaultdict(list)
        for d in data:
            sorted_dict[d.get(field)].append(d)
        return sorted_dict

    def _compare(self, watchlist, registered):
        w = self._make_list(watchlist)
        r = self._make_list(registered)
        # TODO: deleteme, this invokes at least one alert (for testing purposes)
        # r.append(w[-1])
        matches = list()
        for i in w:
            if i in r:
                matches.append(i)
        return matches

    def _heuristics(self, registered):
        matches = list()
        db = DatabaseUtils()
        score_hits = db.get_score(score=SCORING_CONFIG['threshold'])
        sorted_score = self._sorted(score_hits)
        for r in registered:
            if isinstance(r, dict):
                r = r.get('value')
            if r in sorted_score:
                matches.append({'value': r, 'score': sorted_score[r][-1].get('score')})
        return matches

    def _certificats(self, start=False, end=False):
        db = DatabaseUtils()
        certificates_hits = db.get_certificates(start=start, end=end)

        return certificates_hits

    def check_watchlist(self, domains):
        db = DatabaseUtils()
        domains_to_watch = db.get_domains()
        matches = list()
        for domain in domains_to_watch:
            watchlist = db.get_watchlist_by_parent(domain.get('id'))
            watchlist_matches = self._compare(watchlist, domains)
            for match in watchlist_matches:
                m = dict()
                m['parent'] = domain.get('value')
                m['value'] = match
                m['match'] = domain.get('value')
                m['source'] = 'watchlist'
                matches.append(m)
        return matches

    def check_keywords(self):
        db = DatabaseUtils()
        domains_to_watch = db.get_domains()
        matches = list()
        for domain in domains_to_watch:
            keywords = domain.get('keywords')
            for keyword in keywords:
                keyword_matches = db.get_registered_by_keyword(keyword)
                for match in keyword_matches:
                    m = dict()
                    m['parent'] = domain.get('value')
                    m['value'] = match
                    m['match'] = keyword
                    m['source'] = 'keyword'
                    matches.append(m)

        return matches

    def check_heuristics(self, domains):
        matches = list()
        heuristic_matches = self._heuristics(domains)
        for match in heuristic_matches:
            m = dict()
            m['parent'] = match.get('value')
            m['value'] = match.get('value')
            m['match'] = match.get('score')
            m['source'] = 'heuristic'
            matches.append(m)
        return matches

    def check_certificates(self, start=False, end=False):
        if not start:
            start = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

        if not end:
            end = datetime.datetime.now().strftime('%Y-%m-%d')

        matches = list()
        certificate_matches = self._certificats(start=start, end=end)
        for match in certificate_matches:
            m = dict()
            m['parent'] = match.get('value')
            m['value'] = match.get('value')
            m['match'] = match.get('cert_domains')
            m['source'] = 'certificate'
            matches.append(m)
        return matches

    def check_ip(self):
        db = DatabaseUtils()
        domains_to_watch = db.get_domains()
        matches = list()
        for domain in domains_to_watch:
            ip_address = self._get_ip_address(domain.get('value'))
            if ip_address and not domain.get('ip_address') == ip_address:
                m = dict()
                m['parent'] = domain.get('value')
                m['values'] = [ip_address]
                m['match'] = domain.get('ip_address')
                m['source'] = 'ip_address'
                matches.append(m)

        return matches

    def get_alerts(self, status='open'):
        """
        this method returns all alerts (default status='open')
        :param status:
        :return:
        """
        db = DatabaseUtils()
        alerts = db.get_alerts(status=status)
        return alerts

    def get_alerts_grouped_by_value(self, alerts=None, status='open'):
        if not alerts:
            alerts = self.get_alerts(status=status)
        return self._sorted(alerts)

    def get_alerts_grouped_by_category(self, alerts=None, status='open'):
        if not alerts:
            alerts = self.get_alerts(status=status)
        return self._sorted(alerts, field='source')

    def get_alert(self, value):
        db = DatabaseUtils()
        alerts = db.get_alerts(value=value)
        return alerts

    def exists(self, alerts):
        if not isinstance(alerts, list):
            alerts = [alerts]

        hits = list()
        db = DatabaseUtils()
        for alert in alerts:
            if isinstance(alert, dict):
                alert = alert.get('value')
            keys = [
                {'value': alert},
                {'status': 'closed'},
                ]
            hits.extend(db.exists(keys, index='alerts_index'))
        return self._sorted(hits)

    def _close_alert(self, alert):
        db = DatabaseUtils()
        db.update_alert_status(alert)

    def close(self, alert):
        """
        this method closes all alerts matching on the same value.
        :param alert: either list of alerts, alert(dict) or alert(value)
        :return:
        """
        if isinstance(alert, list):
            for a in alert:
                self.close(a)
        if isinstance(alert, dict):
            alert = alert.get('value')
        # find all matching alerts
        hits = self.get_alert(alert)
        self._close_alert(hits)

    @staticmethod
    def _get_ip_address(domain):
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            logger.error("Cannot retrieve ip address for hostname: {}".format(domain))
            return False

    def create(self, matches):
        db = DatabaseUtils()
        alert_ids = list()
        for match in matches:
            parent = match.get('parent')
            value = match.get('value')
            if isinstance(value, dict):
                value = value.get('value')
            if value in self.exists(value):
                logger.info("Skipping alert creation for: {}".format(value))
                continue
            a_id = db.create_alerts(parent, value, match.get('source'), match.get('match'))
            alert_ids.extend(a_id)
        return alert_ids
