import certstream
from scoring.phishing.phishing_score import PhishingScore
from settings.config import CERTIFICATE_WATCH_CONFIG
from database.database import DatabaseUtils

import logging

logger = logging.getLogger()


class CertificateWatcher:
    def __init__(self):
        self._logger()
        self.url = CERTIFICATE_WATCH_CONFIG['url']
        self.threshold = CERTIFICATE_WATCH_CONFIG['threshold']
        self.score = PhishingScore()
        self.data = list()
        self.store_threshold = 0

    def _logger(self):
        # create logger with 'spam_application'
        logger.setLevel(logging.INFO)
        # create file handler which logs even debug messages
        fh = logging.FileHandler(CERTIFICATE_WATCH_CONFIG['log_file'])
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

    def _store(self, data):
        self.data.append(data)

        if len(self.data) > self.store_threshold:
            db = DatabaseUtils()
            db.add_certificate_watch_data(self.data)
            self.data.clear()

    def _callback(self, message, context):
        """Callback handler for certstream events."""
        if message['message_type'] == "heartbeat":
            return

        if message['message_type'] == "certificate_update":
            all_domains = message['data']['leaf_cert']['all_domains']

            for domain in all_domains:
                score = self.score.run(domain.lower())

                # If issued from a free CA = more suspicious
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 10

                if score >= self.threshold:
                    data = message['data']
                    data['value'] = domain
                    self._store(data)
                    logger.info("Found suspicious domain: {}".format(domain))
                    break

    def watch(self):
        certstream.listen_for_events(self._callback, url=self.url)


if __name__ == '__main__':
    c = CertificateWatcher()
    c.watch()
