from scoring.gibberish.gib_detect import Gibberish
from scoring.phishing.phishing_score import PhishingScore
from settings.config import DOMAIN_CONFIG
from collections import defaultdict
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Scoring:
    def __init__(self):
        self.gibberish = Gibberish()
        self.phishing = PhishingScore()

    def score(self, domains):
        s = list()
        for count, domain in enumerate(domains):
            # debugging helper
            if not count % 1000:
                logging.debug("Scoring {}/{}..".format(count, len(domains)))

            if isinstance(domain, dict):
                domain = domain.get('value')

            scoring_value = 0
            data = dict()
            # data = defaultdict(list)

            # gibberish
            res = self.gibberish.run(domain)
            data['gibberish'] = {'method': 'gibberish', 'score': res}
            # data['methods'].append({'method': 'gibberish', 'score': res})
            scoring_value += res

            # phishing
            res = self.phishing.run(domain)
            data['phishing'] = {'method': 'phishing', 'score': res}
            # data['methods'].append({'method': 'phishing', 'score': res})
            scoring_value += res

            s.append({'value': domain, 'score': scoring_value, 'data': data})

        return s
