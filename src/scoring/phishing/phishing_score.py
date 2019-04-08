import re
import yaml
import entropy
from Levenshtein import distance
from tld import get_tld
from scoring.phishing.confusables import unconfuse

from settings.config import DOMAIN_CONFIG, SCORING_CONFIG, GENERATOR_CONFIG
import logging


logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class PhishingScore:
    def __init__(self):
        self.config = SCORING_CONFIG['phishing']
        self.suspicious = self._load_suspicious()
        self._load_external()
        self.alexa_whitelist = self._load_alexa_whitelist()
        self.google_whitelist = self._load_google_whitelist()
        self.internal_whitelist = self._load_internal_whitelist()

    def _load_suspicious(self):
        with open(self.config['suspicious.yaml'], 'r') as f:
            suspicious = yaml.safe_load(f)
        return suspicious

    def _load_external(self):
        with open(self.config['external.yaml'], 'r') as f:
            external = yaml.safe_load(f)

        if external['keywords'] is not None:
            self.suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            self.suspicious['tlds'].update(external['tlds'])

    @staticmethod
    def _load_internal_whitelist():
        """
        populates list with known good domains. This method is can also be used for generation of watchlist.
        :return:
        """
        # TODO: replace this function with global whitelist service -> fetch current data from a service not from file
        data = dict()
        logger.debug("Loading Internal whitelist data...")
        try:
            with open(GENERATOR_CONFIG['internal_whitelist_file']) as top1m:
                for line in top1m:
                    parts = line.rstrip().split(',', 1)
                    if len(parts) == 2:
                        data[parts[1]] = int(parts[0])
        except FileNotFoundError:
            logger.info("Internal Whitelist not found..skipping")
        except Exception as e:
            logger.error("[Internal Whitelist] Exception: {}".format(e))
        return data

    @staticmethod
    def _load_alexa_whitelist():
        """
        populates list with known alexa top X domains. This method is also used for generation of watchlist.
        :return:
        """
        # TODO: replace this function with global whitelist service -> fetch current data from a service not from file
        data = dict()
        logger.debug("Loading Alexa data...")
        try:
            with open(GENERATOR_CONFIG['alexa_whitelist_file']) as top1m:
                for line in top1m:
                    parts = line.rstrip().split(',', 1)
                    if len(parts) == 2:
                        data[parts[1]] = int(parts[0])
        except FileNotFoundError:
            logger.info("Alexa Whitelist not found..skipping")
        except Exception as e:
            logger.error("[Alexa Whitelist] Exception: {}".format(e))
        return data

    @staticmethod
    def _load_google_whitelist():
        """
        populates list with known good google domains. This method is can also be used for generation of watchlist.
        :return:
        """
        # TODO: replace this function with global whitelist service -> fetch current data from a service not from file
        data = dict()
        logger.debug("Loading Google Whitelist data...")
        try:
            with open(GENERATOR_CONFIG['google_whitelist_file']) as top1m:
                for line in top1m:
                    parts = line.rstrip().split(',', 1)
                    if len(parts) == 2:
                        data[parts[1]] = int(parts[0])
        except FileNotFoundError:
            logger.info("Google Whitelist not found..skipping")
        except Exception as e:
            logger.error("[Google Whitelist] Exception: {}".format(e))
        return data

    def _calculate(self, domain):
        """
        Score `domain`. The highest score, the most probable `domain` is a phishing site.
        Args:
            domain (str): the domain to check.
        Returns:
            int: the score of `domain`.
        """
        score = 0

        # skipp scoring if on any popular whitelist
        if domain in self.internal_whitelist or domain in self.alexa_whitelist or domain in self.google_whitelist:
            return 0

        for t in self.suspicious['tlds']:
            if domain.endswith(t):
                score += self.config['weights']['suspicious_tld']

        # Remove initial '*.' for wildcard certificates bug
        if domain.startswith('*.'):
            domain = domain[2:]

        # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
        try:
            res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
            domain = '.'.join([res.subdomain, res.domain])
        except Exception:
            pass

        # Higher entropy is kind of suspicious
        score += int(round(entropy.shannon_entropy(domain) * self.config['weights']['shannon_multiplier']))

        # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
        domain = unconfuse(domain)

        words_in_domain = re.split("\W+", domain)

        # Remove initial '*.' for wildcard certificates bug
        if domain.startswith('*.'):
            domain = domain[2:]
            # ie. detect fake .com (ie. *.com-account-management.info)
            if words_in_domain[0] in ['com', 'net', 'org']:
                score += self.config['weights']['fake_tld']

        # Testing keywords
        for word in self.suspicious['keywords']:
            if word in domain:
                score += self.suspicious['keywords'][word]

        # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
        for key in [k for (k, s) in self.suspicious['keywords'].items() if s >= 70]:
            # Removing too generic keywords (ie. mail.domain.com)
            for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                if distance(str(word), str(key)) == 1:
                    score += self.config['weights']['levenshtein']

        # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
        if 'xn--' not in domain and domain.count('-') >= 4:
            score += domain.count('-') * self.config['weights']['dash_multiplier']

        # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
        if domain.count('.') >= 3:
            score += domain.count('.') * self.config['weights']['nested_subdomains_multiplier']

        return score

    def run(self, domain):
        try:
            return self._calculate(domain)
        except Exception as e:
            logging.error("[Phishing Score] Cannot calculate score for {}: {}".format(domain, e))
