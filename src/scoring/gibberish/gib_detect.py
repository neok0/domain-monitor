import pickle
from scoring.gibberish.gib_detect_train import GibberishLearner
from settings.config import DOMAIN_CONFIG, SCORING_CONFIG
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Gibberish:
    def __init__(self):
        self.config = SCORING_CONFIG['gibberish']
        self.model_data = self._load_model()
        self.model_mat = self.model_data['mat']
        self.threshold = self.model_data['thresh']
        self.gibberish = GibberishLearner()

    def _initialize(self):
        self.gibberish.train()

    def _load_model(self):
        try:
            return pickle.load(open(self.config['gib_model'], 'rb'))
        except FileNotFoundError:
            self._initialize()
            self._load_model()
        except Exception as e:
            logging.error("Cannot load gibberish model: {}".format(e))
            return None

    def _calculate(self, domain):
        r = self.gibberish.avg_transition_prob(domain, self.model_mat) > self.threshold
        if r:
            return 0
        else:
            return self.config['weights']['gibberish']

    def run(self, domain):
        try:
            return self._calculate(domain)
        except Exception as e:
            logging.error("Error Gibberish value cannot be determined for {}: {}".format(domain, e))
            return 0
