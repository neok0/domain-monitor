from elasticsearch import Elasticsearch

from settings.config import DATABASE_CONFIG, TIMEFORMAT


class EnrichMissing:
    """
    This Class can be used to enrich only missing domains
    """
    def __init__(self):
        self.es = Elasticsearch(DATABASE_CONFIG['es_host'])
        self.time_format = TIMEFORMAT

    def run(self):
        pass
