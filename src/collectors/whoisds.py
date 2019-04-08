import zipfile
import requests
import os
import base64
import datetime
from settings.config import DOMAIN_CONFIG, COLLECTOR_CONFIG

import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Collect:
    def __init__(self, get_new=True):
        self.source = COLLECTOR_CONFIG['whoisds']['name']
        self.dir = COLLECTOR_CONFIG['whoisds']['input']
        self.url = COLLECTOR_CONFIG['whoisds']['url']

        self.src = self._build_fn(self.dir, 'domains.zip')
        self.dest = self._build_fn(self.dir, 'domains')
        self.fn = 'domain-names.txt'

        self.get_new = get_new

        self.domains = None

    def _build_fn(self, dn, name):
        if dn.endswith('/'):
            dn = dn[:-1]
        return "{}/{}".format(dn, name)

    def _build_url(self):
        date = datetime.datetime.now() - datetime.timedelta(days=1)
        s = "{}.zip".format(date.strftime('%Y-%m-%d'))
        b64 = (base64.b64encode(s.encode())).decode('utf8')
        return self.url.format(b64)

    def _unzip(self):
        try:
            zip_ref = zipfile.ZipFile(self.src, 'r')
            zip_ref.extractall(self.dest)
            zip_ref.close()
        except FileNotFoundError:
            os.makedirs(self.dir, exist_ok=True)
            self._unzip()
        except Exception as e:
            logger.exception(e)

    def _store(self, r):
        try:
            with open(self.src, 'wb') as f:
                for chunk in r:
                    f.write(chunk)
        except FileNotFoundError:
            os.makedirs(self.dir, exist_ok=True)
            self._store(r)

    def _download(self, url):
        try:
            r = requests.get(url, stream=True, timeout=3*60)
            if r.status_code == 200:
                self._store(r)
        except Exception as e:
            logger.exception(e)

    def _load(self):
        with open(self._build_fn(self.dest, self.fn), 'r') as f:
            raw_data = f.readlines()

        data = list()
        for raw in raw_data:
            data.append(raw.replace('\n', ''))

        self.domains = data

    def get(self):
        if self.get_new:
            url = self._build_url()
            self._download(url)
            self._unzip()
        self._load()

