from pythonwhois import get_whois
from settings.config import DOMAIN_CONFIG, TIMEFORMAT
import logging

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class WHOIS:
    def __init__(self, limit=0):
        self.source = 'whois'
        self.limit = limit
        self.results = list()

    @staticmethod
    def _parse_datetime(date):
        try:
            return date[0].strftime(TIMEFORMAT)
        except IndexError:
            logger.debug("WHOIS date entry missing")
            return date
        except Exception as e:
            logger.error("Cannot parse WHOIS datetime: {}".format(e))
            return date

    @staticmethod
    def _parse_status(data):
        status = list()
        for s in data:
            try:
                status.append(s.split(' ', 1)[0])
            except IndexError:
                status.append(s)
            except Exception as e:
                logger.error("Cannot parse WHOIS status: {}".format(e))
        return status

    @staticmethod
    def _parse_contacts(data):
        try:
            return data
        except Exception as e:
            logger.error("Cannot parse WHOIS contact: {}".format(e))
            return data

    def _parse(self, data, domain):
        parsed = dict()
        parsed['value'] = domain
        parsed['registrar_created_on'] = self._parse_datetime(data.get('creation_date', []))
        parsed['registrar_updated_on'] = self._parse_datetime(data.get('updated_date', []))
        parsed['registrar_expires_on'] = self._parse_datetime(data.get('expiration_date', []))
        parsed['registrant_org'] = data.get('registrar', [])
        parsed['registrant_org'] = data.get('registrar', [])
        parsed['whois_server'] = data.get('whois_server', [])
        parsed['nameservers'] = data.get('nameservers', [])

        # contacts
        parsed['registrant_contact'] = self._parse_contacts(data.get('contacts', {}).get('registrant', ''))
        parsed['technical_contact'] = self._parse_contacts(data.get('contacts', {}).get('tech', ''))
        parsed['admin_contact'] = self._parse_contacts(data.get('contacts', {}).get('admin', ''))
        parsed['billing_contact'] = self._parse_contacts(data.get('contacts', {}).get('billing', ''))
        parsed['email_address'] = data.get('emails', [])

        # status
        status = list()
        for s in data.get('status', []):
            try:
                status.append(s.split(' ', 1)[0])
            except IndexError:
                status.append(s)
        parsed['registrar_status'] = self._parse_status(data.get('status', []))

        return parsed

    def _get(self, domain):
        try:
            whois = get_whois(domain)
            self.results.append(self._parse(whois, domain))
        except ConnectionResetError:
            logger.error("Cannot connect to WHOIS server for: {}".format(domain))
        except Exception as e:
            logger.exception("Cannot get WHOIS data for {}: {}".format(domain, e))

    def run(self, data):
        if isinstance(data, list):
            for count, domain in enumerate(data):
                if self.limit and count >= self.limit:
                    return
                if not count % 100:
                    logger.debug("Processing {}/{}".format(count, len(data)))
                self._get(domain)
        else:
            self._get(data)
