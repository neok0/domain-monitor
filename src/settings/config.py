import os

BASE = os.path.join(os.getcwd(), 'src')

TIMEFORMAT = '%Y-%m-%d %H:%M:%S'

DOMAIN_CONFIG = {
    'logger': 'domain.log',
    'log_file': os.path.join(BASE, 'logs', 'domain_monitor.log'),

}

CERTIFICATE_WATCH_CONFIG = {
    'logger': 'certificate_watcher.log',
    'log_file': os.path.join(BASE, 'logs', 'certificate_watcher.log'),
    'url': 'wss://certstream.calidog.io',
    'threshold': 100
}

COLLECTOR_CONFIG = {
    'whoisds': {
        'name': 'whoisds',
        'url': 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd',
        'input':  os.path.join(BASE, 'tmp/whoisds'),
    }
}

DATABASE_CONFIG = {
    # indicies
    'domains_index': 'domains',
    'certificate_index': 'certificates',
    'watchlist_index': 'watchlist',
    'alerts_index': 'alerts',
    'registered_index': 'registered',
    'whois_index': 'whois',
    'pdns_index': 'pdns',
    'scoring_index': 'score',

    # database
    'es_host': 'http://localhost:18075',
    'es_timeformat': 'YYYY-MM-DD HH:mm:ss',

}
SCORING_CONFIG = {
    'threshold': 100,
    'gibberish': {
        'gib_model': os.path.join(BASE, 'scoring', 'gibberish', 'data', 'gib_model.pki'),
        'weights': {
            'gibberish': 50,
        }
    },
    'phishing': {
        'suspicious.yaml': os.path.join(BASE, 'scoring', 'phishing', 'data', 'suspicious.yaml'),
        'external.yaml': os.path.join(BASE, 'scoring', 'phishing', 'data', 'suspicious.yaml'),
        'weights': {
            'suspicious_tld': 20,
            'shannon_multiplier': 50,
            'fake_tld': 10,
            'levenshtein': 70,
            'dash_multiplier': 3,
            'nested_subdomains_multiplier': 3,
        }
    },
}


GENERATOR_CONFIG = {
    'qwerty': {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6',
        '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6',
        'u': '8ijhy7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy',
        'j': 'ikmnhu',
        'k': 'olmji', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    },
    'qwertz': {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5',
        '7': '8uz6', '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5',
        'z': '7uhgt6', 'u': '8ijhz7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft',
        'h': 'ujnbgz', 'j': 'ikmnhu',
        'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm',
        'm': 'njk'
    },
    'azerty': {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4',
        '6': '7yt5', '7': '8uy6', '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4',
        't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr',
        'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu',
        'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
        'n': 'bhj'
    },

    'homoglyphs': {
        'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'а', u'ạ', u'ǎ', u'ă', u'ȧ', u'ӓ'],
        'b': ['d', 'lb', 'ib', u'ʙ', u'Ь', u'b̔', u'ɓ', u'Б'],
        'c': [u'ϲ', u'с', u'ƈ', u'ċ', u'ć', u'ç'],
        'd': ['b', 'cl', 'dl', 'di', u'ԁ', u'ժ', u'ɗ', u'đ'],
        'e': [u'é', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'е', u'ẹ', u'ę', u'є', u'ϵ', u'ҽ'],
        'f': [u'Ϝ', u'ƒ', u'Ғ'],
        'g': ['q', u'ɢ', u'ɡ', u'Ԍ', u'Ԍ', u'ġ', u'ğ', u'ց', u'ǵ', u'ģ'],
        'h': ['lh', 'ih', u'һ', u'հ', u'Ꮒ', u'н'],
        'i': ['1', 'l', u'Ꭵ', u'í', u'ï', u'ı', u'ɩ', u'ι', u'ꙇ', u'ǐ', u'ĭ', u'ì'],
        'j': [u'ј', u'ʝ', u'ϳ', u'ɉ'],
        'k': ['lk', 'ik', 'lc', u'κ', u'ⲕ', u'κ'],
        'l': ['1', 'i', u'ɫ', u'ł'],
        'm': ['n', 'nn', 'rn', 'rr', u'ṃ', u'ᴍ', u'м', u'ɱ'],
        'n': ['m', 'r', u'ń'],
        'o': ['0', u'Ο', u'ο', u'О', u'о', u'Օ', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö', u'ӧ'],
        'p': [u'ρ', u'р', u'ƿ', u'Ϸ', u'Þ'],
        'q': ['g', u'զ', u'ԛ', u'գ', u'ʠ'],
        'r': [u'ʀ', u'Г', u'ᴦ', u'ɼ', u'ɽ'],
        's': [u'Ⴝ', u'Ꮪ', u'ʂ', u'ś', u'ѕ'],
        't': [u'τ', u'т', u'ţ'],
        'u': [u'μ', u'υ', u'Ս', u'ս', u'ц', u'ᴜ', u'ǔ', u'ŭ'],
        'v': [u'ѵ', u'ν', u'v̇'],
        'w': ['vv', u'ѡ', u'ա', u'ԝ'],
        'x': [u'х', u'ҳ', u'ẋ'],
        'y': [u'ʏ', u'γ', u'у', u'Ү', u'ý'],
        'z': [u'ʐ', u'ż', u'ź', u'ʐ', u'ᴢ']
    },

    'default_tld_to_add': ['cm', 'co', 'uk', 'ru'],

    'tld_names_file': os.path.join(BASE, 'datasources/effective_tld_names.dat'),
    'tlds_by_domain_file': os.path.join(BASE, 'datasources/tlds-alpha-by-domain.txt'),
    'alexa_whitelist_file': os.path.join(BASE, 'datasources/top-1m.csv'),
    'google_whitelist_file': os.path.join(BASE, 'datasources/google.txt'),
    'internal_whitelist_file': os.path.join(BASE, 'datasources/google.txt'),
    'confusables_file': os.path.join(BASE, 'datasources/confusables.txt'),
    'country_names_file': os.path.join(BASE, 'datasources/countrynames.txt'),
    'subdomains_file': os.path.join(BASE, 'datasources/subdomains.txt'),
}
