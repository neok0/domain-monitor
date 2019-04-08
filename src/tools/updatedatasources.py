import urllib.request
import os
import gzip
from zipfile import ZipFile

from settings.config import GENERATOR_CONFIG


def ungzip(in_file, out_file):
    with gzip.open(in_file) as in_data:
        with open(out_file, "wb") as out_file:
            out_file.write(in_data.read())
    os.remove(in_file)


def unzip(in_file, inner_file, out_dir):
    with ZipFile(in_file) as in_data:
        in_data.extract(inner_file, out_dir)
    os.remove(in_file)


urllib.request.urlretrieve("http://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
                           "{}.zip".format(GENERATOR_CONFIG['alexa_whitelist_file']))
unzip("{}.zip".format(GENERATOR_CONFIG['alexa_whitelist_file']), "top-1m.csv",
      GENERATOR_CONFIG['alexa_whitelist_file'].split('/', 1)[0])

urllib.request.urlretrieve("https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
                           GENERATOR_CONFIG['tlds_by_domain_file'])

urllib.request.urlretrieve("http://www.unicode.org/Public/security/latest/confusables.txt",
                           GENERATOR_CONFIG['confusables_file'])

urllib.request.urlretrieve("http://publicsuffix.org/list/effective_tld_names.dat", GENERATOR_CONFIG['tld_names_file'])

