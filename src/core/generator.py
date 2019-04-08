import re
import copy
import codecs
import stringprep
from publicsuffix import PublicSuffixList
import logging

from settings.config import DOMAIN_CONFIG, GENERATOR_CONFIG

logger = logging.getLogger(DOMAIN_CONFIG['logger'])


class Generator:
    def __init__(self):
        self.tlds = self._load_tlds()
        self.alexa_top = self._load_alexa_whitelist()
        self.psl = PublicSuffixList(input_file=codecs.open(GENERATOR_CONFIG['tld_names_file'], "r", "utf8"))
        self.homoglyphs_confusables = self.loadconfusables()

        self.keyboards = [GENERATOR_CONFIG['qwerty'], GENERATOR_CONFIG['qwertz'], GENERATOR_CONFIG['azerty']]

        self.homoglyphs = GENERATOR_CONFIG['homoglyphs']

        self.typo_domains = list()

    @staticmethod
    def _load_tlds():
        # Load up the list of TLDs
        logger.debug("Loading TLDs...")
        tlds = list()
        try:
            with open(GENERATOR_CONFIG['tlds_by_domain_file']) as f:
                for line in f:
                    if not line.lstrip().startswith('#'):
                        tlds.append(line.rstrip().lower())
        except FileNotFoundError:
            logger.error("TLDs file not found..skipping")
        except Exception as e:
            logger.error("[TLDs File] Exception: {}".format(e))
        return tlds

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
            logger.error("Alexa Whitelist not found..skipping")
        except Exception as e:
            logger.error("[Alexa Whitelist] Exception: {}".format(e))
        return data

    @staticmethod
    def loadconfusables():
        logger.debug("Loading confusables...")
        homoglyphs_confusables = dict()
        rejected_sequences = set()

        # 'utf_8_sig' swallows the BOM at start of file
        with open(GENERATOR_CONFIG['confusables_file'], "r", encoding="'utf_8_sig") as f:
            for line in f:
                # If line contains more than whitespace and isn't a comment
                if line.strip() and not line.startswith("#"):
                    split = line.split(';', maxsplit=2)
                    # parse the left hand side of the pairing
                    unihex = split[0].split(' ')[0]
                    part0 = (chr(int(unihex, 16)))

                    if part0 in rejected_sequences:
                        continue

                    # parse the right hand side of the pairing
                    part1 = ''
                    for unihex in split[1].strip().split(' '):
                        part1 += (chr(int(unihex, 16)))

                    if part1 in rejected_sequences:
                        continue

                    # Skip pairs already in the _homoglyphs dict
                    if part0 in homoglyphs_confusables and part1 in homoglyphs_confusables[part0]:
                        continue

                    try:
                        # filter out glyphs which do not survive round trip conversion, e.g. ß -> ss -> ss
                        if 'a' + part0 + 'b' != codecs.decode(codecs.encode('a' + part0 + 'b', "idna"), "idna"):
                            rejected_sequences.add(part0)
                            continue
                    except UnicodeError:
                        # Some characters/combinations will fail the nameprep stage
                        rejected_sequences.add(part0)
                        continue

                    try:
                        # filter out glyphs which do not survive round trip conversion, e.g. ß -> ss -> ss
                        if 'a' + part1 + 'b' != codecs.decode(codecs.encode('a' + part1 + 'b', "idna"), "idna"):
                            rejected_sequences.add(part1)
                            continue
                    except UnicodeError:
                        # Some characters/combinations will fail the nameprep stage
                        rejected_sequences.add(part1)
                        continue

                    # Include left to right pair mapping in the dict
                    if part0 not in homoglyphs_confusables:
                        homoglyphs_confusables[part0] = set()
                    homoglyphs_confusables[part0].add(part1)

                    # Include right to left pair mapping in the dict
                    if part1 not in homoglyphs_confusables:
                        homoglyphs_confusables[part1] = set()
                    homoglyphs_confusables[part1].add(part0)
        return homoglyphs_confusables

    def is_domain_valid(self, domain):
        # Ensure its in the correct character set
        if not re.match('^[a-z0-9.-]+$', domain):
            return False
        # Ensure the TLD is sane
        elif domain[domain.rfind(".") + 1:] not in self.tlds:
            return False
        # hostnames can't start or end with a -
        elif ".-" in domain or "-." in domain or domain.startswith("-"):
            return False
        # Ensure the location of dots are sane
        elif ".." in domain or domain.startswith("."):
            return False
        else:
            return True

    @staticmethod
    def _add_result(r, fuzzer):
        return {'value': r, 'fuzzer': fuzzer}

    def bitflipbyte(self, inputbyte):
        """
        Flips the lowest 7 bits in the given input byte/int to build a list of mutated values.

        @param inputbyte: The byte/int to bit flip
        @return: A list of the mutated values.
        """
        result = list()
        mask = 1
        # As we know we're flipping ASCII, only do the lowest 7 bits
        for i in range(0, 7):
            result.append(inputbyte ^ mask)
            mask <<= 1
        return result

    def generate_country_code_doppelgangers(self, domain):
        result = list()
        with open(GENERATOR_CONFIG['country_names_file'], 'r', encoding="UTF-8") as countrynames:
            for line in countrynames:
                if not line.startswith('#'):
                    parts = line.split(';', maxsplit=2)
                    # 2 letter country code subdomain, but without the dot
                    result.append(self._add_result(parts[0].strip().lower() + domain, 'country_code_doppelgangers'))
                    # 3 letter country code subdomain, but without the dot
                    result.append(self._add_result(parts[1].strip().lower() + domain, 'country_code_doppelgangers'))
        return result

    def generate_subdomain_doppelgangers(self, domain):
        result = list()
        with open(GENERATOR_CONFIG['subdomains_file'], 'r') as subdomains:
            for subdomain in subdomains:
                result.append(self._add_result(subdomain.strip() + domain, 'subdomain_doppelgangers'))
        return result

    def generate_extra_dot_doppelgangers(self, domain):
        result = list()
        for idx, char in enumerate(domain):
            # A dot instead of a character
            result.append(self._add_result(domain[:idx] + '.' + domain[idx + 1:], 'extra_dot_doppelgangers'))
            # A dot inserted between characters
            result.append(self._add_result(domain[:idx] + '.' + domain[idx:], 'extra_dot_doppelgangers'))
        return result

    def bitflipstring(self, s):
        """
        Flips the lowest 7 bits in each character of the given string to build a list of mutated values.

        @param s: The string to bit flip
        @return: A list of the mutated values.
        """
        result = list()
        i = 0
        for character in s:
            flipped_chars = self.bitflipbyte(character.encode("UTF-8")[0])
            for flipped_char in flipped_chars:
                result.append(self._add_result(s[:i] + chr(flipped_char) + s[i + 1:], 'bitflip'))
            i += 1
        return result

    def generate_missing_character_typos(self, domain):
        # missing characters
        result = list()
        idx = 0
        while idx < len(domain):
            str_typo = domain[0:idx] + domain[idx + 1:]
            idx += 1
            result.append(self._add_result(str_typo, 'missing_character'))
        return result

    def generate_duplicate_character_typos(self, domain):
        # duplicate characters
        result = list()
        idx = 0
        while idx < len(domain):
            domain_list = list(domain)
            if domain_list[idx] != '.':
                domain_list.insert(idx, domain_list[idx])
                str_typo = "".join(domain_list)
                result.append(self._add_result(str_typo, 'duplicated_character'))
            idx += 1
        return result

    def generate_miskeyed_typos(self, domain):
        # swap to a surrounding key for each character
        result = list()
        # load keyboard mapping
        for idx, char in enumerate(domain):
            for keyboard in self.keyboards:
                if char in keyboard:
                    for replacement_char in keyboard[char]:
                        result.append(self._add_result(domain[:idx] + replacement_char + domain[idx + 1:], 'miskeyed'))
        return result

    def generate_homoglyph_confusables_typos(self, domain):
        # swap characters to similar looking characters, based on Unicode's confusables.txt
        results = list()
        # Replace each homoglyph subsequence in the domain with each replacement
        # subsequence associated with the homoglyph subsequence
        for homoglyph_subsequence in self.homoglyphs_confusables:
            idx = 0
            while 1:
                idx = domain.find(homoglyph_subsequence, idx)
                if idx > -1:
                    for replacement_subsequence in self.homoglyphs_confusables[homoglyph_subsequence]:
                        # Add with just one change
                        newhostname = domain[:idx] + replacement_subsequence + domain[
                                                                               idx + len(homoglyph_subsequence):]
                        try:
                            results.append(self._add_result(str(codecs.encode(newhostname, "idna"), "ascii"),
                                                            'homoglyph_confusables'))
                        except UnicodeError:
                            # This can be caused by domain parts which are too long for IDNA encoding, so just skip it
                            pass

                        # Add with all occurrences changed
                        newhostname = domain.replace(homoglyph_subsequence, replacement_subsequence)
                        try:
                            if newhostname not in results:
                                results.append(self._add_result(str(codecs.encode(newhostname, "idna"), "ascii"),
                                                                'homoglyph_confusables'))
                        except UnicodeError:
                            # This can be caused by domain parts which are too long for IDNA encoding, so just skip it
                            pass

                    idx += len(homoglyph_subsequence)
                else:
                    break

        return results

    def generate_additional_homoglyph_typos(self, domain):
        # swap characters to similar looking characters, based on homoglyphs.txt
        result = list()
        for idx, char in enumerate(domain):
            if char in self.homoglyphs:
                for replacement_char in self.homoglyphs[char]:
                    newhostname = domain[:idx] + replacement_char + domain[idx + 1:]
                    try:
                        result.append(
                            self._add_result(str(codecs.encode(newhostname, "idna"), "ascii"), 'additional_homoglyph'))
                    except UnicodeError:
                        # This can be caused by domain parts which are too long for IDNA encoding, so just skip it
                        pass

        return result

    def generate_ings_and_plurals(self, domain):
        # add ing and plural s to the end of the domain based on what we do during phishing exercises

        ends = ["ing", "s"]

        splits = domain.split('.')
        splitdomain = splits[0]

        result = list()

        for end in ends:
            splits[0] = splitdomain + end
            result.append(self._add_result(".".join(splits), 'appended_ing_and_plural'))

        return result

    def generate_replace_i_l_1_o_0(self, domain):
        # add ing and plural s to the end of the domain based on what we do during phishing exercises

        splits = domain.split('.')
        splitdomain = splits[0]
        result = list()

        splits[0] = splitdomain.replace('i', '1')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('i', 'l')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('l', 'i')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('l', '1')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('1', 'l')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('1', 'i')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('o', '0')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        splits[0] = splitdomain.replace('0', 'o')
        result.append(self._add_result(".".join(splits), 'replaced_i_l_1_o_0'))

        return result

    def generate_ings_and_plurals_then_replace_i_l_1_o_0(self, domain):
        # nomnination for stupidest method name of the year award
        lstingsnplurs = list()
        lstingsnplurs += self.generate_ings_and_plurals(domain)
        result = list()

        for domain in lstingsnplurs:
            result += self.generate_replace_i_l_1_o_0(domain.get('value'))

        return result

    def generate_swap_key_tlds(self, no_suffix):
        result = list()
        for tld in GENERATOR_CONFIG['default_tld_to_add']:
            result.append(self._add_result(no_suffix + "." + tld, 'swapped_key_tlds'))

        return result

    def generate_miskeyed_addition_typos(self, domain):
        # add a surrounding key either side of each character
        result = list()
        for idx, char in enumerate(domain):
            for keyboard in self.keyboards:
                if char in keyboard:
                    for replacement_char in keyboard[char]:
                        result.append(self._add_result(domain[:idx + 1] + replacement_char + domain[idx + 1:],
                                                       'miskeyed_addition'))
                        result.append(self._add_result(domain[:idx] + replacement_char + domain[idx:],
                                                       'miskeyed_addition'))
        return result

    def generate_miskeyed_sequence_typos(self, domain):
        # repeated surrounding keys for any character sequences in the string
        result = list()

        idx = 0
        while idx < len(domain):
            char = domain[idx]
            # Loop through sequences of the same character, counting the sequence length
            sequence_len = 1
            while idx + 1 < len(domain) and domain[idx + 1] == char:
                sequence_len += 1
                idx += 1

            # Increment the index at this point to make the maths easier if we found a sequence
            idx += 1

            # Replace the whole sequence
            if sequence_len > 1:
                for keyboard in self.keyboards:
                    if char in keyboard:
                        for replacement_char in keyboard[char]:
                            result.append(
                                self._add_result(
                                    domain[:idx - sequence_len] + (replacement_char * sequence_len) + domain[idx:],
                                    'miskeyed_sequence'))

        return result

    def generate_transposed_character_typos(self, domain):
        result = list()
        for idx in range(0, len(domain) - 1):
            result.append(
                self._add_result(
                    domain[:idx] + domain[idx + 1:idx + 2] + domain[idx:idx + 1] + domain[idx + 2:],
                    'transposed_character'))
        return result

    @staticmethod
    def is_valid_rfc3491(domain):
        """
        Checks if the given domain would pass processing by nameprep unscathed.

        :param domain: The unicode string of the domain name.
        :return: True if the unicode is valid (i.e. only uses Unicode 3.2 code points)
        """
        valid_rfc3491 = True
        for char in domain:
            if stringprep.in_table_a1(char):
                valid_rfc3491 = False
                break

        return valid_rfc3491

    @staticmethod
    def is_ascii(domain):
        return str(codecs.encode(domain, "idna"), "ascii") == domain

    @staticmethod
    def is_in_charset(domain, icharsetamount):
        if icharsetamount == 100:
            return True
        elif icharsetamount == 50:
            return Generator.is_valid_rfc3491(domain)
        elif icharsetamount == 0:
            return Generator.is_ascii(domain)

    def generate(self, domain, bTypos=True, iTypoIntensity=100, bTLDS=True, bBitFlip=True,
                 bHomoglyphs=True, bDoppelganger=True, bOnlyAlexa=False, bNeverAlexa=False, icharsetamount=100):
        """
        generate the typos

        @param domain The hostname to generate typos for
        @param bTypos Flag to indicate that typos should be generated
        @param iTypoIntensity A percentage of how intense the typo generation should be.
        @param bTLDS Flag to indicate that the TLDs should be swapped
        @param bBitFlip Flag to indicate that the hostname should be bitflipped
        @param bHomoglyphs Flag to indicate that homoglyphs should be generated
        @param bDoppelganger Flag to indicate that domain doppleganers should be generated
        @param bOnlyAlexa Flag to indicate that only results which appear in the Alexa top 1m domains should be returned
        @param bNeverAlexa Flag to indicate that results which are in the Alexa top 1m domains should not be returned
        """

        # result list of typos
        typo_domains = []

        if bBitFlip:
            typo_domains += self.bitflipstring(domain)

        if bTypos:
            # Quick:
            typo_domains += self.generate_missing_character_typos(domain)
            typo_domains += self.generate_duplicate_character_typos(domain)
            typo_domains += self.generate_ings_and_plurals(domain)
            typo_domains += self.generate_replace_i_l_1_o_0(domain)
            typo_domains += self.generate_ings_and_plurals_then_replace_i_l_1_o_0(domain)

            # Balanced:
            if iTypoIntensity > 0:
                typo_domains += self.generate_miskeyed_typos(domain)
                typo_domains += self.generate_miskeyed_sequence_typos(domain)

            # Rigorous phase:
            if iTypoIntensity > 50:
                typo_domains += self.generate_transposed_character_typos(domain)
                typo_domains += self.generate_miskeyed_addition_typos(domain)
                lst_interim = list()
                for sDomain in typo_domains:
                    str_domain = sDomain.get('value').split(".", 1)[0]
                    lst_interim += self.generate_swap_key_tlds(str_domain)
                typo_domains += lst_interim

        if bTLDS:
            public_suffix = self.psl.get_public_suffix(domain)
            no_suffix = public_suffix[:public_suffix.find('.')] + '.'
            # Add each TLD
            for gtld in self.tlds:
                new_host = no_suffix + gtld
                typo_domains.append(self._add_result(new_host, 'swap_tlds'))

        if bHomoglyphs:
            typo_domains += self.generate_homoglyph_confusables_typos(domain)
            typo_domains += self.generate_additional_homoglyph_typos(domain)

        if bDoppelganger:
            typo_domains += self.generate_subdomain_doppelgangers(domain)
            typo_domains += self.generate_extra_dot_doppelgangers(domain)

        # unique_typos = set(typo_domains)
        # unique_typos = set(list({v['value']: v for v in typo_domains}.values()))

        # make values unique
        unique_typos = list()
        tmp = list()
        for typo_domain in typo_domains:
            if typo_domain.get('value') in tmp:
                continue
            unique_typos.append(typo_domain)
            tmp.append(typo_domain.get('value'))

        # Remove any invalid typos
        for typo in copy.copy(unique_typos):
            if not self.is_domain_valid(typo.get('value')):
                unique_typos.remove(typo)
            elif bOnlyAlexa and typo.get('value') not in self.alexa_top:
                unique_typos.remove(typo)
            elif bNeverAlexa and typo.get('value') in self.alexa_top:
                unique_typos.remove(typo)

        # Add the original domain for comparison purposes and to ensure we have at least one result
        # try:
        #     unique_typos.add(domain)
        # except KeyError:
        #     pass

        # unicode_typos = sorted([codecs.decode(asciiHost.get('value').encode(), "idna") for asciiHost in unique_typos])

        # make values unicode
        unicode_typos = list()
        for unique_typo in unique_typos:
            unicode_typos.append({'value': codecs.decode(unique_typo.get('value').encode(), "idna"),
                                  'fuzzer': unique_typo.get('fuzzer')})

        # sort list by values
        unicode_typos = sorted(unicode_typos, key=lambda k: k['value'])

        for typo in copy.copy(unicode_typos):
            if not Generator.is_in_charset(typo.get('value'), icharsetamount):
                unicode_typos.remove(typo)

        self.typo_domains = unicode_typos
        return unicode_typos


if __name__ == '__main__':
    d = 'google.com'
    t = Generator()
    r = t.generate(d)
    print(r)
