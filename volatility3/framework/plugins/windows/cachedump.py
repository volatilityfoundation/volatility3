# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from struct import unpack

from Crypto.Cipher import ARC4, AES
from Crypto.Hash import HMAC

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import hashdump, lsadump
from volatility3.plugins.windows.registry import hivelist


class Cachedump(interfaces.plugins.PluginInterface):
    """Dumps lsa secrets from memory"""

    _required_framework_version = (1, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'lsadump', plugin = lsadump.Lsadump, version = (1, 0, 0))
        ]

    def get_nlkm(self, sechive, lsakey, is_vista_or_later):
        return lsadump.Lsadump.get_secret_by_name(sechive, 'NL$KM', lsakey, is_vista_or_later)

    def decrypt_hash(self, edata, nlkm, ch, xp):
        if xp:
            hmac_md5 = HMAC.new(nlkm, ch)
            rc4key = hmac_md5.digest()
            rc4 = ARC4.new(rc4key)
            data = rc4.encrypt(edata)
        else:
            # based on  Based on code from http://lab.mediaservice.net/code/cachedump.rb
            aes = AES.new(nlkm[16:32], AES.MODE_CBC, ch)
            data = ""
            for i in range(0, len(edata), 16):
                buf = edata[i:i + 16]
                if len(buf) < 16:
                    buf += (16 - len(buf)) * "\00"
                data += aes.decrypt(buf)
        return data

    def parse_cache_entry(self, cache_data):
        (uname_len, domain_len) = unpack("<HH", cache_data[:4])
        if len(cache_data[60:62]) == 0:
            return (uname_len, domain_len, 0, '', '')
        (domain_name_len, ) = unpack("<H", cache_data[60:62])
        ch = cache_data[64:80]
        enc_data = cache_data[96:]
        return (uname_len, domain_len, domain_name_len, enc_data, ch)

    def parse_decrypted_cache(self, dec_data, uname_len, domain_len, domain_name_len):
        """Get the data from the cache and separate it into the username, domain name, and hash data"""
        uname_offset = 72
        pad = 2 * ((uname_len / 2) % 2)
        domain_offset = int(uname_offset + uname_len + pad)
        pad = 2 * ((domain_len / 2) % 2)
        domain_name_offset = int(domain_offset + domain_len + pad)
        hashh = dec_data[:0x10]
        username = dec_data[uname_offset:uname_offset + uname_len]
        username = username.decode('utf-16-le', 'replace')
        domain = dec_data[domain_offset:domain_offset + domain_len]
        domain = domain.decode('utf-16-le', 'replace')
        domain_name = dec_data[domain_name_offset:domain_name_offset + domain_name_len]
        domain_name = domain_name.decode('utf-16-le', 'replace')

        return (username, domain, domain_name, hashh)

    def _generator(self, syshive, sechive):
        bootkey = hashdump.Hashdump.get_bootkey(syshive)
        if not bootkey:
            raise ValueError('Unable to find bootkey')

        vista_or_later = versions.is_vista_or_later(context = self.context, symbol_table = self.config['nt_symbols'])

        lsakey = lsadump.Lsadump.get_lsa_key(sechive, bootkey, vista_or_later)
        if not lsakey:
            raise ValueError('Unable to find lsa key')

        nlkm = self.get_nlkm(sechive, lsakey, vista_or_later)
        if not nlkm:
            raise ValueError('Unable to find nlkma key')

        cache = sechive.get_key("Cache")
        if not cache:
            raise ValueError('Unable to find cache key')

        for cache_item in cache.get_values():
            if cache_item.Name == "NL$Control":
                continue

            data = sechive.read(cache_item.Data + 4, cache_item.DataLength)
            if data is None:
                continue
            (uname_len, domain_len, domain_name_len, enc_data, ch) = self.parse_cache_entry(data)
            # Skip if nothing in this cache entry
            if uname_len == 0 or len(ch) == 0:
                continue
            dec_data = self.decrypt_hash(enc_data, nlkm, ch, not vista_or_later)

            (username, domain, domain_name, hashh) = self.parse_decrypted_cache(dec_data, uname_len, domain_len,
                                                                                domain_name_len)
            yield (0, (username, domain, domain_name, hashh))

    def run(self):
        offset = self.config.get('offset', None)

        for hive in hivelist.HiveList.list_hives(self.context,
                                                 self.config_path,
                                                 self.config['primary'],
                                                 self.config['nt_symbols'],
                                                 hive_offsets = None if offset is None else [offset]):

            if hive.get_name().split('\\')[-1].upper() == 'SYSTEM':
                syshive = hive
            if hive.get_name().split('\\')[-1].upper() == 'SECURITY':
                sechive = hive

        return renderers.TreeGrid([("Username", str), ("Domain", str), ("Domain name", str), ('Hashh', bytes)],
                                  self._generator(syshive, sechive))
