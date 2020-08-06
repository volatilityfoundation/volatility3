
from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.layers import intel
from volatility.plugins.windows.registry import hivelist
from volatility.plugins.windows import hashdump, lsadump, poolscanner
from Crypto.Hash import HMAC
from Crypto.Cipher import ARC4, AES
from struct import unpack


class Cachedump(interfaces.plugins.PluginInterface):
    """Dumps lsa secrets from memory"""
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols",
                                                description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0))
            ]
    @classmethod
    def get_nlkm(cls, sechive, lsakey, is_vista_or_later):
        return lsadump.Lsadump.get_secret_by_name(sechive, 'NL$KM', lsakey, is_vista_or_later)
    
    @classmethod
    def decrypt_hash(cls, edata, nlkm, ch, xp):
        if xp:
            hmac_md5 = HMAC.new(nlkm.encode('latin1'), ch)
            rc4key = hmac_md5.digest()
            rc4 = ARC4.new(rc4key)
            data = rc4.encrypt(edata)
        else:
            # based on  Based on code from http://lab.mediaservice.net/code/cachedump.rb
            aes = AES.new(nlkm.encode('latin1')[16:32], AES.MODE_CBC, ch)
            data = ""
            for i in range(0, len(edata), 16):
                buf = edata[i : i + 16]
                if len(buf) < 16:
                    buf += (16 - len(buf)) * "\00"
                data += aes.decrypt(buf)
        return data
    
    @classmethod
    def parse_cache_entry(cls, cache_data):
        (uname_len, domain_len) = unpack("<HH", cache_data[:4])
        if len(cache_data[60:62]) == 0:
            return (uname_len, domain_len, 0, '', '')
        (domain_name_len,) = unpack("<H", cache_data[60:62])
        ch = cache_data[64:80]
        enc_data = cache_data[96:]
        return (uname_len, domain_len, domain_name_len, enc_data, ch)

    @classmethod
    def parse_decrypted_cache(cls, dec_data, uname_len,
            domain_len, domain_name_len):
        uname_off = 72
        pad = 2 * ((uname_len / 2) % 2)
        domain_off = int(uname_off + uname_len + pad)
        pad = 2 * ((domain_len / 2) % 2)
        domain_name_off = int(domain_off + domain_len + pad)
        hashh = dec_data[:0x10]
        username = dec_data[uname_off:uname_off + uname_len]
        username = username.decode('utf-16-le', 'replace')
        domain = dec_data[domain_off:domain_off + domain_len]
        domain = domain.decode('utf-16-le', 'replace')
        domain_name = dec_data[domain_name_off:domain_name_off + domain_name_len]
        domain_name = domain_name.decode('utf-16-le', 'replace')

        return (username, domain, domain_name, hashh)

    def _generator(self, syshive, sechive):
        bootkey = hashdump.Hashdump.get_bootkey(syshive)
        if not bootkey:
            return []
        
        is_vista_or_later = poolscanner.os_distinguisher(version_check = lambda x: x >= (6, 0),
                                                     fallback_checks = [("KdCopyDataBlock", None, True)])
        vista_or_later = is_vista_or_later(context = self.context, symbol_table = self.config['nt_symbols'])

        lsakey = lsadump.Lsadump.get_lsa_key(sechive, bootkey, vista_or_later)
        if not lsakey:
            return []

        nlkm = self.get_nlkm(sechive, lsakey, vista_or_later)
        if not nlkm:
            return []

        cache = sechive.get_key("Cache")
        if not cache:
            return []
        

        for v in cache.get_values():
            if v.Name == "NL$Control":
                continue

            data = sechive.read(v.Data+4, v.DataLength)
            if data == None:
                continue
            (uname_len, domain_len, domain_name_len,
                enc_data, ch) = self.parse_cache_entry(data)
            # Skip if nothing in this cache entry
            if uname_len == 0 or len(ch) == 0:
                continue
            dec_data = self.decrypt_hash(enc_data, nlkm, ch, not vista_or_later)

            (username, domain, domain_name,
                hashh) = self.parse_decrypted_cache(dec_data, uname_len,
                        domain_len, domain_name_len)
            yield (0,(username, domain, domain_name, hashh))

    def run(self):
        offset = self.config.get('offset', None)


        for hive in hivelist.HiveList.list_hives(self.context,
                                            self.config_path,
                                            self.config['primary'],
                                            self.config['nt_symbols'],
                                            hive_offsets = None if offset is None else [offset]):

            if hive.get_name().split('\\')[-1].upper() == 'SYSTEM':
                syshive=hive
            if hive.get_name().split('\\')[-1].upper() == 'SECURITY':
                sechive=hive  

        return renderers.TreeGrid([("Username", str), ("Domain", str), ("Domain name", str), ('Hashh', bytes)], 
                                    self._generator(syshive, sechive))