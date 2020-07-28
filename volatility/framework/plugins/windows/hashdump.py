# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.plugins.windows.registry import hivelist
from struct import unpack, pack
from Crypto.Hash import MD5, MD4
from Crypto.Cipher import ARC4, DES, AES
import hashlib
import binascii

vollog = logging.getLogger(__name__)

class Hashdump(interfaces.plugins.PluginInterface):
    """Dumps user hashes from memory"""
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols",
                                                description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0))
            ]

    odd_parity = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
    ]

    # Permutation matrix for boot key
    p = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
        0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]

    # Constants for SAM decrypt algorithm
    aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    anum = b"0123456789012345678901234567890123456789\0"
    antpassword = b"NTPASSWORD\0"
    almpassword = b"LMPASSWORD\0"
    lmkey = b"KGS!@#$%"

    empty_lm = "aad3b435b51404eeaad3b435b51404ee"
    empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"

    @classmethod
    def get_user_keys(cls, samhive):
        user_key_path= "SAM\\Domains\\Account\\Users"
        root = samhive.root_cell_offset
        if not root:
            return []

        user_key = samhive.get_key(user_key_path)
        if not user_key:
            return []
        return [k for k in user_key.get_subkeys() if k.Name != "Names"]
    
    @classmethod
    def get_bootkey(cls, syshive):
        cs =1
        lsa_base = "ControlSet{0:03}".format(cs)+ "\\Control\\Lsa"
        lsa_keys = ["JD", "Skew1", "GBG", "Data"]
        root = syshive.root_cell_offset 
        if not root:
            return None

        lsa = syshive.get_key(lsa_base)


        if not lsa:
            return None

        bootkey = ""

        for lk in lsa_keys:
            key = syshive.get_key(lsa_base+'\\'+lk)

            class_data = syshive.read(key.Class+4, key.ClassLength)

            if class_data == None:
                return ""
            bootkey += class_data.decode('utf-16-le')
            


        bootkey_str=''.join([chr(int(''.join(c), 16)) for c in zip(bootkey[0::2],bootkey[1::2])])
        bootkey_scrambled = ""

        for i in range(len(bootkey_str)):
            bootkey_scrambled += bootkey_str[cls.p[i]]
        return bootkey_scrambled

    @classmethod
    def get_hbootkey(cls, samhive, bootkey):
        sam_account_path = "SAM\\Domains\\Account"

        if not bootkey:
            return None

        root = samhive.root_cell_offset
        if not root:
            return None

        sam_account_key=samhive.get_key(sam_account_path)
        if not sam_account_key:
            return None
        

        sam_data = None
        for v in sam_account_key.get_values():
            if v.get_name() == 'F':
                sam_data = samhive.read(v.Data+4, v.DataLength)
        if not sam_data:
            return None

        revision = sam_data[0x00]
        if revision == 2:
            md5 = hashlib.md5()
        
            md5.update(sam_data[0x70:0x80] + cls.aqwerty + bootkey.encode('latin1') + cls.anum)
            rc4_key = md5.digest()

            rc4 = ARC4.new(rc4_key)
            hbootkey = rc4.encrypt(sam_data[0x80:0xA0])
            return hbootkey
        elif revision == 3:
            # AES encrypted 
            iv = sam_data[0x78:0x88]
            encryptedHBootKey = sam_data[0x88:0xA8]
            cipher = AES.new(bootkey.encode('latin1'), AES.MODE_CBC, iv)
            hbootkey = cipher.decrypt(encryptedHBootKey)
            return hbootkey[:16]
        else:
            return None

        return hbootkey
    

    @classmethod
    def decrypt_single_salted_hash(cls, rid, hbootkey, enc_hash, lmntstr, salt):
        if enc_hash == "":
            return ""
        (des_k1,des_k2) = cls.sid_to_key(rid)
        des1 = DES.new(des_k1.encode('latin1'), DES.MODE_ECB)
        des2 = DES.new(des_k2.encode('latin1'), DES.MODE_ECB)
        cipher = AES.new(hbootkey[:16], AES.MODE_CBC, salt)
        obfkey = cipher.decrypt(enc_hash)
        return des1.decrypt(obfkey[:8]) + des2.decrypt(obfkey[8:16])

    @classmethod  
    def get_user_hashes(cls, user, samhive, hbootkey):
        ## Will sometimes find extra user with rid = NAMES, returns empty strings right now
        try:
            rid = int(str(user.get_name()), 16)
        except ValueError:
            return None
        sam_data = None
        for v in user.get_values():
            if v.get_name() == 'V':
                sam_data = samhive.read(v.Data+4, v.DataLength)
        if not sam_data:
            return None
        
        lm_offset = unpack("<L", sam_data[0x9c:0xa0])[0] + 0xCC
        lm_len = unpack("<L", sam_data[0xa0:0xa4])[0]
        nt_offset = unpack("<L", sam_data[0xa8:0xac])[0] + 0xCC
        nt_len = unpack("<L", sam_data[0xac:0xb0])[0]


        lm_revision = sam_data[lm_offset + 2:lm_offset + 3]
        if lm_revision == b'\x01':
            lm_exists = True if lm_len == 20 else False
            enc_lm_hash = sam_data[lm_offset + 0x04:lm_offset + 0x14] if lm_exists else ""
            lmhash = cls.decrypt_single_hash(rid, hbootkey, enc_lm_hash, cls.almpassword)
        elif lm_revision == b'\x02':
            lm_exists = True if lm_len == 56 else False
            lm_salt = sam_data[hash_offset+4:hash_offset+20] if lm_exists else ""
            enc_lm_hash = sam_data[hash_offset+20:hash_offset+52] if lm_exists else ""
            lmhash = cls.decrypt_single_salted_hash(rid, hbootkey, enc_lm_hash, cls.almpassword, lm_salt)

        # NT hash decryption
        nt_len = unpack("<L", sam_data[0xac:0xb0])[0]

        nt_revision = sam_data[nt_offset + 2:nt_offset + 3]
        if nt_revision == b'\x01':
            nt_exists = True if nt_len == 20 else False
            enc_nt_hash = sam_data[nt_offset+4:nt_offset+20] if nt_exists else ""
            nthash = cls.decrypt_single_hash(rid, hbootkey, enc_nt_hash, cls.antpassword)
        elif nt_revision == b'\x02':
            nt_exists = True if nt_len == 56 else False
            nt_salt = sam_data[nt_offset+8:nt_offset+24] if nt_exists else ""
            enc_nt_hash = sam_data[nt_offset+24:nt_offset+56] if nt_exists else ""
            nthash = cls.decrypt_single_salted_hash(rid, hbootkey, enc_nt_hash, cls.antpassword, nt_salt)
        return lmhash, nthash
    
    #Takes rid of a user and converts it to a key to be used by the DES cipher
    @classmethod
    def sid_to_key(cls, sid):

        str1 = ""
        str1 += chr(sid & 0xFF)
        str1 += chr((sid >> 8) & 0xFF)
        str1 += chr((sid >> 16) & 0xFF)
        str1 += chr((sid >> 24) & 0xFF)
        str1 += str1[0]
        str1 += str1[1]
        str1 += str1[2]
        str2 = str1[3] + str1[0] + str1[1] + str1[2]
        str2 += str2[0] + str2[1] + str2[2]
        return cls.str_to_key(str1), cls.str_to_key(str2)

    #build final DES key from the strings generated in sid_to_key
    @classmethod
    def str_to_key(cls, s):
        key = []
        key.append(ord(s[0]) >> 1)
        key.append(((ord(s[0]) & 0x01) << 6) | (ord(s[1]) >> 2))
        key.append(((ord(s[1]) & 0x03) << 5) | (ord(s[2]) >> 3))
        key.append(((ord(s[2]) & 0x07) << 4) | (ord(s[3]) >> 4))
        key.append(((ord(s[3]) & 0x0F) << 3) | (ord(s[4]) >> 5))
        key.append(((ord(s[4]) & 0x1F) << 2) | (ord(s[5]) >> 6))
        key.append(((ord(s[5]) & 0x3F) << 1) | (ord(s[6]) >> 7))
        key.append(ord(s[6]) & 0x7F)
        for i in range(8):
            key[i] = (key[i] << 1)
            key[i] = cls.odd_parity[key[i]]
        return "".join(chr(k) for k in key)

    @classmethod
    def decrypt_single_hash(cls, rid, hbootkey, enc_hash, lmntstr):
        (des_k1, des_k2) = cls.sid_to_key(rid)
        des1 = DES.new(des_k1.encode('latin1'), DES.MODE_ECB)
        des2 = DES.new(des_k2.encode('latin1'), DES.MODE_ECB)
        md5 = MD5.new()

        md5.update(hbootkey[:0x10] + pack("<L", rid) + lmntstr)
        rc4_key = md5.digest()
        rc4 = ARC4.new(rc4_key)
        obfkey = rc4.encrypt(enc_hash)

        hash = des1.decrypt(obfkey[:8]) + des2.decrypt(obfkey[8:])
        return hash

    @classmethod
    def get_user_name(cls, user, samhive):
        V = None
        for v in user.get_values():
            if v.get_name() == 'V':
                V = samhive.read(v.Data+4, v.DataLength)
        if not V:
            return None

        name_offset = unpack("<L", V[0x0c:0x10])[0] + 0xCC
        name_length = unpack("<L", V[0x10:0x14])[0]
        if name_length > len(V):
            return None

        username = V[name_offset:name_offset + name_length].decode('utf-16-le')
        return username

    #replaces the dump_hashes method in vol2
    def _generator(self, syshive, samhive):
        if syshive == None:
            vollog.debug("SYSTEM address is None: Did you use the correct profile?")
            yield (0, (renderers.NotAvailableValue(), renderers.NotAvailableValue(), renderers.NotAvailableValue(),
                               renderers.NotAvailableValue()))
        if samhive == None:
            vollog.debug("SAM address is None: Did you use the correct profile?")
            yield (0, (renderers.NotAvailableValue(), renderers.NotAvailableValue(), renderers.NotAvailableValue(),
                               renderers.NotAvailableValue()))
        bootkey = self.get_bootkey(syshive)
        hbootkey = self.get_hbootkey(samhive, bootkey)
        if hbootkey:
            for user in self.get_user_keys(samhive):
                ret = self.get_user_hashes(user, samhive, hbootkey)
                if not ret:
                    yield (0, (renderers.UnreadableValue(), renderers.UnreadableValue(), renderers.NotAvailableValue(),
                               renderers.NotAvailableValue()))
                else:
                    lmhash, nthash = ret
                    if not lmhash:
                        lmhash = self.empty_lm
                    if not nthash:
                        nthash = self.empty_nt
                        ## temporary fix to prevent UnicodeDecodeError backtraces 
                        ## however this can cause truncated user names as a result
                    name = self.get_user_name(user, samhive)
                    if name is not None:
                        name = name.encode('ascii', 'ignore')
                    else:
                        name = renderers.NotAvailableValue()
                        

                    if lmhash == self.empty_lm:
                        lmout=lmhash
                    else:
                        lmout = binascii.hexlify(lmhash).decode('latin1')
                        
                    if nthash == self.empty_nt:
                        ntout=nthash
                    else:
                        ntout = binascii.hexlify(nthash).decode('latin1')
                    yield (0,   (name.decode('latin1'), 
                                str(int(str(user.get_name()), 16)),
                                lmout,
                                ntout))
        else:
            raise Exception("Hbootkey is not valid")

    def run(self):
        offset = self.config.get('offset', None)
        syshive=None
        samhive=None
        for hive in hivelist.HiveList.list_hives(self.context,
                                                 self.config_path,
                                                 self.config['primary'],
                                                 self.config['nt_symbols'],
                                                 hive_offsets = None if offset is None else [offset]):

            if hive.get_name().split('\\')[-1].upper() == 'SYSTEM':
                syshive=hive
            if hive.get_name().split('\\')[-1].upper() == 'SAM':
                samhive=hive  


        return renderers.TreeGrid([("User", str), ("rid", str), ("lmhash", str), ("nthash", str)], 
                                    self._generator(syshive, samhive))

