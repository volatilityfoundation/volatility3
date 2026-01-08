# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import binascii
import hashlib
import logging
from struct import pack, unpack
from typing import List, Optional, Tuple

from Crypto.Cipher import AES, ARC4, DES

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry as registry_layer
from volatility3.framework.symbols.windows.extensions import registry
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class Hashdump(interfaces.plugins.PluginInterface):
    """Dumps user hashes from memory"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
        ]

    odd_parity = [
        1,
        1,
        2,
        2,
        4,
        4,
        7,
        7,
        8,
        8,
        11,
        11,
        13,
        13,
        14,
        14,
        16,
        16,
        19,
        19,
        21,
        21,
        22,
        22,
        25,
        25,
        26,
        26,
        28,
        28,
        31,
        31,
        32,
        32,
        35,
        35,
        37,
        37,
        38,
        38,
        41,
        41,
        42,
        42,
        44,
        44,
        47,
        47,
        49,
        49,
        50,
        50,
        52,
        52,
        55,
        55,
        56,
        56,
        59,
        59,
        61,
        61,
        62,
        62,
        64,
        64,
        67,
        67,
        69,
        69,
        70,
        70,
        73,
        73,
        74,
        74,
        76,
        76,
        79,
        79,
        81,
        81,
        82,
        82,
        84,
        84,
        87,
        87,
        88,
        88,
        91,
        91,
        93,
        93,
        94,
        94,
        97,
        97,
        98,
        98,
        100,
        100,
        103,
        103,
        104,
        104,
        107,
        107,
        109,
        109,
        110,
        110,
        112,
        112,
        115,
        115,
        117,
        117,
        118,
        118,
        121,
        121,
        122,
        122,
        124,
        124,
        127,
        127,
        128,
        128,
        131,
        131,
        133,
        133,
        134,
        134,
        137,
        137,
        138,
        138,
        140,
        140,
        143,
        143,
        145,
        145,
        146,
        146,
        148,
        148,
        151,
        151,
        152,
        152,
        155,
        155,
        157,
        157,
        158,
        158,
        161,
        161,
        162,
        162,
        164,
        164,
        167,
        167,
        168,
        168,
        171,
        171,
        173,
        173,
        174,
        174,
        176,
        176,
        179,
        179,
        181,
        181,
        182,
        182,
        185,
        185,
        186,
        186,
        188,
        188,
        191,
        191,
        193,
        193,
        194,
        194,
        196,
        196,
        199,
        199,
        200,
        200,
        203,
        203,
        205,
        205,
        206,
        206,
        208,
        208,
        211,
        211,
        213,
        213,
        214,
        214,
        217,
        217,
        218,
        218,
        220,
        220,
        223,
        223,
        224,
        224,
        227,
        227,
        229,
        229,
        230,
        230,
        233,
        233,
        234,
        234,
        236,
        236,
        239,
        239,
        241,
        241,
        242,
        242,
        244,
        244,
        247,
        247,
        248,
        248,
        251,
        251,
        253,
        253,
        254,
        254,
    ]

    # Permutation matrix for boot key
    bootkey_perm_table = [
        0x8,
        0x5,
        0x4,
        0x2,
        0xB,
        0x9,
        0xD,
        0x3,
        0x0,
        0x6,
        0x1,
        0xC,
        0xE,
        0xA,
        0xF,
        0x7,
    ]

    # Constants for SAM decrypt algorithm
    aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    anum = b"0123456789012345678901234567890123456789\0"
    antpassword = b"NTPASSWORD\0"
    almpassword = b"LMPASSWORD\0"
    lmkey = b"KGS!@#$%"

    empty_lm = b"\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
    empty_nt = b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"

    @classmethod
    def get_hive_key(
        cls, hive: registry_layer.RegistryHive, key: str
    ) -> Optional["registry.CM_KEY_NODE"]:
        result = None
        try:
            if hive:
                result = hive.get_key(key)
        except (KeyError, registry_layer.RegistryException):
            vollog.info(
                f"Unable to load the required registry key {hive.get_name()}\\{key} from this memory image"
            )
        return result

    @classmethod
    def get_user_keys(
        cls, samhive: registry_layer.RegistryHive
    ) -> List[interfaces.objects.ObjectInterface]:
        user_key_path = "SAM\\Domains\\Account\\Users"

        user_key = cls.get_hive_key(samhive, user_key_path)

        if not user_key:
            return []
        return [k for k in user_key.get_subkeys() if k.get_name() != "Names"]

    @classmethod
    def get_bootkey(cls, syshive: registry_layer.RegistryHive) -> Optional[bytes]:
        """
        Returns the scrambled bootkey necessary to decrypt hashes
        """
        cs = 1
        lsa_base = f"ControlSet{cs:03}" + "\\Control\\Lsa"
        lsa_keys = ["JD", "Skew1", "GBG", "Data"]

        lsa = cls.get_hive_key(syshive, lsa_base)
        if not lsa:
            return None

        bootkey = ""

        for lk in lsa_keys:
            try:
                key = cls.get_hive_key(syshive, lsa_base + "\\" + lk)
                class_data = None
                if key:
                    try:
                        class_data = syshive.read(key.Class + 4, key.ClassLength)
                    except exceptions.InvalidAddressException:
                        return None

                if class_data is None:
                    return None
                bootkey += class_data.decode("utf-16-le")
            except (
                exceptions.InvalidAddressException,
                registry_layer.RegistryException,
            ) as excp:
                vollog.log(
                    constants.LOGLEVEL_VVV, f"Unable to read Lsa key {lk}: {excp}"
                )
                return None

        bootkey_str = binascii.unhexlify(bootkey)
        bootkey_scrambled = bytes(
            [bootkey_str[cls.bootkey_perm_table[i]] for i in range(len(bootkey_str))]
        )
        return bootkey_scrambled

    @classmethod
    def get_hbootkey(
        cls, samhive: registry_layer.RegistryHive, bootkey: bytes
    ) -> Optional[bytes]:
        sam_account_path = "SAM\\Domains\\Account"

        if not bootkey:
            return None

        sam_account_key = cls.get_hive_key(samhive, sam_account_path)
        if not sam_account_key:
            return None

        sam_data = None
        for v in sam_account_key.get_values():
            if v.get_name() == "F":
                try:
                    sam_data = samhive.read(v.Data + 4, v.DataLength)
                except exceptions.InvalidAddressException:
                    return None

        if not sam_data:
            return None

        revision = sam_data[0x00]
        if revision == 2:
            md5 = hashlib.md5()

            md5.update(sam_data[0x70:0x80] + cls.aqwerty + bootkey + cls.anum)
            rc4_key = md5.digest()

            rc4 = ARC4.new(rc4_key)
            hbootkey = rc4.encrypt(
                sam_data[0x80:0xA0]
            )  # lgtm [py/weak-cryptographic-algorithm]
            return hbootkey
        elif revision == 3:
            # AES encrypted
            iv = sam_data[0x78:0x88]
            encryptedHBootKey = sam_data[0x88:0xA8]
            cipher = AES.new(bootkey, AES.MODE_CBC, iv)
            hbootkey = cipher.decrypt(encryptedHBootKey)
            return hbootkey[:16]
        return None

    @classmethod
    def decrypt_single_salted_hash(
        cls, rid, hbootkey: bytes, enc_hash: bytes, _lmntstr, salt: bytes
    ) -> Optional[bytes]:
        (des_k1, des_k2) = cls.sid_to_key(rid)
        des1 = DES.new(des_k1, DES.MODE_ECB)
        des2 = DES.new(des_k2, DES.MODE_ECB)
        cipher = AES.new(hbootkey[:16], AES.MODE_CBC, salt)
        obfkey = cipher.decrypt(enc_hash)
        return des1.decrypt(obfkey[:8]) + des2.decrypt(
            obfkey[8:16]
        )  # lgtm [py/weak-cryptographic-algorithm]

    @classmethod
    def get_user_hashes(
        cls,
        user: registry.CM_KEY_NODE,
        samhive: registry_layer.RegistryHive,
        hbootkey: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        ## Will sometimes find extra user with rid = NAMES, returns empty strings right now
        try:
            rid = int(str(user.get_name()), 16)
        except ValueError:
            return None
        sam_data = None
        for v in user.get_values():
            if v.get_name() == "V":
                try:
                    sam_data = samhive.read(v.Data + 4, v.DataLength)
                except (
                    exceptions.InvalidAddressException,
                    registry_layer.RegistryException,
                ):
                    return None

        if not sam_data:
            return None

        lm_offset = unpack("<L", sam_data[0x9C:0xA0])[0] + 0xCC
        lm_len = unpack("<L", sam_data[0xA0:0xA4])[0]
        nt_offset = unpack("<L", sam_data[0xA8:0xAC])[0] + 0xCC
        nt_len = unpack("<L", sam_data[0xAC:0xB0])[0]

        lm_revision = sam_data[lm_offset + 2 : lm_offset + 3]
        lmhash = None
        if lm_revision == b"\x01":
            if lm_len == 20:
                enc_lm_hash = sam_data[lm_offset + 0x04 : lm_offset + 0x14]
                lmhash = cls.decrypt_single_hash(
                    rid, hbootkey, enc_lm_hash, cls.almpassword
                )
        elif lm_revision == b"\x02":
            if lm_len == 56:
                lm_salt = sam_data[lm_offset + 4 : lm_offset + 20]
                enc_lm_hash = sam_data[lm_offset + 20 : lm_offset + 52]
                lmhash = cls.decrypt_single_salted_hash(
                    rid, hbootkey, enc_lm_hash, cls.almpassword, lm_salt
                )

        # NT hash decryption
        nthash = None
        nt_revision = sam_data[nt_offset + 2 : nt_offset + 3]
        if nt_revision == b"\x01":
            if nt_len == 20:
                enc_nt_hash = sam_data[nt_offset + 4 : nt_offset + 20]
                nthash = cls.decrypt_single_hash(
                    rid, hbootkey, enc_nt_hash, cls.antpassword
                )
        elif nt_revision == b"\x02":
            if nt_len == 56:
                nt_salt = sam_data[nt_offset + 8 : nt_offset + 24]
                enc_nt_hash = sam_data[nt_offset + 24 : nt_offset + 56]
                nthash = cls.decrypt_single_salted_hash(
                    rid, hbootkey, enc_nt_hash, cls.antpassword, nt_salt
                )
        return lmhash, nthash

    @classmethod
    def sid_to_key(cls, sid: int) -> Tuple[bytes, bytes]:
        """Takes rid of a user and converts it to a key to be used by the DES cipher"""
        bytestr1 = [
            sid & 0xFF,
            (sid >> 8) & 0xFF,
            (sid >> 16) & 0xFF,
            (sid >> 24) & 0xFF,
        ]
        bytestr1 += bytestr1[0:3]
        bytestr2 = [bytestr1[3]] + bytestr1[0:3]
        bytestr2 += bytestr2[0:3]
        return cls.sidbytes_to_key(bytes(bytestr1)), cls.sidbytes_to_key(
            bytes(bytestr2)
        )

    @classmethod
    def sidbytes_to_key(cls, s: bytes) -> bytes:
        """Builds final DES key from the strings generated in sid_to_key"""
        key = [
            s[0] >> 1,
            ((s[0] & 0x01) << 6) | (s[1] >> 2),
            ((s[1] & 0x03) << 5) | (s[2] >> 3),
            ((s[2] & 0x07) << 4) | (s[3] >> 4),
            ((s[3] & 0x0F) << 3) | (s[4] >> 5),
            ((s[4] & 0x1F) << 2) | (s[5] >> 6),
            ((s[5] & 0x3F) << 1) | (s[6] >> 7),
            s[6] & 0x7F,
        ]
        for i in range(8):
            key[i] = key[i] << 1
            key[i] = cls.odd_parity[key[i]]
        return bytes(key)

    @classmethod
    def decrypt_single_hash(
        cls, rid: int, hbootkey: bytes, enc_hash: bytes, lmntstr: bytes
    ):
        (des_k1, des_k2) = cls.sid_to_key(rid)
        des1 = DES.new(des_k1, DES.MODE_ECB)
        des2 = DES.new(des_k2, DES.MODE_ECB)
        md5 = hashlib.md5()

        md5.update(hbootkey[:0x10] + pack("<L", rid) + lmntstr)
        rc4_key = md5.digest()
        rc4 = ARC4.new(rc4_key)
        obfkey = rc4.encrypt(enc_hash)  # lgtm [py/weak-cryptographic-algorithm]

        return des1.decrypt(obfkey[:8]) + des2.decrypt(
            obfkey[8:]
        )  # lgtm [py/weak-cryptographic-algorithm]

    @classmethod
    def get_user_name(
        cls, user: registry.CM_KEY_NODE, samhive: registry_layer.RegistryHive
    ) -> Optional[bytes]:
        value = None
        for v in user.get_values():
            if v.get_name() == "V":
                try:
                    value = samhive.read(v.Data + 4, v.DataLength)
                except exceptions.InvalidAddressException:
                    return None

        if not value:
            return None

        name_offset = unpack("<L", value[0x0C:0x10])[0] + 0xCC
        name_length = unpack("<L", value[0x10:0x14])[0]
        if name_length > len(value):
            return None

        username = value[name_offset : name_offset + name_length]
        return username

    # replaces the dump_hashes method in vol2
    def _generator(
        self, syshive: registry_layer.RegistryHive, samhive: registry_layer.RegistryHive
    ):
        if syshive is None:
            vollog.debug("SYSTEM address is None: No system hive found")
        if samhive is None:
            vollog.debug("SAM address is None: No SAM hive found")
        bootkey = self.get_bootkey(syshive)
        hbootkey = self.get_hbootkey(samhive, bootkey)
        if hbootkey:
            for user in self.get_user_keys(samhive):
                ret = self.get_user_hashes(user, samhive, hbootkey)
                if ret:
                    lmhash, nthash = ret

                    ## temporary fix to prevent UnicodeDecodeError backtraces
                    ## however this can cause truncated user names as a result
                    name = self.get_user_name(user, samhive)
                    if name is None:
                        name = renderers.NotAvailableValue()
                    else:
                        name = str(name, "utf-16-le", errors="ignore")

                    lmout = str(binascii.hexlify(lmhash or self.empty_lm), "latin-1")
                    ntout = str(binascii.hexlify(nthash or self.empty_nt), "latin-1")
                    rid = int(str(user.get_name()), 16)
                    yield (0, (name, rid, lmout, ntout))
        else:
            vollog.warning("Hbootkey is not valid")

    def run(self):
        offset = self.config.get("offset", None)
        syshive = None
        samhive = None
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            hive_offsets=None if offset is None else [offset],
        ):
            if hive.get_name().split("\\")[-1].upper() == "SYSTEM":
                syshive = hive
            if hive.get_name().split("\\")[-1].upper() == "SAM":
                samhive = hive

        return renderers.TreeGrid(
            [("User", str), ("rid", int), ("lmhash", str), ("nthash", str)],
            self._generator(syshive, samhive),
        )
