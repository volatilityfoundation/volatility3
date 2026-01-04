# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from struct import unpack
from typing import Optional
import hashlib

from Crypto.Cipher import ARC4, DES, AES

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements

from volatility3.framework.layers import registry as registry_layer
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows.registry import hashdump, hivelist
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Lsadump(interfaces.plugins.PluginInterface):
    """Dumps lsa secrets from memory"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="hashdump", component=hashdump.Hashdump, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def decrypt_aes(cls, secret: bytes, key: bytes) -> bytes:
        """
        Based on code from http://lab.mediaservice.net/code/cachedump.rb
        """
        sha = hashlib.sha256()
        sha.update(key)
        for _i in range(1, 1000 + 1):
            sha.update(secret[28:60])
        aeskey = sha.digest()

        data = b""
        for i in range(60, len(secret), 16):
            aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
            buf = secret[i : i + 16]
            if len(buf) < 16:
                buf += (16 - len(buf)) * "\00"
            data += aes.decrypt(buf)

        return data

    @classmethod
    def get_lsa_key(
        cls, sechive: registry_layer.RegistryHive, bootkey: bytes, vista_or_later: bool
    ) -> Optional[bytes]:
        if not bootkey:
            return None

        if vista_or_later:
            policy_key = "PolEKList"
        else:
            policy_key = "PolSecretEncryptionKey"

        enc_reg_key = hashdump.Hashdump.get_hive_key(sechive, "Policy\\" + policy_key)
        if not enc_reg_key:
            return None
        enc_reg_value = next(enc_reg_key.get_values(), None)
        if not enc_reg_value:
            return None

        try:
            obf_lsa_key = sechive.read(enc_reg_value.Data + 4, enc_reg_value.DataLength)
        except exceptions.InvalidAddressException:
            return None

        if not obf_lsa_key:
            return None
        if not vista_or_later:
            md5 = hashlib.md5()
            md5.update(bootkey)
            for _i in range(1000):
                md5.update(obf_lsa_key[60:76])
            rc4key = md5.digest()

            rc4 = ARC4.new(rc4key)
            lsa_key = rc4.decrypt(
                obf_lsa_key[12:60]
            )  # lgtm [py/weak-cryptographic-algorithm]
            lsa_key = lsa_key[0x10:0x20]
        else:
            lsa_key = cls.decrypt_aes(obf_lsa_key, bootkey)
            lsa_key = lsa_key[68:100]
        return lsa_key

    @classmethod
    def get_secret_by_name(
        cls,
        sechive: registry_layer.RegistryHive,
        name: str,
        lsakey: bytes,
        is_vista_or_later: bool,
    ) -> Optional[bytes]:
        enc_secret_key = hashdump.Hashdump.get_hive_key(
            sechive, "Policy\\Secrets\\" + name + "\\CurrVal"
        )

        secret = None
        if enc_secret_key:
            try:
                enc_secret_value = next(enc_secret_key.get_values(), None)
            except (
                exceptions.InvalidAddressException,
                registry_layer.RegistryException,
            ):
                enc_secret_value = None

            if enc_secret_value:
                try:
                    enc_secret = sechive.read(
                        enc_secret_value.Data + 4, enc_secret_value.DataLength
                    )
                except exceptions.InvalidAddressExceptions:
                    return None

                if enc_secret:
                    if not is_vista_or_later:
                        secret = cls.decrypt_secret(enc_secret[0xC:], lsakey)
                    else:
                        secret = cls.decrypt_aes(enc_secret, lsakey)

        return secret

    @classmethod
    def decrypt_secret(cls, secret: bytes, key: bytes) -> bytes:
        """Python implementation of SystemFunction005.

        Decrypts a block of data with DES using given key.
        Note that key can be longer than 7 bytes."""
        decrypted_data = b""
        j = 0  # key index

        for i in range(0, len(secret), 8):
            enc_block = secret[i : i + 8]
            block_key = key[j : j + 7]
            des_key = hashdump.Hashdump.sidbytes_to_key(block_key)
            des = DES.new(des_key, DES.MODE_ECB)
            enc_block = enc_block + b"\x00" * int(abs(8 - len(enc_block)) % 8)
            decrypted_data += des.decrypt(
                enc_block
            )  # lgtm [py/weak-cryptographic-algorithm]
            j += 7
            if len(key[j : j + 7]) < 7:
                j = len(key[j : j + 7])

        (dec_data_len,) = unpack("<L", decrypted_data[:4])

        return decrypted_data[8 : 8 + dec_data_len]

    def _generator(
        self,
        syshive: registry_layer.RegistryHive,
        sechive: registry_layer.RegistryHive,
    ):
        kernel = self.context.modules[self.config["kernel"]]

        vista_or_later = versions.is_vista_or_later(
            context=self.context, symbol_table=kernel.symbol_table_name
        )

        bootkey = hashdump.Hashdump.get_bootkey(syshive)
        if not bootkey:
            vollog.warning("Unable to find bootkey")
            return None

        lsakey = self.get_lsa_key(sechive, bootkey, vista_or_later)
        if not lsakey:
            vollog.warning("Unable to find lsa key")
            return None

        secrets_key = hashdump.Hashdump.get_hive_key(sechive, "Policy\\Secrets")
        if not secrets_key:
            vollog.warning("Unable to find secrets key")
            return None

        for key in secrets_key.get_subkeys():
            sec_val_key = hashdump.Hashdump.get_hive_key(
                sechive,
                "Policy\\Secrets\\" + key.get_key_path().split("\\")[3] + "\\CurrVal",
            )
            if not sec_val_key:
                continue

            try:
                enc_secret_value = next(sec_val_key.get_values(), None)
            except (
                StopIteration,
                exceptions.InvalidAddressException,
                registry_layer.RegistryException,
            ):
                enc_secret_value = None

            if not enc_secret_value:
                continue

            try:
                enc_secret = sechive.read(
                    enc_secret_value.Data + 4, enc_secret_value.DataLength
                )
            except exceptions.InvalidAddressExceptions:
                continue

            if not vista_or_later:
                secret = self.decrypt_secret(enc_secret[0xC:], lsakey)
            else:
                secret = self.decrypt_aes(enc_secret, lsakey)

            try:
                key_name = key.get_name()
            except (
                exceptions.InvalidAddressException,
                registry_layer.RegistryException,
            ):
                key_name = renderers.UnreadableValue()

            yield (0, (key_name, format_hints.HexBytes(secret), secret))

    def run(self):
        offset = self.config.get("offset", None)
        syshive = sechive = None

        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            hive_offsets=None if offset is None else [offset],
        ):
            if hive.get_name().split("\\")[-1].upper() == "SYSTEM":
                syshive = hive
            if hive.get_name().split("\\")[-1].upper() == "SECURITY":
                sechive = hive

        return renderers.TreeGrid(
            [("Key", str), ("Secret", format_hints.HexBytes), ("Hex", bytes)],
            self._generator(syshive, sechive),
        )
