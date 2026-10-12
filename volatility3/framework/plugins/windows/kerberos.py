"""
Klist plugin made with love by the Airbus CERT team

The plugin intend to:
    - Sessions      : list sessions managed by the kerberos security provider
    - Tickets       : list ticket in cache
    - VadTicketScan : Carve tickets from lsass process Vad
"""
import logging
import datetime
from typing import Iterable, Tuple, List, Type, Callable

from volatility3.framework import interfaces, symbols, exceptions, constants, objects
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import conversion
from volatility3.plugins.windows import pslist, vadinfo, pe_symbols
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)    

def UnwrapMemoryOr(default):
    """Wrapper that will check if the function could access to an invalid memory space"""
    def _safe_memory_wrapper_1(function):
        def _safe_memory_wrapper_2(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Invalid address {hex(excp.invalid_address)} in layer {excp.layer_name} from {function.__qualname__}"
                )
                return default
        
        return _safe_memory_wrapper_2
    return _safe_memory_wrapper_1

def _layout_scanner(
        source: interfaces.objects.ObjectInterface, 
        object_type: str, 
        condition: Callable, 
        start=0x0,
        increment=0x8, 
        max_offset=512
    ):
    """Will scan an object layout memory by casting it into object_type and respect condition
        source: object which want to test the layout
        condition: function call to to know if object was found
        
        :return: list of offset from source where condition is valid
    """
    result = []
    # align for 64 bits
    offset = start
    while offset < max_offset:
        obj = source._context.object(
            layer_name=source.vol.layer_name,
            object_type=object_type, 
            offset=source.vol.offset + offset
        )
        
        if condition(obj):
            result.append(offset)
            
        offset += increment
    return result

def _scan_for_list_header(
        obj: interfaces.objects.ObjectInterface, 
        max_offset=512, 
        max_element=50,
        inc=0x8
    ):
    """Will test the LIST_ENTRY by looping over all element and test if it come back to the original
    
    """
    result = []
    # align for 64 bits
    offset = 0
    while (offset < max_offset and inc > 0) or (offset > max_offset and inc < 0):
        list_head = obj._context.object(
            layer_name=obj.vol.layer_name,
            object_type=obj._context.modules['kernel'].symbol_table_name+constants.BANG+'_LIST_ENTRY', 
            offset=obj.vol.offset + offset
        )
        
        try:
            index_element = 0
            element = list_head
            while element.Flink != list_head.vol.offset:
                element = element.Flink
                index_element += 1
                if index_element > max_element:
                    raise exceptions.VolatilityException("Max element reach before looping")
                
            #find
            result.append(offset)
                
        except:
            """The list does not loop on self element so not a list"""
            
        offset += inc
    return result

def _scan_for_unicode_string(obj: interfaces.objects.ObjectInterface):
    """Search for unicode string where pattern is MaxLength = Length + 2 (null terminator)"""
    return _layout_scanner(
        source=obj, 
        object_type=obj._context.modules['kernel'].symbol_table_name+constants.BANG+'_UNICODE_STRING',
        condition=lambda s: s.Length + 2 == s.MaximumLength and obj._context.layers[obj.vol.layer_name].is_valid(s.Buffer, s.MaximumLength)
    )
    
def _scan_for_timestamp(obj, max_offset=512):
    """ Search for timestamp integer that start with 0x01D"""
    return _layout_scanner(
        source=obj, 
        object_type=obj._context.modules['kernel'].symbol_table_name+constants.BANG+'unsigned long long',
        condition=lambda timestamp: (timestamp & 0xff00000000000000 == 0x0100000000000000) and not obj._context.layers[obj.vol.layer_name].is_valid(timestamp, 8)
    )

def _etype_str(etype:int) -> str:
    if etype == 18:
        return "AES_256_CTS_HMAC_SHA_196"
    elif etype == 17:
        return "AES_128_CTS_HMAC_SHA_196"
    elif etype == 23:
        return "RC4_HMAC"
    else:
        return "UNKNOWN_ETYPE"

class KERB_INTERNAL_NAME(objects.StructType):
    """Use to reprensent an internal name in kerberos
    
    The name is concataned using '/' char
    """
    @UnwrapMemoryOr("UNKNOWN")
    def get_string(self):
        result = []
        for i in range(0, self.NbString):
            result.append(
                self._context.object(
                    layer_name=self.vol.layer_name,
                    object_type=self.array.get_symbol_table_name() + constants.BANG + "_UNICODE_STRING", 
                    offset=self.array.vol.offset + i * 0x10
                ).String
        )
        return "/".join(result)
        
        
class KERB_CREDENTIAL(objects.StructType):
    @UnwrapMemoryOr(None)
    def get_primary(self):
        """ Search for primary struct whch start by two unicode string"""
        # search for the first unicode string to align the struct
        primary_offset = _scan_for_unicode_string(self)
        if primary_offset is None or len(primary_offset) == 0:
            vollog.debug(
                f"Unable to compute the ticket primary offset"
            )
            return None

        return self._context.object(
            layer_name=self.vol.layer_name,
            object_type=self.get_symbol_table_name() + constants.BANG + "_KERB_PRIMARY_CREDENTIAL", 
            offset= self.vol.offset + primary_offset[0]
        )
        
    def get_logon_session_id(self):
        if self.LogonSessionId_1.HighPart == 0 and self.LogonSessionId_1.LowPart == 0:
            return self.LogonSessionId_2
        else:
            return self.LogonSessionId_1


class KERB_PRIMARY_CREDENTIAL(objects.StructType):  
    @UnwrapMemoryOr(None)
    def get_ticket_cache(self):
        """Ticket cache are three _LIST_ENTRY in the Credential struct"""
        # ticket cache is three LIST_ENTRY
        ticket_cache_offset = _scan_for_list_header(self)
        if ticket_cache_offset is None or len(ticket_cache_offset) < 3:
            vollog.debug(
                f"Unable to compute the ticket cache offset"
            )
            return None
        # keep only the three first
        ticket_cache_offset = ticket_cache_offset[:3]
        return [
            self._context.object(
                layer_name=self.vol.layer_name,
                object_type=self.Username.get_symbol_table_name() + constants.BANG + "_LIST_ENTRY", 
                offset=self.vol.offset + offset
            ) for offset in ticket_cache_offset
        ]

class KERB_TICKET_INFO(objects.StructType):   
    def _scan_for_ticket(self):
        """Search for Ticket where tkt_vno is always 5 (specification) and EType is in [1, 3, 17, 18, 23, 24]"""
        return _layout_scanner(
            source=self, 
            object_type=self.get_symbol_table_name() + constants.BANG + "_KERB_TICKET",
            condition=lambda ticket: ticket.tkt_vno == 5 and ticket.EType in [1, 3, 17, 18, 23, 24]
        )[0]
      
    def _scan_for_session_key(self):
        """Session key layout is more challenging and could failed as the layout is very dependant to Windows version"""
        for key_session_type in ["KERB_SESSION_KEY_V1", "KERB_SESSION_KEY_V2"]:
            
            scan = _layout_scanner(
                source=self, 
                object_type=self.get_symbol_table_name() + constants.BANG + key_session_type,
                condition=lambda session_key: (session_key.EType == 18 and session_key.Size == 0x20) or (session_key.EType == 17 and session_key.Size == 0x10) or (session_key.EType == 23 and session_key.Size == 0x10)
            )
            
            if scan:
                return scan[0], key_session_type
        
        return None
          
    def _scan_for_client_name(self):
        """client name is the first valid address from kdcCalled offset"""
        return _layout_scanner(
            source=self,
            start=self.KdcCalled.vol.offset + 0x10 - self.vol.offset,
            object_type=self.get_symbol_table_name() + constants.BANG + "unsigned long long",
            condition=lambda pointer: self._context.layers[self.vol.layer_name].is_valid(pointer)
        )[0]
        

    def get_client_name(self):
        client_name_offset = self._scan_for_client_name()
        if client_name_offset is None:
            vollog.debug(
                f"Unable to compute the client name offset"
            )
            return None
        return self._context.object(
            layer_name=self.vol.layer_name,
            object_type=self.get_symbol_table_name() + constants.BANG + "pointer",
            subtype=self._context.modules[self.get_symbol_table_name()].get_type("_KERB_INTERNAL_NAME"), 
            offset=self.vol.offset + client_name_offset
        )
    
    @UnwrapMemoryOr(-1)
    def get_ticket_time(self):
        """ Search for at least three timestamp in the info layout"""
        # There is three timestamp that represent the timestamp of every ticket
        ticket_time_offset = (_scan_for_timestamp(self) + [0,0,0])[:3]
        return [
            self._context.object(
                layer_name=self.vol.layer_name,
                object_type=self.get_symbol_table_name( ) + constants.BANG + "unsigned long long", 
                offset=self.vol.offset + offset
            ) for offset in ticket_time_offset
        ]
    
    @UnwrapMemoryOr(None)   
    def get_ticket(self):
        """The layout of ticket is just after the renew time"""
        ticket_offset = self._scan_for_ticket()
        if ticket_offset is None:
            vollog.debug(
                f"Unable to compute the ticket offset"
            )
            return None
        return self._context.object(
            layer_name=self.vol.layer_name,
            object_type=self.get_symbol_table_name() + constants.BANG + "_KERB_TICKET", 
            offset=self.vol.offset + ticket_offset
        )
    
    @UnwrapMemoryOr(None)
    def get_session_key(self):
        session_key_offset = self._scan_for_session_key()
        if session_key_offset is None:
            vollog.debug(
                f"Unable to compute the session key offset"
            )
            return None
        return self._context.object(
            layer_name=self.vol.layer_name,
            object_type=self.get_symbol_table_name() + constants.BANG + session_key_offset[1], 
            offset=self.vol.offset + session_key_offset[0]
        )
                  
    @UnwrapMemoryOr(0)
    def get_ticket_flags(self):
        """Ticket flag are 0x16 far from Client Name scan result"""
        client_name_offset = self._scan_for_client_name()
        if client_name_offset is None:
            vollog.debug(
                f"Unable to compute the client name offset"
            )
            return None
        return self._context.object(
            layer_name=self.vol.layer_name,
            object_type=self.get_symbol_table_name() + constants.BANG + "unsigned long long", 
            offset=self.vol.offset + client_name_offset + 0x10
        ) 
        
    @UnwrapMemoryOr("Unable to parse service name")
    def get_service_name(self):
        return self.ServiceName
        
    @UnwrapMemoryOr(-1)
    def get_start_time(self):
        return self.get_ticket_time()[0]
    
    @UnwrapMemoryOr(-1)
    def get_end_time(self):
        return self.get_ticket_time()[1]
    
    @UnwrapMemoryOr(-1)
    def get_renew_time(self):
        return self.get_ticket_time()[2]
    
    
    def toKRBCRED(self):
        """Function inspired by impacket convertion script"""
        try:
            from impacket.krb5.asn1 import AS_REP, TGS_REP, Ticket, KRB_CRED, EncKrbCredPart, KrbCredInfo, seq_set_iter
            from impacket.krb5.types import KerberosTime
            from pyasn1.type.univ import noValue
            from pyasn1.codec.der import encoder
        except:
            raise exceptions.VolatilityException("Unable to dump ticket, install impacket before")
        
        session_key = self.get_session_key()
        if session_key is None:
            raise Exception("Unable to find session key")
            
        ticket = self.get_ticket()
        if ticket is None:
            raise Exception("Unable to find ticket")
        
        krbCredInfo = KrbCredInfo()

        krbCredInfo['key'] = noValue
        krbCredInfo['key']['keytype'] = session_key.EType
        krbCredInfo['key']['keyvalue'] = self._context.layers[self.vol.layer_name].read(session_key.Buffer, session_key.Size)

        
        krbCredInfo['prealm'] = ticket.Realm.dereference().cast("string", encoding="utf-8", errors="replace", max_length=512)

        krbCredInfo['pname'] = noValue
        krbCredInfo['pname']['name-type'] = self.get_client_name().dereference().PrincipalType
        seq_set_iter(krbCredInfo['pname'], 'name-string', (self.get_client_name().dereference().get_string(),))

        krbCredInfo['flags'] = self.get_ticket_flags()

        krbCredInfo['starttime'] = KerberosTime.to_asn1(conversion.wintime_to_datetime(self.get_start_time()))
        krbCredInfo['endtime'] = KerberosTime.to_asn1(conversion.wintime_to_datetime(self.get_end_time()))
        krbCredInfo['renew-till'] = KerberosTime.to_asn1(conversion.wintime_to_datetime(self.get_renew_time()))

        krbCredInfo['srealm'] = self.ServerRealm.String

        krbCredInfo['sname'] = noValue
        krbCredInfo['sname']['name-type'] = self.ServiceName.dereference().PrincipalType
        tmp_service_class, tmp_service_hostname, *_ = self.ServiceName.dereference().get_string().split('/') + ["unknown", "unknown"]
        seq_set_iter(krbCredInfo['sname'], 'name-string', (tmp_service_class, tmp_service_hostname))

        encKrbCredPart = EncKrbCredPart()
        seq_set_iter(encKrbCredPart, 'ticket-info', (krbCredInfo,))

        krbCred = KRB_CRED()
        krbCred['pvno'] = 5
        krbCred['msg-type'] = 22

        krbCred['enc-part'] = noValue
        krbCred['enc-part']['etype'] = 0
        krbCred['enc-part']['cipher'] = encoder.encode(encKrbCredPart)

        newticket = Ticket()
        newticket['tkt-vno'] = ticket.tkt_vno
        
        newticket['sname'] = noValue
        newticket['sname']['name-type'] = self.ServiceName.dereference().PrincipalType
        seq_set_iter(newticket['sname'], 'name-string', (tmp_service_class, tmp_service_hostname))
        
        newticket['realm'] = self.ServerRealm.String
        
        newticket['enc-part']['etype'] = ticket.EType
        newticket['enc-part']['kvno'] = ticket.Kvno
        newticket['enc-part']['cipher'] = self._context.layers[self.vol.layer_name].read(ticket.Cipher, ticket.CipherLength)
        
        seq_set_iter(krbCred, 'tickets', (newticket,))

        encodedKrbCred = encoder.encode(krbCred)

        return encodedKrbCred

class KlistCommand:
    def _find_global_session_table_with_pdb_symbols(
        self,
        kerberos_symbols: str,
        kerberos_types: interfaces.context.ModuleInterface,
        proc_layer_name: str,
        kerberos_base: int,
    ) -> interfaces.objects.ObjectInterface:
        """
        Find the Global Session Table base on public symbol
        """
        
        kerberos_module = self.context.module(
            kerberos_symbols, layer_name=proc_layer_name, offset=kerberos_base
        )

        KerbGlobalLogonSessionTableAddr = kerberos_module.get_symbol(
            "?KerbGlobalLogonSessionTable@@3U_RTL_AVL_TABLE@@A"
        )
        
        if KerbGlobalLogonSessionTableAddr is None:
            raise exceptions.SymbolError("Unable to find the KerbGlobalLogonSessionTable symbol")
        
        KerbGlobalLogonSessionTable = kerberos_types.object(
           object_type="_RTL_AVL_TABLE", 
           offset=KerbGlobalLogonSessionTableAddr.address
        )
        
        return KerbGlobalLogonSessionTable
        
    def _get_kerberos_types(
        self,
        context: interfaces.context.ContextInterface,
        config,
        config_path: str,
        proc_layer_name: str,
        kerberos_base: int,
    ) -> interfaces.context.ModuleInterface:
        """
        Builds a symbol table from the kerberos types generated after binary analysis

        Args:
            context: the context to operate upon
            config:
            config_path:
            proc_layer_name: name of the lsass.exe process layer
            kerberos_base: base address of kerberos.dll inside of lsass.exe
        """
        
        kernel = self.context.modules[self.config["kernel"]]
        table_mapping = {"nt_symbols": kernel.symbol_table_name}

        kerberos_symbol_table = intermed.IntermediateSymbolTable.create(
            context=context,
            config_path=config_path,
            sub_path="windows",
            filename="kerberos",
            class_types={
                "_KERB_INTERNAL_NAME": KERB_INTERNAL_NAME, 
                "_KERB_CREDENTIAL": KERB_CREDENTIAL,
                "_KERB_PRIMARY_CREDENTIAL": KERB_PRIMARY_CREDENTIAL,
                "_KERB_TICKET_INFO": KERB_TICKET_INFO
            },
            table_mapping=table_mapping,
        )

        return context.module(
            kerberos_symbol_table, proc_layer_name, offset=kerberos_base
        )
        
    def _find_lsass_proc(
        self, proc_list: Iterable
    ) -> Tuple[interfaces.context.ContextInterface, str]:
        """
        Walks the process list and returns the first valid lsass instances.
        There should be only one lsass process, but malware will often use the
        process name to try and blend in.

        Args:
            proc_list: The process list generator

        Return:
            The process object for lsass
        """

        for proc in proc_list:
            try:
                proc_layer_name = proc.add_process_layer()

                return proc, proc_layer_name

            except exceptions.InvalidAddressException as excp:
                vollog.error(
                    f"Invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )

        return None, None

    def _find_kerberos(
        self, lsass_proc: interfaces.context.ContextInterface
    ) -> Tuple[int, int]:
        """
        """
        for vad in lsass_proc.get_vad_root().traverse():
            filename = vad.get_file_name()

            if isinstance(filename, str) and filename.lower().endswith("kerberos.dll"):
                base = vad.get_start()
                return base, vad.get_size()

        return None, None
    
    def _search_sessions_from_root(
        self, avl_root_node: interfaces.objects.ObjectInterface
    ) -> List[interfaces.objects.ObjectInterface]:
        """
        Recurcively parse the tree to find each node from the BalancedRoot
        """
        
        return self._search_sessions(avl_root_node.LeftChild) + self._search_sessions(avl_root_node.RightChild)
   
    def _search_sessions(
        self, avl_node: interfaces.objects.ObjectInterface
    ) -> List[interfaces.objects.ObjectInterface]:
        """
        Will output every node of the tree casted into _KERB_LOGON_SESSION_ENTRY
        """
        
        if avl_node == 0:
            return []
        try:
            return [avl_node.dereference().cast("_KERB_LOGON_SESSION_ENTRY")] + self._search_sessions(avl_node.LeftChild) + self._search_sessions(avl_node.RightChild)
        except exceptions.PagedInvalidAddressException:
            return []
        

    def _find_kerberos_ticket(
        self,
        kerberos_types: interfaces.context.ModuleInterface,
        kerberos_logon_session: interfaces.objects.ObjectInterface,
    ):

        primary = kerberos_logon_session.Credentials.get_primary()
        if primary is None:
            vollog.error(
                f"Unable to compute the primary ticket for logon session %s"%format_hints.Hex(kerberos_logon_session.vol.offset)
            )
            return

        ticket_caches = primary.get_ticket_cache()

        for cache in ticket_caches:
            try:
                next_ticket = cache.Flink
                while next_ticket != cache.vol.offset:
                    ticket_info = kerberos_types.object(
                       object_type="_KERB_TICKET_INFO", 
                       offset=next_ticket,
                       absolute=True
                    )
                    yield kerberos_logon_session, ticket_info                
                    next_ticket = next_ticket.Flink
            except exceptions.InvalidAddressException:
                vollog.warning("_LIST_ENTRY corrupted during ticket parsing")
       
    def _load_kerberos_type_and_symbol(
        self, 
        procs
    ) -> Tuple[str, int, interfaces.context.ModuleInterface, str]:
        """Will find type and symbol for the kerberos.dll
        """
        kernel = self.context.modules[self.config["kernel"]]

        if not symbols.symbol_table_is_64bit(
            context=self.context, symbol_table_name=kernel.symbol_table_name
        ):
            vollog.info("This plugin only supports 64bit Windows memory samples")
            return None

        lsass_proc, proc_layer_name = self._find_lsass_proc(procs)

        if not lsass_proc:
            vollog.error(
                "Unable to find a valid lsass.exe process in the process list. This should never happen. Analysis cannot proceed."
            )
            return None

        kerberos_base, kerberos_size = self._find_kerberos(lsass_proc)
        if not kerberos_base:
            vollog.error(
                "Unable to find the location of kerberos.dll inside of lsass.exe. Analysis cannot proceed."
            )
            return None

        kerberos_types = self._get_kerberos_types(
            self.context, self.config, self.config_path, proc_layer_name, kerberos_base
        )
        
        try:
            kerberos_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                self.context,
                interfaces.configuration.path_join(self.config_path, "kerberos"),
                proc_layer_name,
                "KERBEROS.pdb",
                kerberos_base,
                kerberos_size,
            )
        except exceptions.VolatilityException as e:
            vollog.debug(
                f"Unable to use the kerberos PDB. Stopping PDB symbols based analysis : {e}"
            )
            return None

        return proc_layer_name, kerberos_base, kerberos_types, kerberos_symbols
        
    def _find_kerberos_sessions(
        self,
        proc_layer_name,
        kerberos_base,
        kerberos_types, 
        kerberos_symbols
    ) -> List[interfaces.objects.ObjectInterface]:
        """
        This function will find the Global session table, parse the tree and output all found sessions
        as _KERB_LOGON_SESSION_ENTRY
        """

        global_session_table = self._find_global_session_table_with_pdb_symbols(
            kerberos_symbols, kerberos_types, proc_layer_name, kerberos_base
        )
        
        return self._search_sessions_from_root(global_session_table.BalancedRoot)
        
    def _lsass_proc_filter(self, proc):
        """
        Used to filter to only lsass.exe processes

        There should only be one of these, but malware can/does make lsass.exe
        named processes to blend in or uses lsass.exe as a process hollowing target
        """
        process_name = utility.array_to_string(proc.ImageFileName)

        return process_name != "lsass.exe"
    

    @classmethod
    def dump_ticket(
        cls,
        ticket_info, 
        open_method: Type[interfaces.plugins.FileHandlerInterface]
    ) -> interfaces.plugins.FileHandlerInterface:
        try:
            file_handle = open_method(
                open_method.sanitize_filename(
                    f"{hex(ticket_info.vol.offset)}.kirbi"
                )
            )
            file_handle.write(ticket_info.toKRBCRED())
        except Exception as excp:
            vollog.warning(f"Unable to dump Ticket from address {ticket_info.vol.offset}: {excp}")
               

class Sessions(interfaces.plugins.PluginInterface, KlistCommand):
    """Looks for sessions managed by the kerberos security provider"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pe_symbols.PESymbols, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            )
        ]

    def _generator(self):
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=self._lsass_proc_filter,
        )

        proc_layer_name, kerberos_base, kerberos_types, kerberos_symbols = self._load_kerberos_type_and_symbol(procs)
        kerberos_sessions = self._find_kerberos_sessions(
            proc_layer_name, kerberos_base, kerberos_types, kerberos_symbols
        )
        
        for session in kerberos_sessions:
            logon_session_entry = session.entry.dereference().cast('_KERB_LOGON_SESSION')
            try:
                yield (0,
                    (
                        "%s:%s"%(hex(logon_session_entry.Credentials.get_logon_session_id().HighPart)[2:],hex(logon_session_entry.Credentials.get_logon_session_id().LowPart)[2:]),
                        logon_session_entry.Credentials.get_primary().Username.String,
                        logon_session_entry.Credentials.get_primary().Realm.String,
                        len(list(self._find_kerberos_ticket(kerberos_types, logon_session_entry)))
                    )
                )
            except exceptions.InvalidAddressException as e:
                vollog.warning(
                    "Unable to parse session %s"%str(e)
                )
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", str),
                ("Domain", str),
                ("TargetUsername", str),
                ("Nb Tickets", int),
            ],
            self._generator()
        )

class Tickets(interfaces.plugins.PluginInterface, KlistCommand, timeliner.TimeLinerInterface):
    """Looks for tickets managed by the kerberos security provider"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pe_symbols.PESymbols, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed tickets",
                default=False,
                optional=True,
            )
        ]

    def _generator(self):
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=self._lsass_proc_filter,
        )

        proc_layer_name, kerberos_base, kerberos_types, kerberos_symbols = self._load_kerberos_type_and_symbol(procs)
        kerberos_sessions = self._find_kerberos_sessions(
            proc_layer_name, kerberos_base, kerberos_types, kerberos_symbols
        )
        
        for session in kerberos_sessions:
            logon_session_entry = session.entry.dereference().cast('_KERB_LOGON_SESSION')

            for session, ticket_info in self._find_kerberos_ticket(kerberos_types, logon_session_entry):
                primary = session.Credentials.get_primary()
                username = "UNKNOWN"
                realm = "UNKNOWN"
                if not primary is None:
                    username = session.Credentials.get_primary().Username.String
                    realm = session.Credentials.get_primary().Realm.String
                    
                ticket = ticket_info.get_ticket()
                ticket_etype = -1
                if not ticket is None:
                    ticket_etype = ticket.EType
                
                session_key = ticket_info.get_session_key()
                session_key_etype = -1
                if not session_key is None:
                    session_key_etype = session_key.EType
                
                yield (0, (
                    format_hints.Hex(ticket_info.vol.offset),
                    "%s @ %s"%(username, realm),
                    "%s @ %s"%(ticket_info.ServiceName.dereference().get_string(), realm),
                    _etype_str(ticket_etype),
                    format_hints.Hex(ticket_info.get_ticket_flags()),
                    conversion.wintime_to_datetime(ticket_info.get_start_time()),
                    conversion.wintime_to_datetime(ticket_info.get_end_time()),
                    conversion.wintime_to_datetime(ticket_info.get_renew_time()),
                    _etype_str(session_key_etype),
                    ticket_info.KdcCalled.String,
                ))

                # dump ticket if parameter is passed
                if self.config["dump"]:
                    KlistCommand.dump_ticket(ticket_info, self.open)

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Kerberos Ticket: {row_data[1]} {row_data[2]} ({row_data[9]})"
            yield (description, timeliner.TimeLinerType.CREATED, row_data[5])
            yield (description, timeliner.TimeLinerType.CHANGED, row_data[7])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Client", str),
                ("Server", str),
                ("KerbTicket Encryption Type", str),
                ("Ticket Flags", format_hints.Hex),
                ("Start Time", datetime.datetime),
                ("End Time", datetime.datetime),
                ("Renew Time", datetime.datetime),
                ("Session Key Type", str),
                ("Kdc Called", str),
            ],
            self._generator()
        )
        
class VadTicketScan(interfaces.plugins.PluginInterface, KlistCommand):
    """Scan VAD space and carve ticket layout to find unreferenced ticket in the cache
    """

    _required_framework_version = (2, 4, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed tickets",
                default=False,
                optional=True,
            )
        ]

    def _generator(self):
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=self._lsass_proc_filter,
        )

        lsass_proc, proc_layer_name = self._find_lsass_proc(procs)

        if not lsass_proc:
            vollog.error(
                "Unable to find a valid lsass.exe process in the process list. This should never happen. Analysis cannot proceed."
            )
            return None

        kerberos_base, _ = self._find_kerberos(lsass_proc)
        if not kerberos_base:
            vollog.error(
                "Unable to find the location of kerberos.dll inside of lsass.exe. Analysis cannot proceed."
            )
            return None

        kerberos_types = self._get_kerberos_types(
            self.context, self.config, self.config_path, proc_layer_name, kerberos_base
        )

        sanity_check = 1024 * 1024 * 1024  # 1 GB

        max_vad_size = 0
        vad_maps_to_scan = []

        for start, size in self.get_vad_maps(lsass_proc):
            if size > sanity_check:
                vollog.debug(
                    f"VAD at 0x{start:x} over sanity-check size, not scanning"
                )
                continue
            max_vad_size = max(max_vad_size, size)
            vad_maps_to_scan.append((start, size))

        if not vad_maps_to_scan:
            vollog.warning(
                f"No VADs were found for task {lsass_proc.UniqueProcessId}, not scanning"
            )
            return

        for start, size in vad_maps_to_scan:

            buffer = self.context.layers[proc_layer_name].read(start, size, pad=True)
            # We will find every 5 value which is one of the marker of kerberos ticket
            offset = buffer.find(5)
            while offset != -1:
                try:
                    ticket = kerberos_types.object(
                        object_type="_KERB_TICKET", 
                        offset=start + offset - 4,
                        absolute=True
                    )
                    if ticket.tkt_vno == 5 and ticket.EType in [1, 3, 17, 18, 23, 24]:
                        #Found a candidate try to retrieve ticket_info list header in backward
                        header_offset = _scan_for_list_header(ticket, max_offset=-0x200, inc=-0x8)[0]
                        
                        ticket_info = kerberos_types.object(
                            object_type="_KERB_TICKET_INFO", 
                            offset=ticket.vol.offset + header_offset,
                            absolute=True
                        )
                        
                        yield (0, (
                            format_hints.Hex(ticket_info.vol.offset),
                            str(ticket_info.get_client_name().dereference().get_string()), 
                            str(ticket_info.ServiceName.dereference().get_string()),
                            _etype_str(int(ticket_info.get_ticket().EType)),
                            format_hints.Hex(int(ticket_info.get_ticket_flags())),
                            conversion.wintime_to_datetime(ticket_info.get_start_time()),
                            conversion.wintime_to_datetime(ticket_info.get_end_time()),
                            conversion.wintime_to_datetime(ticket_info.get_renew_time()),
                            _etype_str(int(ticket_info.get_session_key().EType)),
                            ticket_info.KdcCalled.String,
                        ))

                        if self.config["dump"]:
                            # now handle the dump
                            KlistCommand.dump_ticket(ticket_info, self.open)

                except Exception as e:
                    # can generate a lot due to the way the scanning works
                    vollog.debug(
                        f"Exception happened during scanning {e}"
                    )
                    
                offset = buffer.find(5, offset + 1)

    @staticmethod
    def get_vad_maps(
        task: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and size for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            yield (vad.get_start(), vad.get_size())

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Client", str),
                ("Server", str),
                ("KerbTicket Encryption Type", str),
                ("Ticket Flags", format_hints.Hex),
                ("Start Time", datetime.datetime),
                ("End Time", datetime.datetime),
                ("Renew Time", datetime.datetime),
                ("Session Key Type", str),
                ("Kdc Called", str),
            ],
            self._generator()
        )