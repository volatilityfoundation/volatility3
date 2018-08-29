import codecs
import datetime
import logging
import typing

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import exceptions, renderers, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers.physical import BufferDataLayer
from volatility.framework.layers.registry import RegistryHive
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)

# taken from http://msdn.microsoft.com/en-us/library/dd378457%28v=vs.85%29.aspx
folder_guids = {
    "{de61d971-5ebc-4f02-a3a9-6c82895e5c04}": "Add or Remove Programs (Control Panel)",
    "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{a305ce99-f527-492b-8b1a-7e76fa98d6e4}": "Installed Updates",
    "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn",
    "{df7266ac-9274-4867-8d55-3bd661de872d}": "Programs and Features",
    "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}": "%ALLUSERSPROFILE%\\OEM Links",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
    "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{B94237E7-57AC-4347-9151-B08C6C32D1F7}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates",
    "{0AC0837C-BBF8-452A-850D-79D08E667CA7}": "(My) Computer",
    "{4bfefb45-347d-4006-a5be-ac0cb0567192}": "Conflicts",
    "{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}": "Network Connections",
    "{56784854-C6CB-462b-8169-88E350ACB882}": "%USERPROFILE%\\Contacts",
    "{82A74AEB-AEB4-465C-A014-D097EE346D63}": "Control Panel",
    "{2B0F765D-C0E9-4171-908E-08A611B84FF6}": "%APPDATA%\\Microsoft\\Windows\\Cookies",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{5CE4A5E9-E4EB-479D-B89F-130C02886155}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore",
    "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%USERPROFILE%\\Downloads",
    "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": "%USERPROFILE%\\Favorites",
    "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}": "%windir%\\Fonts",
    "{CAC52C1A-B53D-4edc-92D7-6B2E8AC19434}": "Games",
    "{054FAE61-4DD8-4787-80B6-090220C4B700}": "GameExplorer",
    "{D9DC8A3B-B784-432E-A781-5A1130A75963}": "%LOCALAPPDATA%\\Microsoft\\Windows\\History",
    "{52528A6B-B9E3-4ADD-B60D-588C2DBA842D}": "Homegroup",
    "{BCB5256F-79F6-4CEE-B725-DC34E402FD46}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts",
    "{352481E8-33BE-4251-BA85-6007CAEDCF9D}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
    "{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}": "The Internet",
    "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}": "%APPDATA%\\Microsoft\\Windows\\Libraries",
    "{bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968}": "%USERPROFILE%\\Links",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "%LOCALAPPDATA% (%USERPROFILE%\\AppData\\Local)",
    "{A520A1A4-1780-4FF6-BD18-167343C5AF16}": "%USERPROFILE%\\AppData\\LocalLow",
    "{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}": "%windir%\\resources\\0409 (code page)",
    "{4BD8D571-6D19-48D3-BE97-422220080E43}": "%USERPROFILE%\\Music",
    "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
    "{C5ABBF53-E17F-4121-8900-86626FC2C973}": "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
    "{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}": "Network",
    "{2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39}": "%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images",
    "{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}": "%USERPROFILE%\\Pictures\\Slide Shows",
    "{A990AE9F-A03B-4E80-94BC-9912D7504104}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "%USERPROFILE%\\Pictures",
    "{DE92C1C7-837F-4F69-A3BB-86E631204A23}": "%USERPROFILE%\\Music\\Playlists",
    "{76FC4E2D-D6AD-4519-A663-37BD56068185}": "Printers",
    "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}": "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "%USERPROFILE% (%SystemDrive%\\Users\\%USERNAME%)",
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "%ALLUSERSPROFILE% (%ProgramData%, %SystemDrive%\\ProgramData)",
    "{905e63b6-c1bf-494e-b29c-65b732d3d21a}": "%ProgramFiles%",
    "{6D809377-6AF0-444b-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles%",
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "%ProgramFiles%\\Common Files",
    "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "%ProgramFiles%\\Common Files",
    "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": "%ProgramFiles%\\Common Files",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{DFDF76A2-C82A-4D63-906A-5644AC457385}": "%PUBLIC% (%SystemDrive%\\Users\\Public)",
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "%PUBLIC%\\Desktop",
    "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "%PUBLIC%\\Documents",
    "{3D644C9B-1FB8-4f30-9B45-F670235F79C0}": "%PUBLIC%\\Downloads",
    "{DEBF2536-E1A8-4c59-B6A2-414586476AEA}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer",
    "{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries",
    "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "%PUBLIC%\\Music",
    "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "%PUBLIC%\\Pictures",
    "{E555AB60-153B-4D17-9F04-A5FE99FC15EC}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones",
    "{2400183A-6185-49FB-A2D8-4A392A602BA3}": "%PUBLIC%\\Videos",
    "{52a4f021-7b75-48a9-9f6b-4b87a210bc8f}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
    "{AE50C081-EBD2-438A-8655-8A092E34987A}": "%APPDATA%\\Microsoft\\Windows\\Recent",
    "{1A6FDBA2-F42D-4358-A798-B74D745926C5}": "%PUBLIC%\\RecordedTV.library-ms",
    "{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}": "Recycle Bin",
    "{8AD10C31-2ADB-4296-A8F7-E4701232C972}": "%windir%\\Resources",
    "{C870044B-F49E-4126-A9C3-B52A1FF411E8}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Ringtones",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "%APPDATA% (%USERPROFILE%\\AppData\\Roaming)",
    "{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}": "%PUBLIC%\\Music\\Sample Music",
    "{C4900540-2379-4C75-844B-64E6FAF8716B}": "%PUBLIC%\\Pictures\\Sample Pictures",
    "{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}": "%PUBLIC%\\Music\\Sample Playlists",
    "{859EAD94-2E85-48AD-A71A-0969CB56A6CD}": "%PUBLIC%\\Videos\\Sample Videos",
    "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}": "%USERPROFILE%\\Saved Games",
    "{7d1d3a04-debb-4115-95cf-2f29da2920da}": "%USERPROFILE%\\Searches",
    "{ee32e446-31ca-4aba-814f-a5ebd2fd6d5e}": "Offline Files",
    "{98ec0e18-2098-4d44-8644-66979315a281}": "Microsoft Office Outlook",
    "{190337d1-b8ca-4121-a639-6d472d16972a}": "Search Results",
    "{8983036C-27C0-404B-8F08-102D10DCFD74}": "%APPDATA%\\Microsoft\\Windows\\SendTo",
    "{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}": "%ProgramFiles%\\Windows Sidebar\\Gadgets",
    "{A75D362E-50FC-4fb7-AC2C-A8BEAA314493}": "%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets",
    "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "%APPDATA%\\Microsoft\\Windows\\Start Menu",
    "{B97D20BB-F46A-4C97-BA10-5E3608430854}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{43668BF8-C14E-49B2-97C9-747784D784B7}": "Sync Center",
    "{289a9a43-be44-4057-a41b-587a76d7e7f9}": "Sync Results",
    "{0F214138-B1D3-4a90-BBA9-27CBC0C5389A}": "Sync Setup",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%windir%\\system32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%windir%\\system32",
    "{A63293E8-664E-48DB-A079-DF759E0509F7}": "%APPDATA%\\Microsoft\\Windows\\Templates",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    "{0762D272-C50A-4BB0-A382-697DCD729B80}": "%SystemDrive%\\Users",
    "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}": "%LOCALAPPDATA%\\Programs",
    "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}": "%LOCALAPPDATA%\\Programs\\Common",
    "{f3ce0f7c-4901-4acc-8648-d5d44b04ef8f}": "The user's full name",
    "{A302545D-DEFF-464b-ABE8-61C8648D939B}": "Libraries",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "%USERPROFILE%\\Videos",
    "{491E922F-5643-4AF4-A7EB-4E7A138D8174}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%windir%",
}


class UserAssist(interfaces_plugins.PluginInterface):
    """"Print userassist registry keys and information"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._userassist_size = 0
        self._userassist_type_name = "_VOL_USERASSIST_TYPES_7"
        self._win7 = None

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'offset',
                                            description = "Hive Offset",
                                            default = None,
                                            optional = True)]

    def parse_userassist_data(self, reg_val):
        """Reads the raw data of a _CM_KEY_VALUE and returns a dict of userassist fields"""

        item = {
            "id": renderers.UnparsableValue(),
            "count": renderers.UnparsableValue(),
            "focus": renderers.UnparsableValue(),
            "time": renderers.UnparsableValue(),
            "lastupdated": renderers.UnparsableValue(),
            "rawdata": renderers.UnparsableValue(),
        }

        userassist_data = reg_val.decode_data()

        if userassist_data is None:
            return item

        item["rawdata"] = userassist_data

        if self._win7 is None:
            # if OS is still unknown at this point, return the default item which just has the rawdata
            return item

        if len(userassist_data) < self._userassist_size:
            return item

        userassist_layer_name = self.context.memory.free_layer_name("userassist_buffer")
        buffer = BufferDataLayer(self.context, self._config_path, userassist_layer_name, userassist_data)
        self.context.add_layer(buffer)
        userassist_obj = self.context.object(
            symbol = self._reg_table_name + constants.BANG + self._userassist_type_name,
            layer_name = userassist_layer_name,
            offset = 0)

        if self._win7:
            item["id"] = renderers.NotApplicableValue()
            item["count"] = int(userassist_obj.Count)

            seconds = (userassist_obj.FocusTime + 500) / 1000.0
            time = datetime.timedelta(seconds = seconds) if seconds > 0 else userassist_obj.FocusTime
            item["focus"] = int(userassist_obj.FocusCount)
            item["time"] = str(time)

        else:
            item["id"] = int(userassist_obj.ID)
            item["count"] = int(userassist_obj.CountStartingAtFive
                                if userassist_obj.CountStartingAtFive < 5
                                else userassist_obj.CountStartingAtFive - 5)
            item["focus"] = renderers.NotApplicableValue()
            item["time"] = renderers.NotApplicableValue()

        item["lastupdated"] = utility.wintime_to_datetime(userassist_obj.LastUpdated.QuadPart)

        return item

    def _determine_userassist_type(self) -> None:
        """Determine the userassist type and generate a context.Module depending on the OS version"""

        if self._win7 is True:
            self._userassist_type_name = "_VOL_USERASSIST_TYPES_7"
        elif self._win7 is False:
            self._userassist_type_name = "_VOL_USERASSIST_TYPES_XP"

        self._userassist_size = self.context.symbol_space.get_type(
            self._reg_table_name + constants.BANG + self._userassist_type_name).size

    def _win7_or_later(self) -> bool:
        # TODO: change this if there is a better way of determining the OS version
        # _KUSER_SHARED_DATA.CookiePad is in Windows 6.1 (Win7) and later
        return self.context.symbol_space.get_type(
            self.config['nt_symbols'] + constants.BANG + "_KUSER_SHARED_DATA").has_member('CookiePad')

    def list_userassist(self, hive: RegistryHive) -> typing.Generator:
        """Generate userassist data for a registry hive."""

        hive_name = hive.hive.cast(self.config["nt_symbols"] + constants.BANG + "_CMHIVE").get_name()

        if self._win7 is None:
            self._win7 = self._win7_or_later()
            self._determine_userassist_type()

        userassist_node_path = hive.get_key("software\\microsoft\\windows\\currentversion\\explorer\\userassist",
                                            return_list = True)

        if not userassist_node_path:
            vollog.warning("list_userassist did not find a valid node_path (or None)")
            raise StopIteration

        userassist_node = userassist_node_path[-1]
        # iterate through the GUIDs under the userassist key
        for guidkey in userassist_node.get_subkeys():
            # each guid key should have a Count key in it
            for countkey in guidkey.get_subkeys():
                countkey_path = countkey.get_key_path()
                countkey_last_write_time = utility.wintime_to_datetime(countkey.LastWriteTime.QuadPart)

                # output the parent Count key
                result = (0,
                          (renderers.format_hints.Hex(hive.hive_offset),
                           hive_name,
                           countkey_path,
                           countkey_last_write_time,
                           "Key",
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue(),
                           renderers.NotApplicableValue()))
                yield result

                # output any subkeys under Count
                for subkey in countkey.get_subkeys():

                    subkey_name = subkey.get_name()
                    result = (1, (renderers.format_hints.Hex(hive.hive_offset),
                                  hive_name,
                                  countkey_path,
                                  countkey_last_write_time,
                                  "Subkey",
                                  subkey_name,
                                  renderers.NotApplicableValue(),
                                  renderers.NotApplicableValue(),
                                  renderers.NotApplicableValue(),
                                  renderers.NotApplicableValue(),
                                  renderers.NotApplicableValue(),
                                  renderers.NotApplicableValue(),))
                    yield result

                # output any values under Count
                for value in countkey.get_values():

                    value_name = value.get_name()
                    try:
                        value_name = codecs.encode(value_name, "rot_13")
                    except UnicodeDecodeError:
                        pass

                    if self._win7:
                        guid = value_name.split("\\")[0]
                        if guid in folder_guids:
                            value_name = value_name.replace(guid, folder_guids[guid])

                    userassist_data_dict = self.parse_userassist_data(value)
                    result = (1, (renderers.format_hints.Hex(hive.hive_offset),
                                  hive_name,
                                  countkey_path,
                                  countkey_last_write_time,
                                  "Value",
                                  value_name,
                                  userassist_data_dict["id"],
                                  userassist_data_dict["count"],
                                  userassist_data_dict["focus"],
                                  userassist_data_dict["time"],
                                  userassist_data_dict["lastupdated"],
                                  format_hints.HexBytes(userassist_data_dict["rawdata"]),))
                    yield result

    def _generator(self):

        # get all the user hive offsets or use the one specified
        if self.config.get('offset', None) is None:
            try:
                import volatility.plugins.windows.hivelist as hivelist
                plugin_config_path = self.make_subconfig(primary = self.config['primary'],
                                                         nt_symbols = self.config['nt_symbols'],
                                                         filter = "ntuser.dat")
                plugin = hivelist.HiveList(self.context, plugin_config_path)
                hive_offsets = [hive.vol.offset for hive in plugin.list_hives()]
            except:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")
        else:
            hive_offsets = [self.config['offset']]

        self._reg_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                       self._config_path,
                                                                       'windows',
                                                                       'registry')

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = self.make_subconfig(hive_offset = hive_offset,
                                                  base_layer = self.config['primary'],
                                                  nt_symbols = self.config['nt_symbols'])

            hive_name = None
            try:
                hive = RegistryHive(self.context, reg_config_path, name = 'hive' + hex(hive_offset))
                hive_name = hive.hive.cast(self.config["nt_symbols"] + constants.BANG + "_CMHIVE").get_name()
                self.context.memory.add_layer(hive)
                yield from self.list_userassist(hive)
                break
            except exceptions.PagedInvalidAddressException as excp:
                vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
            except KeyError:
                vollog.debug("Key '{}' not found in Hive at offset {}.".format(
                    "software\\microsoft\\windows\\currentversion\\explorer\\userassist", hex(hive_offset)))

            # yield UnreadableValues when an exception occurs for a given hive_offset
            result = (0,
                      (renderers.format_hints.Hex(hive_offset),
                       hive_name if hive_name else renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue(),
                       renderers.UnreadableValue()))
            yield result

    def run(self):

        return renderers.TreeGrid([("Hive Offset", renderers.format_hints.Hex),
                                   ("Hive Name", str),
                                   ("Path", str),
                                   ("Last Write Time", datetime.datetime),
                                   ("Type", str),
                                   ("Name", str),
                                   ("ID", int),
                                   ("Count", int),
                                   ("Focus Count", int),
                                   ("Time Focused", str),
                                   ("Last Updated", datetime.datetime),
                                   ("Raw Data", format_hints.HexBytes)],
                                  self._generator())
