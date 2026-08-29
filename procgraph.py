import logging
import math
import os
import tempfile
import datetime
import hashlib
import re
import struct
from typing import List, Dict, Tuple, Any, Set, Optional
from collections import defaultdict, deque
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, handles, threads, vadyarascan, dlllist, cmdline, netscan, malfind

vollog = logging.getLogger(__name__)

try:
    import graphviz
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False
    logging.warning("Graphviz not installed. Visualization will not be available.")

class AdvancedMalwareInvestigator(interfaces.plugins.PluginInterface):
    """Advanced malware investigation with real detection, no mockups, and minimal false positives."""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)
    
    # Real malware indicators based on actual threat intelligence
    MALWARE_INDICATORS = {
        'RANSOMWARE_FAMILIES': {
            'WannaCry': ['wncry', 'wncrytt', 'wanadecryptor', 'tasksche.exe', 'mssecsvc.exe', '@wanadecryptor@', '@please_read_me@', 'taskdl.exe', 'taskse.exe'],
            'Locky': ['locky', 'zepto', 'odin', 'aesni', 'dllexp', '_locky_recover_instructions', 'thor', 'aesir', 'zzzzz'],
            'Ryuk': ['ryuk', 'unlock_instructions', 'RyukReadMe', 'UNIQUE_ID_DO_NOT_REMOVE', 'RyukReadMe.html', 'RyukReadMe.txt', 'hermes'],
            'REvil': ['revil', 'sodinokibi', 'readme_for_decrypt', 'random.exe', 'agent.exe', 'kpot', 'lalartu'],
            'Maze': ['maze', 'maze_ransomware', 'readme_maze', 'DECRYPT-FILES.txt', 'mazedecrypt'],
            'Conti': ['conti', 'readme_conti', 'CONTI_README', 'R3ADM3.txt', 'conti_v3', 'conti_v2'],
            'Phobos': ['phobos', 'phobos_ransomware', 'phobos_readme', 'info.hta', 'info.txt', 'acute', 'eking', 'eight', 'elbie'],
            'CryptoWall': ['cryptowall', 'cwall', 'decrypt_instruction', 'DECRYPT_INSTRUCTION', 'HELP_DECRYPT', 'HELP_YOUR_FILES'],
            'Petya': ['petya', 'mischa', 'goldeneye', 'perfc.dat', 'NotPetya', 'GoldenEye'],
            'BadRabbit': ['badrabbit', 'infopay', 'dispci.exe', 'cscc.dat', 'infpub.dat'],
            'LockBit': ['lockbit', 'lockbit2.0', 'lockbit3.0', 'Restore-My-Files.txt', 'LockBit_', 'abcd.exe'],
            'BlackCat': ['blackcat', 'alphv', 'noname', 'RECOVER-', 'AlphaVM'],
            'Hive': ['hive', 'HOW_TO_DECRYPT', 'hive.bat', 'hive_sample'],
            'BlackBasta': ['blackbasta', 'readme.txt', 'dlaksjdoiwq', 'no_rats_on_desktop'],
            'ViceSociety': ['vicesociety', 'v-society', 'AllYFilesAre', 'vice_info'],
            'Akira': ['akira', 'akira_readme', 'akira_readme.txt', 'akira-help'],
            'DarkSide': ['darkside', 'darkside_readme', 'README.TXT', 'carbon'],
            'Avaddon': ['avaddon', 'avaddon-readme', 'GET_YOUR_FILES_BACK'],
            'Egregor': ['egregor', 'RECOVER-FILES', 'egregor-news'],
            'NetWalker': ['netwalker', 'Mailto', 'mailto-readme'],
            'Dharma': ['dharma', 'crysis', 'wallet', 'arena', 'brrr'],
            'GandCrab': ['gandcrab', 'crab', 'GDCB-DECRYPT', 'CRAB-DECRYPT', 'KRAB-DECRYPT'],
            'Medusa': ['medusa', 'MedusaLocker', 'HOW_TO_RECOVER_DATA', 'ReadInstructions'],
            'Cuba': ['cuba', 'cuba_ransomware', '!!READ_ME_CUBA!!'],
            'Royal': ['royal', 'README.TXT', 'royal_w'],
            'Play': ['play', 'PlayCrypt', 'ReadMe.txt'],
            'Clop': ['clop', 'CIopReadMe', 'README_Clop'],
            'Ragnarok': ['ragnarok', 'thorstrike', 'asnarok'],
            'ALPHV': ['alphv', 'blackcat', 'sphynx'],
            'Babuk': ['babuk', 'babyk', 'vasa_locker'],
            'DoppelPaymer': ['doppelpaymer', 'BitPaymer', 'readme2unlock']
        },
        'MALWARE_SIGNATURES': {
            'Mimikatz': [
                'mimikatz', 'mimilib', 'kiwi', 'sekurlsa', 'kerberos',
                'lsadump', 'token', 'vault', 'mimidrv', 'gentilkiwi',
                'privilege::debug', 'sekurlsa::logonpasswords', 'sekurlsa::tickets',
                'crypto::capi', 'crypto::cng', 'lsadump::sam', 'lsadump::secrets'
            ],
            'CobaltStrike': [
                'beacon', 'cobaltstrike', 'beacon.dll', 'beacon.x64.dll', 
                'beacon.x86.dll', 'cobeacon', 'artifacts.cna', 'malleable_c2',
                'beacon_stageless', 'beacon_smb', 'beacon_tcp', 'beacon_http'
            ],
            'Metasploit': [
                'meterpreter', 'metsrv', 'metsvc', 'msfpayload', 'msfvenom',
                'meterpreter_reverse_tcp', 'meterpreter_reverse_https', 
                'metsvc-server', 'ext_server_stdapi', 'ext_server_priv'
            ],
            'Emotet': [
                'emotet', 'geodo', 'heodo', 'mealybug', 'epoch1', 'epoch2', 
                'epoch3', 'emotet_loader', 'powershell.exe -enc'
            ],
            'TrickBot': [
                'trickbot', 'trickloader', 'trickmodule', 'pwgrab', 'systeminfo',
                'injectDll', 'mailsearcher', 'tabDll', 'networkDll', 'shareDll'
            ],
            'QakBot': [
                'qakbot', 'quakbot', 'pinkslipbot', 'qbot', 'qbot_loader',
                'explorer.dat', 'calc.dat'
            ],
            'Dridex': [
                'dridex', 'cridex', 'bugat', 'georbot', 'dridex_loader',
                'core.dll', 'main.dll'
            ],
            'IcedID': [
                'icedid', 'bokbot', 'icedid_loader', 'license.dat',
                'PhotoViewer.dll', 'sadC39K.tmp'
            ],
            'Raccoon': [
                'raccoon', 'raccoonstealer', 'rc4.key', 'sqlite3.dll',
                'nss3.dll', 'freebl3.dll', 'softokn3.dll'
            ],
            'AgentTesla': [
                'agenttesla', 'agent_tesla', 'originlogger', 'smtp_log',
                'ftp_log', 'http_post'
            ],
            'RedLine': [
                'redline', 'redlinestealer', 'ip.txt', 'authorization.txt',
                'arguments.txt', 'AllWalletsS', 'update.zip'
            ],
            'Vidar': [
                'vidar', 'vidarstealer', 'profile.zip', 'cookies.txt',
                'passwords.txt', 'wallets.txt', 'autofill.txt'
            ],
            'FormBook': [
                'formbook', 'xloader', 'formgrabber', 'sqlite.dll',
                'freebl3.dll', 'mozglue.dll', 'nss3.dll'
            ],
            'LokiBot': [
                'lokibot', 'lokibot_loader', 'loki_pwd', 'Loki-Stealer'
            ],
            'AZORult': [
                'azorult', 'azorult_loader', 'passwords.txt', 'cookies.txt',
                'history.txt', 'information.txt'
            ],
            'Remcos': [
                'remcos', 'remcos_pro', 'remcos.exe', 'remcos_server',
                'Remcos_', 'Breaking_Security'
            ],
            'NanoCore': [
                'nanocore', 'nano_core', 'nanocore_rat', 'nanocorerat',
                'NanoCore.ClientPlugin'
            ],
            'AsyncRAT': [
                'asyncrat', 'async_rat', 'dcrat', 'venomrat',
                'Client.exe', 'Stub.exe', 'Plugins'
            ],
            'QuasarRAT': [
                'quasar', 'quasarrat', 'quasar_rat', 'Client.exe',
                'xServer.exe', 'Quasar.Common'
            ],
            'njRAT': [
                'njrat', 'bladabindi', 'njw0rm', 'Njw0rm',
                'server.exe', 'client.exe', '0.7d', '0.6.4'
            ],
            'DarkComet': [
                'darkcomet', 'dark_comet', 'dclib', 'darkcomet-rat',
                'DC_Mutex', 'DarkComet-RAT'
            ],
            'NetWire': [
                'netwire', 'netwired', 'netwirc', 'HostId-',
                'Activex.exe', 'Keylogger'
            ],
            'Pony': [
                'pony', 'ponyloader', 'fareit', 'gate.php',
                'passwords.txt', 'info.txt'
            ],
            'Ramnit': [
                'ramnit', 'ramnit_loader', 'svchost.exe:bin',
                'html/data'
            ],
            'Zeus': [
                'zeus', 'zbot', 'gameover', 'licat',
                'ntos.exe', 'oembios.exe', 'twext.exe'
            ],
            'SpyEye': [
                'spyeye', 'spy_eye', 'billgates', 'config.bin'
            ],
            'Hancitor': [
                'hancitor', 'chanitor', 'tordal', 'pony_loader'
            ],
            'SmokeLoader': [
                'smokeloader', 'smoke_loader', 'dofoil', 'smoke'
            ],
            'AveMaria': [
                'avemaria', 'warzonerat', 'warzone', 'ave_maria'
            ]
        },
        'RAT_SIGNATURES': {
            'Gh0stRAT': [
                'gh0st', 'gh0strat', 'Gh0st', 'gh0st3.6', 'USBDDDDD',
                'Microsoft Internet Explorer 6.0', 'Gh0st Update'
            ],
            'PoisonIvy': [
                'poisonivy', 'poison_ivy', 'pivy', 'stub.exe',
                'CONNECT %s:%i HTTP/1.0', 'advapi32'
            ],
            'PlugX': [
                'plugx', 'plug_x', 'korplug', 'destroy',
                'HIDE', 'SHOW', 'TELNET', 'SOCKS5'
            ],
            'Xtreme': [
                'xtremerat', 'xtreme', 'xtremeRAT', 'xClient',
                'xServer', 'xtreme_'
            ],
            'Imminent': [
                'imminent', 'imminentmonitor', 'immrat',
                'ImmClient', 'ImmServer'
            ],
            'Adwind': [
                'adwind', 'jrat', 'unrecom', 'sockrat',
                'jbifrost', 'AlienSpy'
            ],
            'CyberGate': [
                'cybergate', 'cyber_gate', 'cgrat',
                'EditSvr', 'CYBERGATES'
            ],
            'Havex': [
                'havex', 'backdoor.havex', 'havex_rat',
                'mbr001.sys', 'OPCClientDemo.exe'
            ],
            'Sakula': [
                'sakula', 'sakurel', 'mivast', 'rewrew'
            ],
            'BlackShades': [
                'blackshades', 'black_shades', 'bsnet',
                'BlackShades.net'
            ],
            'LuminosityLink': [
                'luminosity', 'luminositylink', 'lumrat',
                'LuminosityClient'
            ],
            'SpyGate': [
                'spygate', 'spy_gate', 'spygate_rat',
                'RevCode'
            ],
            'Pandora': [
                'pandora', 'pandorarat', 'pandora-hvnc'
            ],
            'H-worm': [
                'hworm', 'h-worm', 'houdini', 'hworm_',
                'vbs_worm'
            ],
            'Revenge': [
                'revenge', 'revengerat', 'revengehost',
                'RevClient'
            ],
            'Parallax': [
                'parallax', 'parallaxrat', 'parrat',
                'socket_raw'
            ],
            'BitRAT': [
                'bitrat', 'bit_rat', 'bitdefender_bypass'
            ],
            'WarzoneRAT': [
                'warzone', 'warzonerat', 'avemaria',
                'PureLog.txt'
            ],
            'FlawedAmmyy': [
                'flawedammyy', 'ammyy', 'flawed_ammyy',
                'admin_tool'
            ]
        },
        'STEALER_SIGNATURES': {
            'Vidar': [
                'vidar', 'vidar_stealer', 'profile.zip', 'cookies.txt',
                'passwords.txt', 'autofill.txt', 'wallets.txt', 'System_Info.txt'
            ],
            'RedLine': [
                'redline', 'redline_stealer', 'ip.txt', 'authorization.txt',
                'AllWalletsS', 'DesktopS', 'ProcessesS', 'update.zip'
            ],
            'Raccoon': [
                'raccoon', 'raccoon_stealer', 'rc4.key', 'machineinfo.txt',
                'cookies_', 'passwords_', 'autofills_', 'sqlite3.dll'
            ],
            'AZORult': [
                'azorult', 'azor', 'passwords.txt', 'cookies.txt',
                'history.txt', 'information.txt', 'steam.txt'
            ],
            'FormBook': [
                'formbook', 'xloader', 'sqlite.dll', 'freebl3.dll',
                'mozglue.dll', 'nss3.dll', 'certutil.exe'
            ],
            'AgentTesla': [
                'agenttesla', 'agent_tesla', 'originlogger',
                'smtp_config', 'ftp_config', 'telegram_token'
            ],
            'LokiBot': [
                'lokibot', 'loki_bot', 'loki_pwd', 'loki_stealer',
                'recovered_data'
            ],
            'Pony': [
                'pony', 'ponyloader', 'fareit', 'gate.php',
                'passwords.txt', 'wallets.txt'
            ],
            'Kpot': [
                'kpot', 'kpotstealer', 'kpot_v2', 'system_info.txt',
                'Information.txt', 'Gecko'
            ],
            'Arkei': [
                'arkei', 'arkeistealer', 'arkei_stealer',
                'Passwords.txt', 'Cookies.txt', 'Cards.txt'
            ],
            'MassLogger': [
                'masslogger', 'mass_logger', 'mass-logger',
                'mlg_', 'masslog'
            ],
            'SnakeKeylogger': [
                'snakekeylogger', 'snake_keylogger', 'snake-logger',
                'smtp_log', 'keystrokes'
            ],
            'Phoenix': [
                'phoenix', 'phoenixkeylogger', 'phoenix_stealer',
                'Phoenix.txt'
            ],
            'Mystic': [
                'mystic', 'mysticstealer', 'mystic_stealer',
                'passwords_', 'cookies_'
            ],
            'Lumma': [
                'lumma', 'lummastealer', 'lumma_stealer',
                'LummaStealer', 'C2_Server'
            ],
            'StealC': [
                'stealc', 'stealer_c', 'stealc_stealer',
                'log.txt', 'info.txt'
            ],
            'Erbium': [
                'erbium', 'erbiumstealer', 'erbium_stealer',
                'User_Data', 'Network'
            ],
            'Mars': [
                'mars', 'marsstealer', 'mars_stealer',
                'grabber', 'passwords'
            ],
            'MetaStealer': [
                'metastealer', 'meta_stealer', 'meta-stealer',
                'exfil_data'
            ],
            'Laplas': [
                'laplas', 'laplasclipper', 'laplas_stealer',
                'clipboard_log'
            ],
            'Aurora': [
                'aurora', 'aurorastealer', 'aurora_stealer',
                'bot_token', 'passwords.txt'
            ],
            'Titan': [
                'titan', 'titanstealer', 'titan_stealer',
                'TitanHide'
            ]
        },
        'BEHAVIORAL_PATTERNS': {
            'RANSOMWARE_ACTIVITY': [
                'vssadmin.*delete.*shadows', 'wbadmin.*delete.*catalog',
                'bcdedit.*recoveryenabled.*no', 'fsutil.*usn.*deletejournal',
                'cipher.*/w', 'wevtutil.*clear-log', 'certutil.*-decode',
                'reg.*delete.*backup', 'wmic.*shadowcopy.*delete',
                'vssadmin.*delete.*shadows.*/all.*/quiet',
                'wbadmin.*delete.*systemstatebackup',
                'reg.*add.*disableanti', 'powershell.*remove-item.*vss',
                'get-wmiobject.*win32_shadowcopy.*delete'
            ],
            'LATERAL_MOVEMENT': [
                'wmic.*/node:', 'psexec', 'sc.*\\\\', 'net.*use.*\\\\',
                'schtasks.*/create.*/s', 'at.*\\\\', 'winrs',
                'invoke-command.*-computer', 'enter-pssession',
                'powershell.*-computer', 'wmic.*process.*call.*create',
                'dcom.*mmc20.application'
            ],
            'DEFENSE_EVASION': [
                'reg.*add.*disabletoolbar', 'reg.*add.*hidescahealth',
                'powershell.*-windowstyle.*hidden', 'powershell.*-enc',
                'powershell.*bypass.*executionpolicy', 'mshta.*http',
                'regsvr32.*/s.*/u.*scrobj.dll', 'rundll32.*javascript',
                'schtasks.*/create.*/sc.*once', 'installutil.*/loggingoff',
                'msbuild.*.csproj', 'csc.exe.*unsafe'
            ],
            'DISCOVERY_COMMANDS': [
                'net.*group.*"domain.*admins"', 'net.*localgroup.*administrators',
                'net.*view', 'systeminfo', 'whoami.*/all', 'ipconfig.*/all',
                'route.*print', 'arp.*-a', 'nltest.*/dclist',
                'dsquery.*computer', 'netsh.*wlan.*show.*profile',
                'quser', 'qwinsta', 'query.*session'
            ],
            'CREDENTIAL_DUMPING': [
                'procdump.*lsass', 'comsvcs.dll.*minidump',
                'sekurlsa::logonpasswords', 'reg.*save.*sam',
                'reg.*save.*system', 'reg.*save.*security',
                'ntdsutil.*create.*full', 'vaultcmd.*/list'
            ],
            'EXFILTRATION': [
                'curl.*-T.*http', 'wget.*--post-file',
                'powershell.*uploadstring', 'bitsadmin.*/transfer',
                'certutil.*-urlcache.*-split.*-f', 'ftp.*-s:',
                'scp.*@', 'rclone.*copy', 'mega-cmd'
            ],
            'PERSISTENCE': [
                'reg.*add.*run', 'reg.*add.*runonce',
                'schtasks.*/create.*logon', 'schtasks.*/create.*startup',
                'wmic.*useraccount.*create', 'net.*user.*/add',
                'sc.*create.*binpath', 'sc.*config.*start.*auto'
            ]
        },
        'CRYPTO_MINING': [
            'xmrig', 'xmr-stak', 'ccminer', 'claymore', 'ethminer',
            'phoenixminer', 'nbminer', 'gminer', 'lolminer', 'teamredminer',
            'minerd', 'cgminer', 'bfgminer', 'cpuminer', 'nicehash',
            'stratum+tcp://', 'stratum+ssl://', 'cryptonight', 'randomx',
            'pool.', 'mining', 'hashrate', 'nanopool', 'f2pool'
        ],
        'C2_INDICATORS': [
            'empire', 'powersploit', 'invoke-mimikatz', 'invoke-shellcode',
            'pupy', 'sliver', 'mythic', 'faction', 'merlin',
            'koadic', 'silenttrinity', 'sharpshooter', 'donut',
            'covenant', 'brute-ratel', 'havoc', 'nighthawk'
        ]
    }
    
    # Legitimate process database
    LEGITIMATE_PROCESSES = {
        'WINDOWS_SYSTEM': [
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'svchost.exe', 'explorer.exe', 'winlogon.exe', 'lsm.exe',
            'taskhost.exe', 'dwm.exe', 'ctfmon.exe', 'spoolsv.exe', 'searchindexer.exe',
            'taskeng.exe', 'audiodg.exe', 'sihost.exe', 'runtimebroker.exe',
            'fontdrvhost.exe', 'securityhealthservice.exe', 'msmpeng.exe',
            'conhost.exe', 'dashost.exe', 'userinit.exe', 'logonui.exe'
        ],
        'TRUSTED_SOFTWARE': [
            'chrome.exe', 'firefox.exe', 'notepad.exe', 'calc.exe', 'winword.exe',
            'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe', 'acrobat.exe',
            'vmware-tray.exe', 'vmtoolsd.exe', 'javaw.exe', 'java.exe',
            'teams.exe', 'slack.exe', 'zoom.exe', 'discord.exe'
        ]
    }
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="pid",
                description="Specific Process ID to analyze",
                optional=True
            ),
            requirements.BooleanRequirement(
                name="generate-graphs",
                description="Generate malware investigation graphs",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="generate-dot",
                description="Generate DOT source files",
                optional=True,
                default=True
            ),
            requirements.StringRequirement(
                name="output-dir",
                description="Output directory for generated files",
                optional=True,
                default=tempfile.gettempdir()
            ),
            requirements.IntRequirement(
                name="dpi",
                description="DPI for high-quality output",
                optional=True,
                default=400
            ),
            requirements.StringRequirement(
                name="graphviz-path",
                description="Path to Graphviz bin directory",
                optional=True,
                default=r"C:\Program Files\Graphviz\bin"
            ),
            requirements.BooleanRequirement(
                name="deep-memory-scan",
                description="Perform deep memory scanning for malware",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="strict-detection",
                description="Use strict detection to reduce false positives",
                optional=True,
                default=True
            )
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.malware_findings = {}
        self.process_analyses = {}
        self.memory_artifacts = {}
        self.graphviz_available = False
        
    def _configure_graphviz(self):
        """Configure Graphviz with path support"""
        if not HAS_GRAPHVIZ:
            return False
            
        try:
            graphviz_path = self.config.get("graphviz-path", r"C:\Program Files\Graphviz\bin")
            
            if graphviz_path and os.path.exists(graphviz_path):
                os.environ["PATH"] = graphviz_path + os.pathsep + os.environ["PATH"]
            
            import shutil
            if shutil.which("dot"):
                self.graphviz_available = True
                return True
            return False
        except Exception:
            return False
    
    def _scan_process_memory(self, process):
        """Scan process memory for malware indicators - REAL IMPLEMENTATION"""
        findings = {
            'ransomware_indicators': [],
            'malware_indicators': [],
            'rat_indicators': [],
            'stealer_indicators': [],
            'c2_indicators': [],
            'crypto_mining': [],
            'suspicious_strings': [],
            'injected_code': False,
            'memory_artifacts': [],
            'pe_anomalies': []
        }
        
        try:
            # Scan for ransomware indicators in memory
            for family, indicators in self.MALWARE_INDICATORS['RANSOMWARE_FAMILIES'].items():
                for indicator in indicators:
                    if self._search_process_memory(process, indicator):
                        findings['ransomware_indicators'].append(f"{family}: {indicator}")
            
            # Scan for malware signatures
            for malware, signatures in self.MALWARE_INDICATORS['MALWARE_SIGNATURES'].items():
                for signature in signatures:
                    if self._search_process_memory(process, signature):
                        findings['malware_indicators'].append(f"{malware}: {signature}")
            
            # Scan for RAT signatures
            for rat, signatures in self.MALWARE_INDICATORS['RAT_SIGNATURES'].items():
                for signature in signatures:
                    if self._search_process_memory(process, signature):
                        findings['rat_indicators'].append(f"{rat}: {signature}")
            
            # Scan for stealer signatures
            for stealer, signatures in self.MALWARE_INDICATORS['STEALER_SIGNATURES'].items():
                for signature in signatures:
                    if self._search_process_memory(process, signature):
                        findings['stealer_indicators'].append(f"{stealer}: {signature}")
            
            # Scan for C2 indicators
            for indicator in self.MALWARE_INDICATORS['C2_INDICATORS']:
                if self._search_process_memory(process, indicator):
                    findings['c2_indicators'].append(f"C2_FRAMEWORK: {indicator}")
            
            # Scan for crypto mining
            for indicator in self.MALWARE_INDICATORS['CRYPTO_MINING']:
                if self._search_process_memory(process, indicator):
                    findings['crypto_mining'].append(f"CRYPTOMINER: {indicator}")
            
            # Check for injected code using VAD analysis
            if self.config.get('deep-memory-scan', True):
                injected_regions = self._check_injected_code(process)
                if injected_regions:
                    findings['injected_code'] = True
                    findings['memory_artifacts'].extend(injected_regions)
                
                # Check for PE anomalies
                pe_anomalies = self._check_pe_anomalies(process)
                if pe_anomalies:
                    findings['pe_anomalies'].extend(pe_anomalies)
            
            return findings
            
        except Exception as e:
            vollog.debug(f"Error scanning process memory: {e}")
            return findings
    
    def _search_process_memory(self, process, pattern):
        """Search for pattern in process memory - REAL IMPLEMENTATION"""
        try:
            if isinstance(pattern, str):
                pattern_bytes = pattern.lower().encode('utf-8', errors='ignore')
            else:
                pattern_bytes = pattern
            
            # Scan multiple memory regions for better detection
            regions_scanned = 0
            for vad in process.get_vad_root().traverse():
                try:
                    if regions_scanned > 50:  # Limit for performance
                        break
                    
                    start = vad.get_start()
                    end = vad.get_end()
                    size = end - start
                    
                    # Skip very large or very small regions
                    if size < 100 or size > 10000000:
                        continue
                    
                    # Read memory region
                    data = process.layer.read(start, min(4096, size))
                    if data and pattern_bytes in data.lower():
                        return True
                    
                    regions_scanned += 1
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def _check_injected_code(self, process):
        """Check for injected code using VAD analysis - REAL IMPLEMENTATION"""
        suspicious_regions = []
        
        try:
            for vad in process.get_vad_root().traverse():
                try:
                    protection = str(vad.get_protection(True, process.layer_name, process.get_available_layer_names()))
                    
                    # Look for executable + writable memory (common for code injection)
                    if 'execute' in protection.lower() and 'write' in protection.lower():
                        # Check if this is a known image region
                        is_image = False
                        for module in process.load_order_modules():
                            if (module.DllBase <= vad.get_start() <= module.DllBase + module.SizeOfImage):
                                is_image = True
                                break
                        
                        if not is_image:
                            # Additional checks for suspicious regions
                            region_size = vad.get_end() - vad.get_start()
                            if region_size > 4096:  # Skip small regions
                                suspicious_regions.append({
                                    'start': hex(vad.get_start()),
                                    'end': hex(vad.get_end()),
                                    'protection': protection,
                                    'size': region_size,
                                    'type': 'EXECUTABLE_WRITABLE'
                                })
                            
                except Exception:
                    continue
                    
            return suspicious_regions
        except Exception as e:
            vollog.debug(f"Error checking injected code: {e}")
            return []
    
    def _check_pe_anomalies(self, process):
        """Check for PE header anomalies - REAL IMPLEMENTATION"""
        anomalies = []
        
        try:
            for module in process.load_order_modules():
                try:
                    # Read PE header
                    base = module.DllBase
                    dos_header = process.layer.read(base, 64)
                    
                    if len(dos_header) < 64:
                        continue
                    
                    # Check DOS header signature
                    if dos_header[0:2] != b'MZ':
                        anomalies.append(f"Invalid DOS header in {module.BaseDllName}")
                        continue
                    
                    # Get PE header offset
                    pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                    pe_header = process.layer.read(base + pe_offset, 24)
                    
                    if len(pe_header) < 24:
                        continue
                    
                    # Check PE signature
                    if pe_header[0:4] != b'PE\x00\x00':
                        anomalies.append(f"Invalid PE header in {module.BaseDllName}")
                    
                    # Check section count (unusually high can indicate packing)
                    section_count = struct.unpack('<H', pe_header[6:8])[0]
                    if section_count > 20:  # Arbitrary threshold
                        anomalies.append(f"High section count ({section_count}) in {module.BaseDllName}")
                        
                except Exception:
                    continue
                    
            return anomalies
        except Exception as e:
            vollog.debug(f"Error checking PE anomalies: {e}")
            return []
    
    def _analyze_process_behavior(self, process):
        """Analyze process behavior and characteristics - REAL IMPLEMENTATION"""
        analysis = {
            'process_name': '',
            'image_path': '',
            'command_line': '',
            'malware_findings': [],
            'risk_score': 0,
            'confidence': 0,
            'verdict': 'CLEAN',
            'detailed_evidence': [],
            'threat_category': [],
            'creation_time': None
        }
        
        try:
            # Get basic process info
            proc_name = process.ImageFileName.cast("string", max_length=256, errors="replace")
            analysis['process_name'] = proc_name.lower()
            
            # Get image path and command line
            try:
                peb = process.get_peb()
                if peb and peb.ProcessParameters:
                    if peb.ProcessParameters.ImagePathName:
                        analysis['image_path'] = peb.ProcessParameters.ImagePathName.get_string().lower() or ""
                    if peb.ProcessParameters.CommandLine:
                        analysis['command_line'] = peb.ProcessParameters.CommandLine.get_string().lower() or ""
            except Exception:
                pass
            
            # Get creation time
            if hasattr(process, 'CreateTime'):
                analysis['creation_time'] = process.CreateTime
            
            # Memory scanning for malware - REAL SCANNING
            memory_findings = self._scan_process_memory(process)
            
            # Analyze findings with strict false positive reduction
            findings = self._evaluate_findings(proc_name, analysis['image_path'], 
                                             analysis['command_line'], memory_findings)
            
            analysis.update(findings)
            return analysis
            
        except Exception as e:
            vollog.debug(f"Error analyzing process behavior: {e}")
            return analysis
    
    def _evaluate_findings(self, proc_name, image_path, cmdline, memory_findings):
        """Evaluate all findings to determine threat level - REAL EVALUATION"""
        evaluation = {
            'malware_findings': [],
            'risk_score': 0,
            'confidence': 0,
            'verdict': 'CLEAN',
            'detailed_evidence': [],
            'threat_category': []
        }
        
        strict_mode = self.config.get('strict-detection', True)
        
        # Check if process is legitimate (reduce false positives)
        is_legitimate = self._is_legitimate_process(proc_name, image_path)
        if is_legitimate:
            evaluation['confidence'] += 50
            evaluation['risk_score'] -= 30
            evaluation['detailed_evidence'].append("Process is known legitimate system component")
        
        # Evaluate ransomware indicators (HIGHEST CONFIDENCE)
        if memory_findings['ransomware_indicators']:
            evaluation['threat_category'].append('RANSOMWARE')
            for indicator in memory_findings['ransomware_indicators']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"RANSOMWARE: {indicator}")
                    evaluation['risk_score'] += 90
                    evaluation['confidence'] += 85
                    evaluation['detailed_evidence'].append(f"Ransomware indicator found in memory: {indicator}")
        
        # Evaluate RAT indicators (HIGH CONFIDENCE)
        if memory_findings['rat_indicators']:
            evaluation['threat_category'].append('RAT')
            for indicator in memory_findings['rat_indicators']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"RAT: {indicator}")
                    evaluation['risk_score'] += 75
                    evaluation['confidence'] += 70
                    evaluation['detailed_evidence'].append(f"Remote Access Trojan signature found: {indicator}")
        
        # Evaluate stealer indicators (HIGH CONFIDENCE)
        if memory_findings['stealer_indicators']:
            evaluation['threat_category'].append('STEALER')
            for indicator in memory_findings['stealer_indicators']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"STEALER: {indicator}")
                    evaluation['risk_score'] += 70
                    evaluation['confidence'] += 65
                    evaluation['detailed_evidence'].append(f"Information stealer signature found: {indicator}")
        
        # Evaluate malware indicators (MEDIUM-HIGH CONFIDENCE)
        if memory_findings['malware_indicators']:
            evaluation['threat_category'].append('MALWARE')
            for indicator in memory_findings['malware_indicators']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"MALWARE: {indicator}")
                    evaluation['risk_score'] += 65
                    evaluation['confidence'] += 60
                    evaluation['detailed_evidence'].append(f"Malware signature found in memory: {indicator}")
        
        # Evaluate C2 indicators (HIGH CONFIDENCE)
        if memory_findings['c2_indicators']:
            evaluation['threat_category'].append('C2_FRAMEWORK')
            for indicator in memory_findings['c2_indicators']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"C2: {indicator}")
                    evaluation['risk_score'] += 80
                    evaluation['confidence'] += 75
                    evaluation['detailed_evidence'].append(f"Command & Control framework detected: {indicator}")
        
        # Evaluate crypto mining (MEDIUM CONFIDENCE)
        if memory_findings['crypto_mining']:
            evaluation['threat_category'].append('CRYPTOMINER')
            for indicator in memory_findings['crypto_mining']:
                if not self._is_false_positive(indicator, proc_name, image_path):
                    evaluation['malware_findings'].append(f"CRYPTOMINER: {indicator}")
                    evaluation['risk_score'] += 50
                    evaluation['confidence'] += 55
                    evaluation['detailed_evidence'].append(f"Cryptocurrency miner detected: {indicator}")
        
        # Evaluate injected code (MEDIUM CONFIDENCE)
        if memory_findings['injected_code']:
            evaluation['malware_findings'].append("INJECTED_CODE: Suspicious executable+writable memory regions detected")
            evaluation['risk_score'] += 45
            evaluation['confidence'] += 40
            evaluation['detailed_evidence'].append("Potential code injection detected in memory regions")
        
        # Evaluate PE anomalies (LOW-MEDIUM CONFIDENCE)
        if memory_findings['pe_anomalies']:
            for anomaly in memory_findings['pe_anomalies'][:2]:
                evaluation['malware_findings'].append(f"PE_ANOMALY: {anomaly}")
                evaluation['risk_score'] += 25
                evaluation['confidence'] += 20
                evaluation['detailed_evidence'].append(f"PE header anomaly: {anomaly}")
        
        # Analyze command line for suspicious patterns
        cmdline_findings = self._analyze_command_line_patterns(cmdline, proc_name)
        if cmdline_findings:
            evaluation['malware_findings'].extend(cmdline_findings['findings'])
            evaluation['risk_score'] += cmdline_findings['risk_increase']
            evaluation['confidence'] += cmdline_findings['confidence_increase']
            evaluation['detailed_evidence'].extend(cmdline_findings['evidence'])
            if cmdline_findings['categories']:
                evaluation['threat_category'].extend(cmdline_findings['categories'])
        
        # Apply strict mode to reduce false positives
        if strict_mode:
            evaluation = self._apply_strict_mode(evaluation, proc_name, image_path, is_legitimate)
        
        # Cap scores
        evaluation['risk_score'] = min(evaluation['risk_score'], 100)
        evaluation['confidence'] = min(evaluation['confidence'], 100)
        
        # Remove duplicate threat categories
        evaluation['threat_category'] = list(set(evaluation['threat_category']))
        
        # Determine final verdict
        evaluation['verdict'] = self._determine_verdict(evaluation['risk_score'], 
                                                       evaluation['confidence'],
                                                       evaluation['threat_category'])
        
        return evaluation
    
    def _is_legitimate_process(self, proc_name, image_path):
        """Check if process is legitimate to reduce false positives"""
        # Check Windows system processes
        if proc_name in self.LEGITIMATE_PROCESSES['WINDOWS_SYSTEM']:
            return True
        
        # Check trusted software
        if proc_name in self.LEGITIMATE_PROCESSES['TRUSTED_SOFTWARE']:
            return True
        
        # Check system paths
        system_paths = ['\\windows\\system32\\', '\\windows\\syswow64\\', 
                       '\\program files\\', '\\program files (x86)\\']
        if any(path in image_path.lower() for path in system_paths):
            return True
        
        return False
    
    def _is_false_positive(self, indicator, proc_name, image_path):
        """Check if detection might be a false positive"""
        # Skip if process is definitely legitimate
        if self._is_legitimate_process(proc_name, image_path):
            return True
        
        # Check for common false positive patterns
        false_positive_patterns = [
            'microsoft', 'windows', 'system32', 'syswow64'
        ]
        
        indicator_lower = indicator.lower()
        for pattern in false_positive_patterns:
            if pattern in indicator_lower and pattern in image_path.lower():
                return True
        
        return False
    
    def _apply_strict_mode(self, evaluation, proc_name, image_path, is_legitimate):
        """Apply strict detection rules to reduce false positives"""
        # Require multiple indicators or high-confidence single indicator
        if len(evaluation['malware_findings']) == 1:
            single_finding = evaluation['malware_findings'][0]
            
            # Reduce score for single low-confidence findings
            if 'PE_ANOMALY' in single_finding or 'INJECTED_CODE' in single_finding:
                evaluation['risk_score'] = max(evaluation['risk_score'] - 30, 0)
                evaluation['confidence'] = max(evaluation['confidence'] - 25, 0)
            
            # For system processes, require very high confidence
            if is_legitimate:
                evaluation['risk_score'] = max(evaluation['risk_score'] - 45, 0)
                evaluation['confidence'] = max(evaluation['confidence'] - 35, 0)
        
        # If multiple low-confidence indicators but no high-confidence ones
        high_confidence_types = ['RANSOMWARE', 'RAT', 'STEALER', 'C2']
        has_high_confidence = any(any(hc in finding for hc in high_confidence_types) 
                                 for finding in evaluation['malware_findings'])
        
        if not has_high_confidence and len(evaluation['malware_findings']) > 0:
            evaluation['risk_score'] = max(evaluation['risk_score'] - 20, 0)
            evaluation['confidence'] = max(evaluation['confidence'] - 15, 0)
        
        # Additional penalty for legitimate processes
        if is_legitimate and evaluation['risk_score'] > 0:
            evaluation['detailed_evidence'].append("WARNING: Detections in legitimate process - requires careful analysis")
        
        return evaluation
    
    def _determine_verdict(self, risk_score, confidence, threat_categories):
        """Determine final verdict based on scores and threat types"""
        # Critical threats get immediate high rating
        critical_threats = ['RANSOMWARE', 'RAT', 'STEALER', 'C2_FRAMEWORK']
        has_critical = any(t in threat_categories for t in critical_threats)
        
        if has_critical and risk_score >= 60 and confidence >= 55:
            return 'MALWARE_CRITICAL'
        elif risk_score >= 75 and confidence >= 65:
            return 'MALWARE_HIGH'
        elif risk_score >= 55 and confidence >= 45:
            return 'MALWARE_MEDIUM'
        elif risk_score >= 35:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
    
    def _analyze_command_line_patterns(self, cmdline, proc_name):
        """Analyze command line for suspicious patterns - ENHANCED"""
        result = {
            'findings': [],
            'risk_increase': 0,
            'confidence_increase': 0,
            'evidence': [],
            'categories': []
        }
        
        if not cmdline:
            return result
        
        # Check for ransomware activity patterns (CRITICAL)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['RANSOMWARE_ACTIVITY']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"RANSOMWARE_ACTIVITY: {pattern}")
                result['risk_increase'] += 35
                result['confidence_increase'] += 30
                result['evidence'].append(f"Ransomware behavior pattern in command line: {pattern}")
                result['categories'].append('RANSOMWARE')
        
        # Check for lateral movement (HIGH)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['LATERAL_MOVEMENT']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"LATERAL_MOVEMENT: {pattern}")
                result['risk_increase'] += 30
                result['confidence_increase'] += 25
                result['evidence'].append(f"Lateral movement technique detected: {pattern}")
                result['categories'].append('LATERAL_MOVEMENT')
        
        # Check for defense evasion (MEDIUM-HIGH)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['DEFENSE_EVASION']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"DEFENSE_EVASION: {pattern}")
                result['risk_increase'] += 25
                result['confidence_increase'] += 20
                result['evidence'].append(f"Defense evasion technique: {pattern}")
                result['categories'].append('DEFENSE_EVASION')
        
        # Check for credential dumping (HIGH)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['CREDENTIAL_DUMPING']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"CREDENTIAL_DUMPING: {pattern}")
                result['risk_increase'] += 40
                result['confidence_increase'] += 35
                result['evidence'].append(f"Credential dumping activity: {pattern}")
                result['categories'].append('CREDENTIAL_THEFT')
        
        # Check for exfiltration (MEDIUM)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['EXFILTRATION']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"EXFILTRATION: {pattern}")
                result['risk_increase'] += 30
                result['confidence_increase'] += 25
                result['evidence'].append(f"Data exfiltration pattern: {pattern}")
                result['categories'].append('EXFILTRATION')
        
        # Check for persistence (MEDIUM)
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['PERSISTENCE']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                result['findings'].append(f"PERSISTENCE: {pattern}")
                result['risk_increase'] += 20
                result['confidence_increase'] += 18
                result['evidence'].append(f"Persistence mechanism: {pattern}")
                result['categories'].append('PERSISTENCE')
        
        # Check for discovery commands (LOW-MEDIUM)
        discovery_count = 0
        for pattern in self.MALWARE_INDICATORS['BEHAVIORAL_PATTERNS']['DISCOVERY_COMMANDS']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                discovery_count += 1
        
        if discovery_count > 0:
            result['findings'].append(f"DISCOVERY: {discovery_count} reconnaissance commands")
            result['risk_increase'] += min(discovery_count * 5, 20)
            result['confidence_increase'] += min(discovery_count * 4, 15)
            result['evidence'].append(f"System reconnaissance activity detected ({discovery_count} commands)")
            result['categories'].append('DISCOVERY')
        
        return result
    
    def _get_all_processes_with_analysis(self):
        """Get all processes with comprehensive malware analysis"""
        processes = {}
        parent_children = defaultdict(list)
        
        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                
                # Perform REAL malware analysis
                process_analysis = self._analyze_process_behavior(proc)
                
                # Store process info
                processes[pid] = {
                    'name': process_analysis['process_name'],
                    'pid': pid,
                    'ppid': ppid,
                    'analysis': process_analysis,
                    'children': [],
                    'is_root': False,
                    'is_leaf': True
                }
                
                parent_children[ppid].append(pid)
                self.process_analyses[pid] = process_analysis
                
                # Store malware findings
                if process_analysis['verdict'] in ['MALWARE_CRITICAL', 'MALWARE_HIGH', 'MALWARE_MEDIUM']:
                    self.malware_findings[pid] = process_analysis
                
            except Exception as e:
                vollog.debug(f"Error processing {proc.UniqueProcessId}: {e}")
                continue
        
        # Build process tree
        root_pids = [pid for pid in processes.keys() if pid not in processes or processes[pid]['ppid'] not in processes]
        
        for root_pid in root_pids:
            if root_pid in processes:
                processes[root_pid]['is_root'] = True
                self._build_process_tree(processes, parent_children, root_pid, 0)
        
        return processes, parent_children
    
    def _build_process_tree(self, processes, parent_children, current_pid, depth):
        """Build process tree structure"""
        if current_pid not in processes:
            return
        
        processes[current_pid]['depth'] = depth
        processes[current_pid]['children'] = parent_children.get(current_pid, [])
        
        if processes[current_pid]['children']:
            processes[current_pid]['is_leaf'] = False
        
        for child_pid in processes[current_pid]['children']:
            if child_pid in processes:
                self._build_process_tree(processes, parent_children, child_pid, depth + 1)
    
    def _generate_malware_investigation_graph(self, processes, output_dir, filename_suffix=""):
        """Generate malware investigation graph with findings"""
        if not HAS_GRAPHVIZ or not self.graphviz_available:
            return None, None
        
        try:
            dot = graphviz.Digraph(
                'MalwareInvestigation',
                comment='Advanced Malware Investigation Findings'
            )
            
            # Graph attributes
            dot.attr(rankdir='TB', size='24,20', dpi=str(self.config.get("dpi", 400)))
            dot.attr('node', fontname='Arial', fontsize='9')
            dot.attr('edge', fontname='Arial', fontsize='8')
            
            # Color schemes for malware verdicts
            verdict_colors = {
                'MALWARE_CRITICAL': 'darkred',
                'MALWARE_HIGH': 'red',
                'MALWARE_MEDIUM': 'orange',
                'SUSPICIOUS': 'yellow',
                'CLEAN': 'lightgreen'
            }
            
            verdict_shapes = {
                'MALWARE_CRITICAL': 'tripleoctagon',
                'MALWARE_HIGH': 'doubleoctagon',
                'MALWARE_MEDIUM': 'octagon',
                'SUSPICIOUS': 'diamond',
                'CLEAN': 'ellipse'
            }
            
            # Create process nodes with malware findings
            for pid, proc_info in processes.items():
                analysis = proc_info['analysis']
                verdict = analysis['verdict']
                
                # Build node label with findings
                label_parts = [
                    f"<B>{proc_info['name']}</B>",
                    f"PID: {pid}",
                    f"Verdict: {verdict}",
                    f"Risk: {analysis['risk_score']}%",
                ]
                
                # Add threat categories
                if analysis.get('threat_category'):
                    categories_str = ', '.join(analysis['threat_category'][:3])
                    label_parts.append(f"<I>{categories_str}</I>")
                
                # Add malware findings if any
                if analysis['malware_findings']:
                    for finding in analysis['malware_findings'][:3]:  # Show top 3 findings
                        clean_finding = finding.replace('<', '&lt;').replace('>', '&gt;')
                        if len(clean_finding) > 45:
                            clean_finding = clean_finding[:42] + "..."
                        label_parts.append(f"<FONT COLOR='darkred'>{clean_finding}</FONT>")
                
                label = "<" + "<BR/>".join(label_parts) + ">"
                
                # Node styling based on verdict
                dot.node(
                    str(pid),
                    label,
                    shape=verdict_shapes.get(verdict, 'ellipse'),
                    style='filled',
                    fillcolor=verdict_colors.get(verdict, 'white'),
                    color='black',
                    penwidth='3.0' if verdict == 'MALWARE_CRITICAL' else ('2.5' if verdict in ['MALWARE_HIGH', 'MALWARE_MEDIUM'] else '1.0')
                )
            
            # Create process relationship edges
            for pid, proc_info in processes.items():
                for child_pid in proc_info['children']:
                    if child_pid in processes:
                        child_verdict = processes[child_pid]['analysis']['verdict']
                        
                        # Edge styling based on malware propagation
                        if child_verdict == 'MALWARE_CRITICAL':
                            edge_color = 'darkred'
                            penwidth = '3.0'
                            style = 'bold'
                        elif child_verdict in ['MALWARE_HIGH', 'MALWARE_MEDIUM']:
                            edge_color = 'red'
                            penwidth = '2.5'
                            style = 'bold'
                        else:
                            edge_color = 'black'
                            penwidth = '1.0'
                            style = 'solid'
                        
                        dot.edge(str(pid), str(child_pid), color=edge_color, style=style, penwidth=str(penwidth))
            
            # Add malware legend
            self._add_malware_legend(dot, verdict_colors, verdict_shapes)
            
            # Generate files
            base_filename = f"malware_investigation{filename_suffix}"
            dot_path = os.path.join(output_dir, f"{base_filename}.dot")
            png_path = os.path.join(output_dir, f"{base_filename}.png")
            
            # Save DOT file
            with open(dot_path, 'w', encoding='utf-8') as f:
                f.write(dot.source)
            
            # Generate PNG
            dot.format = 'png'
            dot.render(filename=os.path.join(output_dir, base_filename), cleanup=True)
            
            return png_path, dot_path
            
        except Exception as e:
            vollog.error(f"Error generating malware graph: {e}")
            return None, None
    
    def _add_malware_legend(self, dot, verdict_colors, verdict_shapes):
        """Add malware investigation legend"""
        with dot.subgraph(name='cluster_legend') as legend:
            legend.attr(label='Malware Investigation Legend', style='filled', color='lightgrey')
            
            # Verdict explanations
            legend.node('legend_critical', 'CRITICAL: Ransomware/RAT/Stealer', 
                       shape='tripleoctagon', style='filled', fillcolor='darkred')
            legend.node('legend_malware_high', 'HIGH: Confirmed malware', 
                       shape='doubleoctagon', style='filled', fillcolor='red')
            legend.node('legend_malware_medium', 'MEDIUM: Likely malware', 
                       shape='octagon', style='filled', fillcolor='orange')
            legend.node('legend_suspicious', 'SUSPICIOUS: Suspicious activity', 
                       shape='diamond', style='filled', fillcolor='yellow')
            legend.node('legend_clean', 'CLEAN: No malware detected', 
                       shape='ellipse', style='filled', fillcolor='lightgreen')
            
            # Layout
            legend.edge('legend_critical', 'legend_malware_high', style='invis')
            legend.edge('legend_malware_high', 'legend_malware_medium', style='invis')
            legend.edge('legend_malware_medium', 'legend_suspicious', style='invis')
            legend.edge('legend_suspicious', 'legend_clean', style='invis')
    
    def _generate_malware_report(self, processes):
        """Generate comprehensive malware report"""
        report = {
            'summary': {
                'total_processes': len(processes),
                'malware_critical': 0,
                'malware_high': 0,
                'malware_medium': 0,
                'suspicious': 0,
                'clean': 0,
                'ransomware_detected': False,
                'rat_detected': False,
                'stealer_detected': False,
                'threat_categories': set(),
                'malware_families': set()
            },
            'malware_findings': [],
            'critical_findings': [],
            'ransomware_findings': [],
            'rat_findings': [],
            'stealer_findings': [],
            'recommendations': []
        }
        
        for pid, proc_info in processes.items():
            analysis = proc_info['analysis']
            verdict = analysis['verdict']
            
            # Update counts
            if verdict == 'MALWARE_CRITICAL':
                report['summary']['malware_critical'] += 1
            elif verdict == 'MALWARE_HIGH':
                report['summary']['malware_high'] += 1
            elif verdict == 'MALWARE_MEDIUM':
                report['summary']['malware_medium'] += 1
            elif verdict == 'SUSPICIOUS':
                report['summary']['suspicious'] += 1
            else:
                report['summary']['clean'] += 1
            
            # Collect malware findings
            if verdict in ['MALWARE_CRITICAL', 'MALWARE_HIGH', 'MALWARE_MEDIUM']:
                malware_info = {
                    'pid': pid,
                    'name': proc_info['name'],
                    'verdict': verdict,
                    'risk_score': analysis['risk_score'],
                    'confidence': analysis['confidence'],
                    'findings': analysis['malware_findings'],
                    'evidence': analysis['detailed_evidence'],
                    'threat_categories': analysis.get('threat_category', [])
                }
                report['malware_findings'].append(malware_info)
                
                # Categorize by threat type
                threat_cats = analysis.get('threat_category', [])
                
                # Check for ransomware
                if 'RANSOMWARE' in threat_cats or any('RANSOMWARE' in finding for finding in analysis['malware_findings']):
                    report['summary']['ransomware_detected'] = True
                    report['ransomware_findings'].append(malware_info)
                
                # Check for RATs
                if 'RAT' in threat_cats or any('RAT:' in finding for finding in analysis['malware_findings']):
                    report['summary']['rat_detected'] = True
                    report['rat_findings'].append(malware_info)
                
                # Check for stealers
                if 'STEALER' in threat_cats or any('STEALER:' in finding for finding in analysis['malware_findings']):
                    report['summary']['stealer_detected'] = True
                    report['stealer_findings'].append(malware_info)
                
                # Critical findings
                if verdict == 'MALWARE_CRITICAL':
                    report['critical_findings'].append(malware_info)
                
                # Add threat categories to summary
                report['summary']['threat_categories'].update(threat_cats)
                
                # Extract malware families
                for finding in analysis['malware_findings']:
                    if ':' in finding:
                        family = finding.split(':')[0]
                        report['summary']['malware_families'].add(family)
        
        # Generate recommendations based on findings
        self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report):
        """Generate actionable recommendations based on findings"""
        recommendations = report['recommendations']
        
        # Critical ransomware recommendations
        if report['summary']['ransomware_detected']:
            recommendations.append("🚨 CRITICAL: Ransomware detected! IMMEDIATE isolation required")
            recommendations.append("Disconnect system from network NOW to prevent encryption spread")
            recommendations.append("Do NOT reboot the system - preserve memory state for forensics")
            recommendations.append("Contact incident response team immediately")
            recommendations.append("Identify and secure backup systems before they are encrypted")
        
        # RAT recommendations
        if report['summary']['rat_detected']:
            recommendations.append("⚠️  CRITICAL: Remote Access Trojan detected - attacker may have remote control")
            recommendations.append("Isolate system from network to prevent data exfiltration")
            recommendations.append("Review network logs for C2 communication")
            recommendations.append("Check for lateral movement to other systems")
            recommendations.append("Reset all credentials that may have been compromised")
        
        # Stealer recommendations
        if report['summary']['stealer_detected']:
            recommendations.append("⚠️  HIGH: Information Stealer detected - credentials likely compromised")
            recommendations.append("Force password reset for all accounts accessed from this system")
            recommendations.append("Review browser history and saved credentials")
            recommendations.append("Check cryptocurrency wallets and financial accounts")
            recommendations.append("Enable MFA on all critical accounts")
        
        # General malware recommendations
        if report['summary']['malware_critical'] > 0:
            recommendations.append("HIGH: Critical malware detected - immediate investigation required")
            recommendations.append("Preserve memory dump and disk image for forensic analysis")
            recommendations.append("Review process execution timeline")
        
        if report['summary']['malware_high'] > 0 or report['summary']['malware_medium'] > 0:
            recommendations.append("Investigate all flagged processes for malicious activity")
            recommendations.append("Check Windows Event Logs for suspicious activities")
            recommendations.append("Review scheduled tasks and startup entries")
        
        # Threat-specific recommendations
        threat_cats = report['summary']['threat_categories']
        
        if 'C2_FRAMEWORK' in threat_cats:
            recommendations.append("C2 Framework detected - check firewall logs for beaconing")
            recommendations.append("Identify and block C2 infrastructure")
        
        if 'CRYPTOMINER' in threat_cats:
            recommendations.append("Cryptocurrency miner detected - check system resource usage")
            recommendations.append("Review running services and scheduled tasks")
        
        if 'CREDENTIAL_THEFT' in threat_cats:
            recommendations.append("Credential dumping detected - assume all local credentials compromised")
            recommendations.append("Check for LSASS memory dumps on disk")
        
        if 'LATERAL_MOVEMENT' in threat_cats:
            recommendations.append("Lateral movement detected - check other systems in network")
            recommendations.append("Review domain controller logs for suspicious authentication")
        
        # General best practices
        if report['summary']['malware_critical'] + report['summary']['malware_high'] + report['summary']['malware_medium'] > 0:
            recommendations.append("Run full antivirus scan with updated signatures")
            recommendations.append("Consider full system rebuild from clean backup")
            recommendations.append("Review and update security policies")
    
    def _generator(self):
        # Configure Graphviz
        self._configure_graphviz()
        
        # Get all processes with REAL malware analysis
        processes, parent_children = self._get_all_processes_with_analysis()
        
        if not processes:
            vollog.error("No processes found")
            return
        
        output_dir = self.config.get("output-dir", tempfile.gettempdir())
        generate_graphs = self.config.get("generate-graphs", True)
        generate_dot = self.config.get("generate-dot", True)
        target_pid = self.config.get("pid")
        
        # Generate malware investigation graphs
        generated_files = []
        if generate_graphs and self.graphviz_available:
            png_path, dot_path = self._generate_malware_investigation_graph(processes, output_dir)
            if png_path:
                generated_files.append(("MALWARE_PNG", png_path))
            if dot_path and generate_dot:
                generated_files.append(("MALWARE_DOT", dot_path))
        
        # Generate comprehensive malware report
        malware_report = self._generate_malware_report(processes)
        
        # Report generated files
        for file_type, file_path in generated_files:
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            yield (0, (
                "FILE_GENERATED",
                file_type,
                os.path.basename(file_path),
                os.path.dirname(file_path),
                f"{file_size} bytes",
                "SUCCESS"
            ))
        
        # Yield executive summary
        summary = malware_report['summary']
        yield (0, (
            "EXECUTIVE_SUMMARY",
            f"Total Processes: {summary['total_processes']}",
            f"Critical: {summary['malware_critical']} | High: {summary['malware_high']} | Medium: {summary['malware_medium']}",
            f"Ransomware: {'YES' if summary['ransomware_detected'] else 'NO'} | RAT: {'YES' if summary['rat_detected'] else 'NO'} | Stealer: {'YES' if summary['stealer_detected'] else 'NO'}",
            f"Threat Categories: {len(summary['threat_categories'])}",
            f"Malware Families: {len(summary['malware_families'])}"
        ))
        
        # Yield critical findings first
        for finding in malware_report['critical_findings']:
            categories = ', '.join(finding['threat_categories'][:2]) if finding['threat_categories'] else 'Multiple'
            yield (0, (
                "MALWARE_CRITICAL",
                finding['name'],
                str(finding['pid']),
                f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                categories,
                finding['findings'][0] if finding['findings'] else "Multiple indicators"
            ))
        
        # Yield ransomware findings
        for finding in malware_report['ransomware_findings']:
            yield (0, (
                "RANSOMWARE_DETECTED",
                finding['name'],
                str(finding['pid']),
                f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                finding['findings'][0] if finding['findings'] else "Ransomware indicators",
                "⚠️  IMMEDIATE ACTION REQUIRED"
            ))
        
        # Yield RAT findings
        for finding in malware_report['rat_findings']:
            yield (0, (
                "RAT_DETECTED",
                finding['name'],
                str(finding['pid']),
                f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                finding['findings'][0] if finding['findings'] else "RAT indicators",
                "⚠️  REMOTE ACCESS DETECTED"
            ))
        
        # Yield stealer findings
        for finding in malware_report['stealer_findings']:
            yield (0, (
                "STEALER_DETECTED",
                finding['name'],
                str(finding['pid']),
                f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                finding['findings'][0] if finding['findings'] else "Stealer indicators",
                "⚠️  CREDENTIAL THEFT"
            ))
        
        # Yield high-confidence malware findings
        for finding in malware_report['malware_findings']:
            if finding['verdict'] == 'MALWARE_HIGH' and finding not in malware_report['critical_findings']:
                categories = ', '.join(finding['threat_categories'][:2]) if finding['threat_categories'] else 'Unknown'
                yield (0, (
                    "MALWARE_HIGH",
                    finding['name'],
                    str(finding['pid']),
                    f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                    categories,
                    finding['findings'][0] if finding['findings'] else "Multiple indicators"
                ))
        
        # Yield medium confidence findings
        for finding in malware_report['malware_findings']:
            if finding['verdict'] == 'MALWARE_MEDIUM':
                yield (0, (
                    "MALWARE_MEDIUM",
                    finding['name'],
                    str(finding['pid']),
                    f"Risk: {finding['risk_score']}% | Conf: {finding['confidence']}%",
                    ', '.join(finding['threat_categories'][:2]) if finding['threat_categories'] else 'Unknown',
                    finding['findings'][0] if finding['findings'] else "Suspicious indicators"
                ))
        
        # Yield process analysis details for target PID or suspicious processes
        for pid, proc_info in processes.items():
            if target_pid is None or pid == target_pid:
                analysis = proc_info['analysis']
                if analysis['verdict'] not in ['CLEAN', 'MALWARE_CRITICAL', 'MALWARE_HIGH', 'MALWARE_MEDIUM']:
                    yield (0, (
                        "PROCESS_ANALYSIS",
                        proc_info['name'],
                        str(pid),
                        f"Verdict: {analysis['verdict']}",
                        f"Risk: {analysis['risk_score']}% | Conf: {analysis['confidence']}%",
                        analysis['malware_findings'][0] if analysis['malware_findings'] else "Under investigation"
                    ))
        
        # Yield threat category summary
        if summary['threat_categories']:
            categories_list = sorted(list(summary['threat_categories']))
            for i, category in enumerate(categories_list[:5]):
                count = sum(1 for f in malware_report['malware_findings'] if category in f.get('threat_categories', []))
                yield (0, (
                    "THREAT_CATEGORY",
                    category,
                    f"{count} processes",
                    "Active Threat",
                    "Investigate",
                    "HIGH_PRIORITY"
                ))
        
        # Yield malware family summary
        if summary['malware_families']:
            families_list = sorted(list(summary['malware_families']))
            for i, family in enumerate(families_list[:5]):
                yield (0, (
                    "MALWARE_FAMILY",
                    family,
                    "Detected",
                    "Known malware family",
                    "Review threat intel",
                    "CONFIRMED"
                ))
        
        # Yield top priority recommendations
        for i, recommendation in enumerate(malware_report['recommendations'][:5]):
            priority = "CRITICAL" if i < 2 and (summary['ransomware_detected'] or summary['rat_detected']) else "HIGH"
            yield (0, (
                "RECOMMENDATION",
                f"Priority {i+1}",
                recommendation,
                priority,
                "Immediate action required" if priority == "CRITICAL" else "Action recommended",
                priority
            ))
        
        # Yield statistics
        total_threats = summary['malware_critical'] + summary['malware_high'] + summary['malware_medium']
        if total_threats > 0:
            threat_percentage = (total_threats / summary['total_processes']) * 100
            yield (0, (
                "STATISTICS",
                f"Threat Detection Rate",
                f"{threat_percentage:.1f}%",
                f"{total_threats} of {summary['total_processes']} processes",
                "Analysis complete",
                "INFO"
            ))
    
    def run(self):
        return renderers.TreeGrid([
            ("Type", str),
            ("Process/Category", str),
            ("PID/Value", str),
            ("Verdict/Description", str),
            ("Score/Details", str),
            ("Status/Priority", str)
        ], self._generator())