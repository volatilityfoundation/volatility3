import logging
import re
import os
from typing import List, Iterator, Tuple
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import vadinfo, pslist, filescan

vollog = logging.getLogger(__name__)

class EnhancedDesktopArtifacts(interfaces.plugins.PluginInterface):
    """Enhanced scanner for desktop files and folders with detailed information."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="user",
                description="Filter by specific username",
                optional=True,
                default=None
            ),
            requirements.StringRequirement(
                name="extension",
                description="Filter by file extension",
                optional=True,
                default=None
            ),
            requirements.BooleanRequirement(
                name="show_folders",
                description="Show folders",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="show_files",
                description="Show files",
                optional=True,
                default=True
            ),
        ]

    def _get_file_details(self, file_path, context, kernel_module_name):
        """Get detailed information about a file"""
        details = {
            'size': 0,
            'processes': set(),
            'memory_address': "N/A",
            'creation_time': "N/A",
            'modified_time': "N/A"
        }
        
        # Try to get file size and process info from filescan
        try:
            for file_obj in filescan.FileScan.scan_files(context, kernel_module_name):
                try:
                    if file_obj.FileName.String and file_obj.FileName.String.lower() == file_path.lower():
                        details['size'] = file_obj.Size.v() if hasattr(file_obj, 'Size') else 0
                        
                        # Get timestamps if available
                        if hasattr(file_obj, 'StandardInformation'):
                            try:
                                creation_time = file_obj.StandardInformation.CreationTime
                                if creation_time:
                                    details['creation_time'] = creation_time
                            except Exception:
                                pass
                            
                            try:
                                modified_time = file_obj.StandardInformation.ModificationTime
                                if modified_time:
                                    details['modified_time'] = modified_time
                            except Exception:
                                pass
                        break
                except Exception:
                    continue
        except Exception:
            pass
        
        # Get process and VAD information
        for proc in pslist.PsList.list_processes(context, kernel_module_name):
            try:
                for vad in vadinfo.VadInfo.list_vads(proc):
                    try:
                        vad_file_name = vad.get_file_name()
                        if vad_file_name and vad_file_name.lower() == file_path.lower():
                            details['processes'].add(proc.ImageFileName.cast(
                                "string", 
                                max_length=proc.ImageFileName.vol.count, 
                                errors="replace"
                            ))
                            if details['memory_address'] == "N/A":
                                details['memory_address'] = f"0x{vad.get_start():x}"
                    except Exception:
                        continue
            except Exception:
                continue
        
        details['process_count'] = len(details['processes'])
        details['process_list'] = ", ".join(sorted(details['processes'])[:3])  # Show first 3 processes
        if len(details['processes']) > 3:
            details['process_list'] += f"... (+{len(details['processes']) - 3} more)"
            
        return details

    def _categorize_item(self, path):
        """Enhanced categorization of desktop items"""
        path_lower = path.lower()
        filename = path.split('\\')[-1] if '\\' in path else path
        
        # File type categories
        file_categories = {
            'Shortcut': ['.lnk'],
            'Document': ['.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt'],
            'Spreadsheet': ['.xls', '.xlsx', '.csv', '.ods'],
            'Presentation': ['.ppt', '.pptx', '.odp'],
            'Image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg'],
            'Video': ['.mp4', '.avi', '.mov', '.wmv', '.mkv', '.flv'],
            'Audio': ['.mp3', '.wav', '.flac', '.aac', '.wma'],
            'Archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'Executable': ['.exe', '.msi', '.bat', '.cmd', '.com'],
            'Code': ['.py', '.java', '.cpp', '.c', '.js', '.html', '.css', '.php'],
            'Config': ['.ini', '.cfg', '.conf', '.xml', '.json'],
            'URL': ['.url', '.webloc'],
            'Database': ['.mdb', '.accdb', '.sqlite', '.db']
        }
        
        # Check for folders first
        if '\\desktop\\' in path_lower and not '.' in filename and not path_lower.endswith(tuple(
            ext for extensions in file_categories.values() for ext in extensions)):
            return 'Folder'
        
        # Check file types
        for category, extensions in file_categories.items():
            if any(path_lower.endswith(ext) for ext in extensions):
                return category
        
        return 'Unknown File'

    def _get_file_extension(self, path):
        """Extract file extension"""
        if '.' in path:
            return '.' + path.split('.')[-1].lower()
        return ''

    def _get_username_from_path(self, path):
        """Extract username from file path"""
        path_lower = path.lower()
        
        # Try to extract username from Users directory
        users_match = re.search(r'\\users\\([^\\]+)', path_lower)
        if users_match:
            return users_match.group(1)
            
        # Try Documents and Settings (older Windows)
        docs_match = re.search(r'\\documents and settings\\([^\\]+)', path_lower)
        if docs_match:
            return docs_match.group(1)
            
        return "Unknown"

    def _scan_for_desktop_paths(self):
        """Enhanced scanning for desktop-related paths"""
        kernel_module_name = self.config["kernel"]
        desktop_items = {}
        
        vollog.info("🔍 Starting enhanced desktop artifacts scan...")
        
        # Method 1: Scan file objects from memory (most reliable)
        vollog.info("📁 Scanning file objects...")
        file_objects_count = 0
        try:
            for file_obj in filescan.FileScan.scan_files(self.context, kernel_module_name):
                try:
                    file_name = file_obj.FileName.String
                    if file_name and self._is_desktop_path(file_name):
                        file_objects_count += 1
                        desktop_items[file_name.lower()] = {
                            'path': file_name,
                            'source': 'FileScan'
                        }
                except Exception:
                    continue
            vollog.info(f"📁 Found {file_objects_count} desktop items via FileScan")
        except Exception as e:
            vollog.warning(f"FileScan plugin not available: {e}")

        # Method 2: Scan process VADs
        vollog.info("🔍 Scanning process VADs...")
        vad_count = 0
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                for vad in vadinfo.VadInfo.list_vads(proc):
                    try:
                        file_name = vad.get_file_name()
                        if file_name and self._is_desktop_path(file_name):
                            vad_count += 1
                            if file_name.lower() not in desktop_items:
                                desktop_items[file_name.lower()] = {
                                    'path': file_name,
                                    'source': 'VAD'
                                }
                    except Exception:
                        continue
            except Exception:
                continue
        vollog.info(f"🔍 Found {vad_count} desktop items via VAD scanning")

        # Convert back to sorted list
        sorted_items = sorted([item['path'] for item in desktop_items.values()])
        vollog.info(f"🎯 Total unique desktop items found: {len(sorted_items)}")
        
        return sorted_items

    def _is_desktop_path(self, path):
        """Enhanced desktop path detection"""
        if not path:
            return False
            
        path_lower = path.lower()
        
        # Skip system files
        system_paths = ['\\windows\\', '\\program files\\', '\\system32\\', '\\syswow64\\']
        if any(system_path in path_lower for system_path in system_paths):
            return False
        
        # Desktop path patterns
        desktop_patterns = [
            r'\\users\\[^\\]+\\desktop\\.*',
            r'\\documents and settings\\[^\\]+\\desktop\\.*',
            r'c:\\users\\[^\\]+\\desktop\\.*',
            r'\\desktop\\.*'
        ]
        
        # Check if path matches any desktop pattern
        for pattern in desktop_patterns:
            if re.search(pattern, path_lower):
                return True
                
        return False

    def _format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0 B"
            
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f} {size_names[i]}"

    def _generator(self):
        target_user = self.config.get("user")
        target_extension = self.config.get("extension")
        show_folders = self.config.get("show_folders", True)
        show_files = self.config.get("show_files", True)
        
        desktop_paths = self._scan_for_desktop_paths()
        
        if not desktop_paths:
            vollog.warning("❌ No desktop artifacts found.")
            yield (0, ("INFO", "No items", "Try running 'filescan' plugin", "N/A", "N/A", "N/A", "N/A", "N/A"))
            return

        # Apply filters
        filtered_paths = []
        for path in desktop_paths:
            # User filter
            if target_user and target_user.lower() not in path.lower():
                continue
                
            # Extension filter
            if target_extension and not path.lower().endswith(target_extension.lower()):
                continue
                
            # Type filter
            item_type = self._categorize_item(path)
            if item_type == 'Folder' and not show_folders:
                continue
            if item_type != 'Folder' and not show_files:
                continue
                
            filtered_paths.append(path)

        vollog.info(f"📊 Displaying {len(filtered_paths)} filtered desktop items")
        
        # Process each item and get details
        for path in filtered_paths:
            item_type = self._categorize_item(path)
            extension = self._get_file_extension(path)
            username = self._get_username_from_path(path)
            file_details = self._get_file_details(path, self.context, self.config["kernel"])
            
            # Extract just the filename for display
            filename = path.split('\\')[-1] if '\\' in path else path
            
            yield (0, (
                filename,                    # File/Folder Name
                item_type,                   # Type
                extension,                   # Extension
                self._format_file_size(file_details['size']),  # Size
                username,                    # User
                file_details['memory_address'],  # Memory Address
                file_details['process_list'],    # Processes
                path                         # Full Path
            ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Name", str),              # File/Folder name
                ("Type", str),              # File type category
                ("Extension", str),         # File extension
                ("Size", str),              # Human-readable size
                ("User", str),              # Username
                ("Memory Address", str),    # Where it's mapped
                ("Processes", str),         # Processes using this file
                ("Full Path", str)          # Complete file path
            ],
            self._generator(),
        )