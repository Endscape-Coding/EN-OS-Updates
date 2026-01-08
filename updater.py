#!/usr/bin/env python3
"""
EN-OS Complete Updater
Объединяет модульность, проверку SHA256 и GitHub синхронизацию
"""

import sys
import os
import json
import hashlib
import tempfile
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import shutil
import re
from dataclasses import dataclass
import traceback

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# ============
# КОнфиг
# ============

CONFIG = {
    'github_repo': 'Endscape-Coding/EN-OS-Updates',
    'branch': 'main',
    'modules_dir': 'modules',
    'hashes_file': 'SHA256SUMS',
    'config_dir': Path.home() / '.config' / 'enos-updater',
    'timeout': 30,
    'max_file_size': 10 * 1024 * 1024,  # 10MB
    'auto_check_interval': 3600,  # 1 час
}

CONFIG['config_dir'].mkdir(parents=True, exist_ok=True)
Path(CONFIG['modules_dir']).mkdir(exist_ok=True)

COLORS = {
    'dark': '#0a0a14',
    'medium': '#1a1a2e',
    'light': '#2a2a4a',
    'blue': '#4361ee',
    'green': '#06d6a0',
    'red': '#ef476f',
    'yellow': '#ffd166',
    'purple': '#7209b7',
    'cyan': '#00bbf9',
    'text': '#e0e0e0',
    'text_muted': '#8a8a9e',
}


@dataclass
class ModuleMetadata:
    id: str
    name: str
    description: str
    category: str
    default: str
    dependencies: List[str]
    filepath: str = ""
    enabled: bool = False

@dataclass
class FunctionMetadata:
    name: str
    description: str
    configurable: bool
    enabled: bool = True

# ==============
# 256 верифер
# ==============

class SHA256Verifier:

    @staticmethod
    def calculate_file_hash(filepath: str) -> str:
        sha256_hash = hashlib.sha256()

        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise Exception(f"Error calculating hash: {e}")

    @staticmethod
    def parse_hashes_file(content: str) -> Dict[str, str]:
        hashes = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('  ')
            if len(parts) >= 2:
                file_hash = parts[0].strip()
                filename = parts[1].strip()
                hashes[filename] = file_hash

        return hashes

    @staticmethod
    def verify_file(filepath: str, expected_hash: str) -> bool:
        try:
            actual_hash = SHA256Verifier.calculate_file_hash(filepath)
            return actual_hash == expected_hash
        except:
            return False

    @staticmethod
    def check_all_hashes(modules_dir: str) -> Tuple[int, int, int]:
        verified = 0
        failed = 0
        missing = 0

        main_hash_file = Path(modules_dir) / CONFIG['hashes_file']
        if main_hash_file.exists():
            with open(main_hash_file, 'r') as f:
                content = f.read()

            hashes = SHA256Verifier.parse_hashes_file(content)

            for filename, expected_hash in hashes.items():
                filepath = Path(modules_dir) / filename

                if filepath.exists():
                    if SHA256Verifier.verify_file(str(filepath), expected_hash):
                        verified += 1
                    else:
                        failed += 1
                else:
                    missing += 1

        return verified, failed, missing

# =================
# Парсер
# =================

class ModuleParser:

    def __init__(self, modules_dir: str = "modules"):
        self.modules_dir = Path(modules_dir)

    def parse_module_metadata(self, filepath: Path) -> Optional[ModuleMetadata]:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            metadata_match = re.search(
                r'# MODULE_METADATA_START\n(.*?)\n# MODULE_METADATA_END',
                content, re.DOTALL
            )

            if not metadata_match:
                return None

            metadata_text = metadata_match.group(1)
            metadata = {}

            for line in metadata_text.split('\n'):
                if line.startswith('# '):
                    key_value = line[2:].split(': ', 1)
                    if len(key_value) == 2:
                        key, value = key_value
                        metadata[key.strip()] = value.strip()

            if 'ID' not in metadata:
                return None

            return ModuleMetadata(
                id=metadata['ID'],
                name=metadata.get('Name', metadata['ID']),
                description=metadata.get('Description', ''),
                category=metadata.get('Category', 'other'),
                default=metadata.get('Default', 'disabled'),
                dependencies=[d.strip() for d in metadata.get('Dependencies', '').split(',') if d.strip()],
                filepath=str(filepath),
                enabled=metadata.get('Default', 'disabled') == 'enabled'
            )
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return None

    def parse_functions(self, filepath: Path) -> List[FunctionMetadata]:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            functions = []
            func_pattern = r'(\w+)\(\)\s*{[^}]*#\s*MODULE_FUNCTION:\s*(\w+)[^}]*#\s*Description:\s*([^\n#]+)[^}]*#\s*Configurable:\s*(true|false)'

            matches = re.finditer(func_pattern, content, re.DOTALL)

            for match in matches:
                functions.append(FunctionMetadata(
                    name=match.group(2),
                    description=match.group(3).strip(),
                    configurable=match.group(4).lower() == 'true'
                ))

            return functions
        except Exception as e:
            print(f"Error parsing functions from {filepath}: {e}")
            return []

    def get_all_modules(self) -> List[Dict]:
        modules = []

        if not self.modules_dir.exists():
            print(f"Directory {self.modules_dir} does not exist!")
            return modules

        for filename in sorted(self.modules_dir.glob("*.sh")):
            metadata = self.parse_module_metadata(filename)

            if metadata:
                modules.append({
                    'metadata': metadata,
                    'functions': self.parse_functions(filename),
                    'filepath': str(filename),
                    'filename': filename.name
                })

        return modules

    def generate_executable_script(self, module_path: str, disabled_functions: List[str] = None) -> str:
        if disabled_functions is None:
            disabled_functions = []

        with open(module_path, 'r', encoding='utf-8') as f:
            content = f.read()

        script_lines = [
            "#!/bin/bash",
            f"# Generated from: {os.path.basename(module_path)}",
            "set -e",
            ""
        ]

        lines = content.split('\n')
        in_disabled_function = False
        current_function = None

        for line in lines:
            func_match = re.match(r'^(\w+)\(\)\s*{\s*$', line.strip())
            if func_match:
                current_function = func_match.group(1)
                in_disabled_function = current_function in disabled_functions

            if in_disabled_function:
                if line.strip() == '}' and current_function in disabled_functions:
                    in_disabled_function = False
                    script_lines.append(f"# {line}  # DISABLED: {current_function}")
                else:
                    script_lines.append(f"# {line}")
            else:
                script_lines.append(line)

        final_script = '\n'.join(script_lines)
        for func in disabled_functions:
            pattern = rf'^\s*{func}\b'
            final_script = re.sub(pattern, f'# {func}  # DISABLED_BY_USER', final_script, flags=re.MULTILINE)

            pattern = rf'^\s*{func}\(\s*\)'
            final_script = re.sub(pattern, f'# {func}()  # DISABLED_BY_USER', final_script, flags=re.MULTILINE)

        return final_script

# =================
# Гитхаб манагер
# =================

class GitHubManager(QObject):

    progress = pyqtSignal(str, int)
    error = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    update_available = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.modules_dir = Path(CONFIG['modules_dir'])
        self.temp_dir = None
        self.is_downloading = False

    def check_for_updates(self) -> bool:
        try:
            hashes_url = f"https://raw.githubusercontent.com/{CONFIG['github_repo']}/{CONFIG['branch']}/{CONFIG['hashes_file']}"

            self.progress.emit("Checking for updates...", 0)

            hashes_content = self._download_file(hashes_url)
            if not hashes_content:
                self.error.emit("Could not download hash file")
                return False

            self.progress.emit("Parsing hash file...", 50)

            remote_hashes = SHA256Verifier.parse_hashes_file(hashes_content)

            local_hash_file = self.modules_dir / CONFIG['hashes_file']
            local_hashes = {}

            if local_hash_file.exists():
                with open(local_hash_file, 'r') as f:
                    local_content = f.read()
                    local_hashes = SHA256Verifier.parse_hashes_file(local_content)

            needs_update = False

            for filename, remote_hash in remote_hashes.items():
                if filename not in local_hashes:
                    needs_update = True
                    break
                elif local_hashes[filename] != remote_hash:
                    needs_update = True
                    break

            self.progress.emit("Check complete", 100)
            self.update_available.emit(needs_update)

            return needs_update

        except Exception as e:
            self.error.emit(f"Update check failed: {e}")
            return False

    def download_updates(self):
        if self.is_downloading:
            return

        self.is_downloading = True

        try:
            self.progress.emit("Starting update process...", 0)

            self.temp_dir = Path(tempfile.mkdtemp(prefix="enos_update_"))

            self.progress.emit("Downloading hash file...", 10)
            hashes_url = f"https://raw.githubusercontent.com/{CONFIG['github_repo']}/{CONFIG['branch']}/{CONFIG['hashes_file']}"
            hashes_content = self._download_file(hashes_url)

            if not hashes_content:
                raise Exception("Failed to download hash file")

            hashes = SHA256Verifier.parse_hashes_file(hashes_content)
            total_files = len(hashes)
            downloaded = 0

            for filename, expected_hash in hashes.items():
                downloaded += 1
                progress = 10 + int((downloaded / total_files) * 80)

                self.progress.emit(f"Downloading {filename}...", progress)
                file_url = f"https://raw.githubusercontent.com/{CONFIG['github_repo']}/{CONFIG['branch']}/{CONFIG['modules_dir']}/{filename}"
                file_content = self._download_file(file_url)

                if not file_content:
                    raise Exception(f"Failed to download {filename}")

                temp_file = self.temp_dir / filename
                temp_file.parent.mkdir(parents=True, exist_ok=True)

                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(file_content)

                if not SHA256Verifier.verify_file(str(temp_file), expected_hash):
                    raise Exception(f"Hash mismatch for {filename}")

                dest_file = self.modules_dir / filename
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(temp_file, dest_file)

                hash_file = dest_file.with_suffix('.sha256')
                with open(hash_file, 'w') as f:
                    f.write(expected_hash)

            hash_file_path = self.modules_dir / CONFIG['hashes_file']
            with open(hash_file_path, 'w') as f:
                f.write(hashes_content)

            self._save_last_update()

            self.progress.emit("Update completed successfully!", 100)
            self.finished.emit(True, f"Downloaded and verified {total_files} modules")

        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))
        finally:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.is_downloading = False

    def _download_file(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'EN-OS-Updater/1.0',
                    'Accept': 'text/plain'
                }
            )

            with urllib.request.urlopen(req, timeout=CONFIG['timeout']) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
                else:
                    print(f"HTTP {response.status} for {url}")
                    return None
        except urllib.error.URLError as e:
            print(f"URL error for {url}: {e}")
            return None
        except Exception as e:
            print(f"Error downloading {url}: {e}")
            return None

    def _save_last_update(self):
        config_file = CONFIG['config_dir'] / 'updates.json'
        data = {
            'last_update': datetime.now().isoformat(),
            'github_repo': CONFIG['github_repo']
        }

        with open(config_file, 'w') as f:
            json.dump(data, f, indent=2)

class ModuleCard(QWidget):

    selection_changed = pyqtSignal(str, bool, list)  # module_id, enabled, disabled_functions

    def __init__(self, module_data: Dict, parent=None):
        super().__init__(parent)
        self.module_id = module_data['metadata'].id
        self.module_data = module_data
        self.function_checkboxes = {}

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        header_layout = QHBoxLayout()

        self.checkbox = QCheckBox(self.module_data['metadata'].name)
        self.checkbox.setChecked(self.module_data['metadata'].default == 'enabled')
        self.checkbox.stateChanged.connect(self.on_checkbox_changed)
        self.checkbox.setStyleSheet(f"""
            QCheckBox {{
                color: {COLORS['text']};
                font-size: 14px;
                font-weight: bold;
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
            }}
        """)

        category_label = QLabel(self.module_data['metadata'].category.upper())
        category_label.setStyleSheet(f"""
            QLabel {{
                color: {self._get_category_color()};
                font-size: 10px;
                font-weight: bold;
                padding: 3px 10px;
                border-radius: 10px;
                background-color: {self._get_category_color()}20;
            }}
        """)

        header_layout.addWidget(self.checkbox)
        header_layout.addStretch()
        header_layout.addWidget(category_label)

        layout.addLayout(header_layout)

        desc_label = QLabel(self.module_data['metadata'].description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(f"""
            QLabel {{
                color: {COLORS['text_muted']};
                font-size: 12px;
                margin-left: 5px;
            }}
        """)
        layout.addWidget(desc_label)

        if self.module_data['metadata'].dependencies:
            deps_text = "Requires: " + ", ".join(self.module_data['metadata'].dependencies)
            deps_label = QLabel(deps_text)
            deps_label.setStyleSheet(f"""
                QLabel {{
                    color: {COLORS['yellow']};
                    font-size: 10px;
                    font-style: italic;
                    margin-left: 5px;
                }}
            """)
            layout.addWidget(deps_label)

        configurable_funcs = [f for f in self.module_data['functions'] if f.configurable]
        if configurable_funcs:
            functions_group = QGroupBox("Functions")
            functions_group.setStyleSheet(f"""
                QGroupBox {{
                    color: {COLORS['text_muted']};
                    border: 1px solid {COLORS['light']};
                    border-radius: 5px;
                    margin-top: 10px;
                }}
                QGroupBox::title {{
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px 0 5px;
                }}
            """)

            functions_layout = QVBoxLayout()

            for func in configurable_funcs:
                func_checkbox = QCheckBox(f"{func.name}: {func.description}")
                func_checkbox.setChecked(True)
                func_checkbox.func_name = func.name
                func_checkbox.stateChanged.connect(self.on_function_changed)
                func_checkbox.setStyleSheet(f"""
                    QCheckBox {{
                        color: {COLORS['text_muted']};
                        font-size: 11px;
                    }}
                """)
                functions_layout.addWidget(func_checkbox)
                self.function_checkboxes[func.name] = func_checkbox

            functions_group.setLayout(functions_layout)
            layout.addWidget(functions_group)

        layout.addStretch()

        self.setStyleSheet(f"""
            ModuleCard {{
                background-color: {COLORS['medium']};
                border: 1px solid {COLORS['light']};
                border-radius: 10px;
            }}
            ModuleCard:hover {{
                border-color: {COLORS['blue']};
            }}
        """)

    def _get_category_color(self):
        colors = {
            'system': COLORS['blue'],
            'security': COLORS['red'],
            'optimization': COLORS['green'],
            'network': COLORS['purple'],
            'other': COLORS['cyan']
        }
        return colors.get(self.module_data['metadata'].category, COLORS['text_muted'])

    def on_checkbox_changed(self):
        enabled = self.checkbox.isChecked()
        disabled_funcs = self.get_disabled_functions()
        self.selection_changed.emit(self.module_id, enabled, disabled_funcs)

    def on_function_changed(self):
        disabled_funcs = self.get_disabled_functions()
        self.selection_changed.emit(self.module_id, self.checkbox.isChecked(), disabled_funcs)

    def get_disabled_functions(self) -> List[str]:
        """Возвращает список отключенных функций"""
        disabled = []
        for func_name, checkbox in self.function_checkboxes.items():
            if not checkbox.isChecked():
                disabled.append(func_name)
        return disabled

# ==================
# Главное очко
# ==================

class ENOSUpdater(QMainWindow):

    def __init__(self):
        super().__init__()
        self.github_manager = GitHubManager()
        self.module_parser = ModuleParser()
        self.modules_data = []
        self.module_cards = {}
        self.user_settings = self.load_settings()

        self.init_ui()
        self.connect_signals()
        self.setup_auto_check()

        QTimer.singleShot(100, self.load_modules)

    def init_ui(self):
        self.setWindowTitle("EN-OS Updater")
        self.setGeometry(100, 100, 1200, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        top_panel = QHBoxLayout()

        title_label = QLabel("🚀 EN-OS System Updater")
        title_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {COLORS['blue']};
        """)

        self.stats_label = QLabel("No modules loaded")
        self.stats_label.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 12px;
            padding: 5px 10px;
            background-color: {COLORS['medium']};
            border-radius: 5px;
        """)

        top_panel.addWidget(title_label)
        top_panel.addStretch()
        top_panel.addWidget(self.stats_label)

        main_layout.addLayout(top_panel)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {COLORS['light']};
                border-radius: 5px;
                background-color: {COLORS['medium']};
                text-align: center;
                height: 20px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['blue']};
                border-radius: 3px;
            }}
        """)
        main_layout.addWidget(self.progress_bar)

        control_panel = QHBoxLayout()
        self.refresh_btn = self._create_button("🔄 Refresh", COLORS['cyan'])
        self.refresh_btn.clicked.connect(self.load_modules)

        self.select_all_btn = self._create_button("✓ Select All", COLORS['green'])
        self.select_all_btn.clicked.connect(self.select_all_modules)

        self.deselect_all_btn = self._create_button("✗ Deselect All", COLORS['red'])
        self.deselect_all_btn.clicked.connect(self.deselect_all_modules)

        control_panel.addWidget(self.refresh_btn)
        control_panel.addWidget(self.select_all_btn)
        control_panel.addWidget(self.deselect_all_btn)
        control_panel.addStretch()

        self.check_updates_btn = self._create_button("🔍 Check GitHub", COLORS['purple'])
        self.check_updates_btn.clicked.connect(self.check_github_updates)

        self.download_btn = self._create_button("⬇️ Download Updates", COLORS['blue'])
        self.download_btn.clicked.connect(self.download_updates)

        control_panel.addWidget(self.check_updates_btn)
        control_panel.addWidget(self.download_btn)

        main_layout.addLayout(control_panel)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {COLORS['light']};
                border-radius: 8px;
                background-color: transparent;
            }}
            QScrollBar:vertical {{
                background-color: {COLORS['medium']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['blue']};
                border-radius: 5px;
            }}
        """)

        self.modules_container = QWidget()
        self.modules_layout = QVBoxLayout(self.modules_container)
        self.modules_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.modules_layout.setSpacing(10)

        self.scroll_area.setWidget(self.modules_container)
        main_layout.addWidget(self.scroll_area)

        bottom_panel = QHBoxLayout()

        self.verify_hashes_btn = self._create_button("🔐 Verify Hashes", COLORS['yellow'])
        self.verify_hashes_btn.clicked.connect(self.verify_all_hashes)

        self.apply_btn = QPushButton("🚀 Apply Selected Updates")
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self.apply_updates)
        self.apply_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['green']};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 15px 30px;
                font-size: 16px;
                font-weight: bold;
                min-width: 200px;
            }}
            QPushButton:hover {{
                background-color: #05c595;
            }}
            QPushButton:pressed {{
                background-color: #05b085;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['medium']};
                color: {COLORS['text_muted']};
            }}
        """)

        bottom_panel.addWidget(self.verify_hashes_btn)
        bottom_panel.addStretch()
        bottom_panel.addWidget(self.apply_btn)

        main_layout.addLayout(bottom_panel)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(100)
        self.log_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['medium']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['light']};
                border-radius: 5px;
                font-family: monospace;
                font-size: 10px;
                padding: 5px;
            }}
        """)
        main_layout.addWidget(self.log_text)

        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['dark']};
            }}
        """)

    def _create_button(self, text: str, color: str) -> QPushButton:
        button = QPushButton(text)
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {color}dd;
            }}
            QPushButton:pressed {{
                background-color: {color}aa;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['medium']};
                color: {COLORS['text_muted']};
            }}
        """)
        return button

    def connect_signals(self):
        self.github_manager.progress.connect(self.on_progress)
        self.github_manager.error.connect(self.on_error)
        self.github_manager.finished.connect(self.on_download_finished)
        self.github_manager.update_available.connect(self.on_update_available)

    def setup_auto_check(self):
        self.auto_check_timer = QTimer()
        self.auto_check_timer.timeout.connect(self.auto_check_github)
        self.auto_check_timer.start(CONFIG['auto_check_interval'] * 1000)

    def load_settings(self) -> dict:
        settings_file = CONFIG['config_dir'] / 'settings.json'
        if settings_file.exists():
            try:
                with open(settings_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'selected_modules': {}}

    def save_settings(self):
        settings_file = CONFIG['config_dir'] / 'settings.json'
        with open(settings_file, 'w') as f:
            json.dump(self.user_settings, f, indent=2)

    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def load_modules(self):
        try:
            for card in self.module_cards.values():
                card.setParent(None)
            self.module_cards.clear()

            self.modules_data = self.module_parser.get_all_modules()

            if not self.modules_data:
                no_modules_label = QLabel("No modules found. Download updates from GitHub or add modules manually.")
                no_modules_label.setStyleSheet(f"""
                    color: {COLORS['text_muted']};
                    font-size: 14px;
                    padding: 40px;
                    text-align: center;
                """)
                self.modules_layout.addWidget(no_modules_label)
                self.apply_btn.setEnabled(False)
                self.stats_label.setText("No modules")
                return

            for module in self.modules_data:
                card = ModuleCard(module)
                card.selection_changed.connect(self.on_module_selection_changed)

                if module['metadata'].id in self.user_settings.get('selected_modules', {}):
                    settings = self.user_settings['selected_modules'][module['metadata'].id]
                    card.checkbox.setChecked(settings.get('enabled', False))

                    for func_name, checkbox in card.function_checkboxes.items():
                        checkbox.setChecked(settings.get('functions', {}).get(func_name, True))

                self.modules_layout.addWidget(card)
                self.module_cards[module['metadata'].id] = card

            self.update_stats()
            self.log(f"Loaded {len(self.modules_data)} modules")

        except Exception as e:
            self.log(f"Error loading modules: {e}")
            traceback.print_exc()

    def on_module_selection_changed(self, module_id: str, enabled: bool, disabled_functions: list):
        if module_id not in self.user_settings['selected_modules']:
            self.user_settings['selected_modules'][module_id] = {}

        card = self.module_cards.get(module_id)
        if card:
            self.user_settings['selected_modules'][module_id] = {
                'enabled': enabled,
                'functions': {func: card.function_checkboxes[func].isChecked()
                            for func in card.function_checkboxes}
            }
            self.save_settings()

        self.update_stats()

    def update_stats(self):
        total = len(self.modules_data)
        selected = sum(1 for card in self.module_cards.values() if card.checkbox.isChecked())

        self.stats_label.setText(f"📦 {total} modules | ✅ {selected} selected")
        self.apply_btn.setEnabled(selected > 0)

    def select_all_modules(self):
        for card in self.module_cards.values():
            card.checkbox.setChecked(True)
        self.update_stats()

    def deselect_all_modules(self):
        for card in self.module_cards.values():
            card.checkbox.setChecked(False)
        self.update_stats()

    def verify_all_hashes(self):
        self.log("🔐 Verifying SHA256 hashes...")

        verified, failed, missing = SHA256Verifier.check_all_hashes(CONFIG['modules_dir'])

        if verified == 0 and failed == 0 and missing == 0:
            self.log("❌ No hash file found. Please download updates first.")
            self.status_bar.showMessage("No hash file found")
        else:
            self.log(f"✅ Verified: {verified}, ❌ Failed: {failed}, ⚠ Missing: {missing}")

            if failed == 0 and missing == 0:
                self.status_bar.showMessage(f"✅ All {verified} files verified")
            else:
                self.status_bar.showMessage(f"⚠ {failed} files failed, {missing} missing")

    def check_github_updates(self):
        self.log("🔍 Checking for updates on GitHub...")
        self.check_updates_btn.setEnabled(False)
        self.progress_bar.setVisible(True)

        self.check_thread = QThread()
        self.check_worker = GitHubManager()

        self.check_worker.moveToThread(self.check_thread)
        self.check_thread.started.connect(self.check_worker.check_for_updates)
        self.check_worker.finished.connect(self.on_check_finished)
        self.check_worker.progress.connect(self.on_progress)
        self.check_worker.error.connect(self.on_error)
        self.check_worker.update_available.connect(self.on_update_available)

        self.check_thread.start()

    def on_check_finished(self, success: bool, message: str):
        self.check_updates_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        if success:
            self.log("✅ Update check completed")
        else:
            self.log(f"❌ Update check failed: {message}")

    def on_update_available(self, available: bool):
        if available:
            self.log("🔄 Updates available on GitHub!")

            reply = QMessageBox.question(
                self,
                "Updates Available",
                "New updates are available on GitHub. Download now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.download_updates()
        else:
            self.log("✅ No updates available")
            self.status_bar.showMessage("No updates available")

    def download_updates(self):
        self.log("⬇️ Downloading updates from GitHub...")
        self.download_btn.setEnabled(False)
        self.progress_bar.setVisible(True)

        self.download_thread = QThread()
        self.download_worker = GitHubManager()

        self.download_worker.moveToThread(self.download_thread)
        self.download_thread.started.connect(self.download_worker.download_updates)
        self.download_worker.finished.connect(self.on_download_finished)
        self.download_worker.progress.connect(self.on_progress)
        self.download_worker.error.connect(self.on_error)

        self.download_thread.start()

    def on_download_finished(self, success: bool, message: str):
        self.download_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        if success:
            self.log(f"✅ {message}")
            self.status_bar.showMessage("Updates downloaded successfully")

            QMessageBox.information(
                self,
                "Updates Downloaded",
                message,
                QMessageBox.StandardButton.Ok
            )

            self.load_modules()
        else:
            self.log(f"❌ {message}")
            self.status_bar.showMessage("Download failed")

    def apply_updates(self):
        selected_cards = [card for card in self.module_cards.values() if card.checkbox.isChecked()]

        if not selected_cards:
            QMessageBox.warning(self, "No Selection", "Please select modules to apply")
            return

        reply = QMessageBox.question(
            self,
            "Confirm Update",
            f"Apply {len(selected_cards)} selected modules?\n"
            "This will require administrator privileges.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        scripts = []
        for card in selected_cards:
            module = next(m for m in self.modules_data if m['metadata'].id == card.module_id)
            if module:
                script = self.module_parser.generate_executable_script(
                    module['filepath'],
                    card.get_disabled_functions()
                )
                scripts.append(script)

        self.execute_updates(scripts)

    def execute_updates(self, scripts: List[str]):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
                f.write("#!/bin/bash\n")
                f.write("set -e\n")
                f.write('echo "=== EN-OS SYSTEM UPDATE === "\n')
                f.write(f'echo "Date: $(date)"\n')
                f.write(f'echo "User: $(whoami)"\n\n')

                for i, script in enumerate(scripts, 1):
                    f.write(f'echo "--- Module {i} ---"\n')
                    f.write(script)
                    f.write('\n\n')

                f.write('echo "=== UPDATE COMPLETE === "\n')

                script_path = f.name

            os.chmod(script_path, 0o755)

            self.log("🔄 Executing updates (requires admin privileges)...")

            process = subprocess.Popen(
                ['pkexec', 'bash', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            for line in process.stdout:
                self.log(line.strip())

            process.wait()

            os.unlink(script_path)

            if process.returncode == 0:
                self.log("✅ Updates applied successfully!")
                QMessageBox.information(self, "Success", "Updates applied successfully!")
            else:
                self.log(f"❌ Update failed with code {process.returncode}")
                QMessageBox.warning(self, "Error", "Some updates failed to apply")

        except Exception as e:
            self.log(f"❌ Error executing updates: {e}")
            traceback.print_exc()

    def auto_check_github(self):
        if self.user_settings.get('auto_check', True):
            self.check_github_updates()

    def on_progress(self, message: str, value: int):
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(message)

    def on_error(self, error: str):
        self.log(f"❌ Error: {error}")
        self.status_bar.showMessage(f"Error: {error[:50]}")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("EN-OS Updater")

    window = ENOSUpdater()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
