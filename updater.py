#!/usr/bin/env python3
"""
EN-OS-Updater
"""

import sys
import os
import json
import hashlib
import tempfile
import subprocess
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import shutil

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

CONFIG = {
    'github_repo': 'Endscape-Coding/EN-OS-Updates',
    'branch': 'main',
    'modules_dir': 'modules',
    'hashes_file': 'SHA256SUMS',
    'signature_file': 'SHA256SUMS.sig',
    'trusted_keys': ['trusted_keys.pub'],
    'timeout': 30,
    'max_file_size': 10 * 1024 * 1024,
}

COLORS = {
    'dark': '#0a0a14',
    'medium': '#1a1a2e',
    'light': '#2a2a4a',
    'blue': '#4361ee',
    'green': '#06d6a0',
    'red': '#ef476f',
    'yellow': '#ffd166',
    'text': '#e0e0e0',
    'text_muted': '#8a8a9e',
}

# ===============
# Проверка 256
# ===============

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
    def calculate_string_hash(content: str) -> str:
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

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

# =====================
# Гит манагер
# =====================

class SimpleGitHubManager(QObject):

    progress = pyqtSignal(str, int)
    error = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self):
        super().__init__()
        self.temp_dir = None
        self.is_downloading = False

    def download_and_verify(self):
        if self.is_downloading:
            return

        self.is_downloading = True

        try:
            self.progress.emit("Starting download...", 0)

            self.temp_dir = tempfile.mkdtemp(prefix="enos_update_")
            temp_path = Path(self.temp_dir)

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

                file_url = f"https://raw.githubusercontent.com/{CONFIG['github_repo']}/{CONFIG['branch']}/modules/{filename}"
                file_content = self._download_file(file_url)

                if not file_content:
                    raise Exception(f"Failed to download {filename}")

                temp_file = temp_path / filename
                temp_file.parent.mkdir(parents=True, exist_ok=True)

                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(file_content)

                if not SHA256Verifier.verify_file(str(temp_file), expected_hash):
                    raise Exception(f"Hash mismatch for {filename}")

                dest_file = Path(CONFIG['modules_dir']) / filename
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(temp_file, dest_file)

                hash_file = dest_file.with_suffix(dest_file.suffix + '.sha256')
                with open(hash_file, 'w') as f:
                    f.write(expected_hash)

            local_hashes = Path(CONFIG['modules_dir']) / CONFIG['hashes_file']
            with open(local_hashes, 'w') as f:
                f.write(hashes_content)

            self.progress.emit("All files verified!", 100)
            self.finished.emit(True, f"Downloaded and verified {total_files} files")

        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.is_downloading = False

    def _download_file(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'EN-OS-Updater'})

            with urllib.request.urlopen(req, timeout=CONFIG['timeout']) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
                else:
                    return None
        except Exception as e:
            print(f"Download error for {url}: {e}")
            return None

# ===============
# Главное очко
# ===============

class SimpleUpdater(QMainWindow):

    def __init__(self):
        super().__init__()
        self.github_manager = SimpleGitHubManager()
        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        self.setWindowTitle("EN-OS Updater")
        self.setGeometry(100, 100, 800, 600)

        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title_label = QLabel("🔄 EN-OS Update System")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"""
            font-size: 28px;
            font-weight: bold;
            color: {COLORS['blue']};
            padding: 20px;
        """)
        layout.addWidget(title_label)

        desc_label = QLabel(
            "Simple and secure update system using SHA256 verification.\n"
            "All modules are checked against trusted hash files from GitHub."
        )
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['text_muted']};
            padding: 10px;
        """)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        layout.addSpacing(20)

        repo_frame = QFrame()
        repo_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['medium']};
                border: 1px solid {COLORS['light']};
                border-radius: 10px;
                padding: 15px;
            }}
        """)
        repo_layout = QVBoxLayout(repo_frame)

        repo_label = QLabel(f"Repository: {CONFIG['github_repo']}")
        branch_label = QLabel(f"Branch: {CONFIG['branch']}")
        hash_file_label = QLabel(f"Hash file: {CONFIG['hashes_file']}")

        for label in [repo_label, branch_label, hash_file_label]:
            label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px; padding: 5px;")
            repo_layout.addWidget(label)

        layout.addWidget(repo_frame)

        layout.addSpacing(20)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {COLORS['light']};
                border-radius: 5px;
                background-color: {COLORS['medium']};
                text-align: center;
                height: 25px;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['blue']};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready to update")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['text']};
            padding: 10px;
            background-color: {COLORS['medium']};
            border-radius: 8px;
            border: 1px solid {COLORS['light']};
        """)
        layout.addWidget(self.status_label)

        layout.addSpacing(20)

        button_layout = QHBoxLayout()

        self.check_button = self._create_button("🔍 Check Local Files", COLORS['yellow'])
        self.check_button.clicked.connect(self.check_local_files)

        self.update_button = self._create_button("⬇️ Download Updates", COLORS['blue'])
        self.update_button.clicked.connect(self.download_updates)

        self.verify_button = self._create_button("✓ Verify All", COLORS['green'])
        self.verify_button.clicked.connect(self.verify_all_files)

        button_layout.addWidget(self.check_button)
        button_layout.addWidget(self.update_button)
        button_layout.addWidget(self.verify_button)

        layout.addLayout(button_layout)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        self.log_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['medium']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['light']};
                border-radius: 8px;
                padding: 10px;
                font-family: monospace;
                font-size: 11px;
            }}
        """)

        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_text)

        layout.addStretch()

        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['dark']};
            }}
            QPushButton {{
                background-color: {COLORS['light']};
                color: {COLORS['text']};
                border: none;
                border-radius: 8px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['blue']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['medium']};
                color: {COLORS['text_muted']};
            }}
        """)

    def _create_button(self, text: str, color: str) -> QPushButton:
        button = QPushButton(text)
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                min-width: 180px;
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
        self.github_manager.finished.connect(self.on_finished)

    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def check_local_files(self):
        self.log("🔍 Checking local files...")

        modules_dir = Path(CONFIG['modules_dir'])
        if not modules_dir.exists():
            self.log("❌ Modules directory not found")
            return

        hashes_file = modules_dir / CONFIG['hashes_file']
        if not hashes_file.exists():
            self.log("❌ Local hash file not found")
            return

        try:
            with open(hashes_file, 'r') as f:
                content = f.read()

            expected_hashes = SHA256Verifier.parse_hashes_file(content)

            verified = 0
            failed = 0
            missing = 0

            for filename, expected_hash in expected_hashes.items():
                filepath = modules_dir / filename

                if filepath.exists():
                    if SHA256Verifier.verify_file(str(filepath), expected_hash):
                        self.log(f"✓ {filename}: OK")
                        verified += 1
                    else:
                        self.log(f"✗ {filename}: HASH MISMATCH")
                        failed += 1
                else:
                    self.log(f"⚠ {filename}: MISSING")
                    missing += 1

            self.log(f"\n✅ Verified: {verified}, ❌ Failed: {failed}, ⚠ Missing: {missing}")

            if failed == 0 and missing == 0:
                self.status_label.setText("✅ All files verified successfully!")
                self.status_label.setStyleSheet(f"color: {COLORS['green']};")
            else:
                self.status_label.setText("⚠ Some files have issues")
                self.status_label.setStyleSheet(f"color: {COLORS['yellow']};")

        except Exception as e:
            self.log(f"❌ Error: {e}")

    def download_updates(self):
        self.log("⬇️ Starting download from GitHub...")
        self.update_button.setEnabled(False)
        self.status_label.setText("Downloading...")

        self.download_thread = QThread()
        self.download_worker = SimpleGitHubManager()

        self.download_worker.moveToThread(self.download_thread)
        self.download_thread.started.connect(self.download_worker.download_and_verify)
        self.download_worker.finished.connect(self.on_download_finished)
        self.download_worker.progress.connect(self.on_progress)
        self.download_worker.error.connect(self.on_error)

        self.download_thread.finished.connect(self.download_thread.deleteLater)
        self.download_thread.start()

    def verify_all_files(self):
        self.log("🔐 Verifying all files with individual hash files...")

        modules_dir = Path(CONFIG['modules_dir'])
        verified = 0
        failed = 0

        for sh_file in modules_dir.glob("*.sh"):
            hash_file = sh_file.with_suffix('.sh.sha256')

            if hash_file.exists():
                with open(hash_file, 'r') as f:
                    expected_hash = f.read().strip()

                if SHA256Verifier.verify_file(str(sh_file), expected_hash):
                    self.log(f"✓ {sh_file.name}: Verified")
                    verified += 1
                else:
                    self.log(f"✗ {sh_file.name}: Hash mismatch")
                    failed += 1
            else:
                self.log(f"⚠ {sh_file.name}: No hash file")

        self.log(f"\n📊 Results: ✅ {verified} verified, ❌ {failed} failed")

        if failed == 0:
            self.status_label.setText(f"✅ All {verified} files verified!")
            self.status_label.setStyleSheet(f"color: {COLORS['green']};")
        else:
            self.status_label.setText(f"⚠ {failed} files failed verification")
            self.status_label.setStyleSheet(f"color: {COLORS['red']};")

    def on_progress(self, message: str, value: int):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.log(f"Progress: {message} ({value}%)")

    def on_error(self, error: str):
        self.log(f"❌ Error: {error}")
        self.status_label.setText(f"Error: {error}")
        self.status_label.setStyleSheet(f"color: {COLORS['red']};")
        self.update_button.setEnabled(True)

    def on_finished(self, success: bool, message: str):
        if success:
            self.log(f"✅ {message}")
            self.status_label.setText("✅ Download complete!")
            self.status_label.setStyleSheet(f"color: {COLORS['green']};")

            QMessageBox.information(
                self,
                "Download Complete",
                message,
                QMessageBox.StandardButton.Ok
            )
        else:
            self.log(f"❌ {message}")
            self.status_label.setText("❌ Download failed")
            self.status_label.setStyleSheet(f"color: {COLORS['red']};")

        self.update_button.setEnabled(True)
        self.progress_bar.setValue(0)

    def on_download_finished(self):
        self.download_thread.quit()
        self.download_thread.wait()

# ============================================================================
# СКРИПТ ДЛЯ ГЕНЕРАЦИИ ХЭШЕЙ
# ============================================================================

def generate_hashes():

    print("🔐 Generating SHA256 checksums...")

    modules_dir = Path("modules")
    if not modules_dir.exists():
        print("❌ Modules directory not found")
        return

    hashes = []

    for file in sorted(modules_dir.glob("*.sh")):
        if file.suffix == '.sh' and not file.name.startswith('.'):
            file_hash = SHA256Verifier.calculate_file_hash(str(file))
            hashes.append(f"{file_hash}  {file.name}")

            hash_file = file.with_suffix('.sh.sha256')
            with open(hash_file, 'w') as f:
                f.write(file_hash)

            print(f"✓ {file.name}: {file_hash[:16]}...")

    main_hash_file = modules_dir / "SHA256SUMS"
    with open(main_hash_file, 'w') as f:
        f.write("# SHA256 checksums for EN-OS modules\n")
        f.write("# Generated automatically - DO NOT EDIT MANUALLY\n\n")
        f.write('\n'.join(hashes))

    print(f"\n✅ Generated {len(hashes)} checksums")
    print(f"📁 Main file: {main_hash_file}")

# ============================================================================
# Github action (на всякий пожарный)
# ============================================================================

"""
.github/workflows/update-hashes.yml:

name: Update SHA256 Hashes

on:
  push:
    paths:
      - 'modules/*.sh'
  workflow_dispatch:

jobs:
  update-hashes:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Generate SHA256 hashes
      run: |
        python3 -c "
        import hashlib
        import os
        import sys

        modules_dir = 'modules'
        hashes = []

        for filename in sorted(os.listdir(modules_dir)):
            if filename.endswith('.sh') and not filename.startswith('.'):
                filepath = os.path.join(modules_dir, filename)
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    hashes.append(f'{file_hash}  {filename}')

                # Create individual hash file
                with open(f'{filepath}.sha256', 'w') as f:
                    f.write(file_hash)

        # Write main hash file
        with open(os.path.join(modules_dir, 'SHA256SUMS'), 'w') as f:
            f.write('# SHA256 checksums for EN-OS modules\\n')
            f.write('# Generated automatically - DO NOT EDIT MANUALLY\\n\\n')
            f.write('\\n'.join(hashes))

        print(f'Generated {len(hashes)} checksums')
        "

    - name: Commit and push changes
      run: |
        git config --local user.email "action@github.com"
        git config --local user.name "GitHub Action"
        git add modules/*.sha256 modules/SHA256SUMS
        git commit -m "Update SHA256 checksums [automated]"
        git push
"""

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("EN-OS Simple Updater")

    window = SimpleUpdater()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":

    if len(sys.argv) > 1 and sys.argv[1] == "--generate-hashes":
        generate_hashes()
    else:
        main()
