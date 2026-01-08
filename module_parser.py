#!/usr/bin/env python3
import re
import os
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class ModuleMetadata:
    id: str
    name: str
    description: str
    category: str
    default: str
    dependencies: List[str]
    enabled: bool = False

@dataclass
class FunctionMetadata:
    name: str
    description: str
    configurable: bool
    enabled: bool = True

class ModuleParser:
    def __init__(self, modules_dir: str = "modules"):
        self.modules_dir = modules_dir

    def parse_module_metadata(self, filepath: str) -> Optional[ModuleMetadata]:
        """Парсит метаданные модуля из файла"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Ищем блок метаданных
            metadata_match = re.search(
                r'# MODULE_METADATA_START\n(.*?)\n# MODULE_METADATA_END',
                content, re.DOTALL
            )

            if not metadata_match:
                return None

            metadata_text = metadata_match.group(1)
            metadata = {}

            # Парсим ключ-значение
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
                dependencies=[d.strip() for d in metadata.get('Dependencies', '').split(',') if d.strip()]
            )
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return None

    def parse_functions(self, filepath: str) -> List[FunctionMetadata]:
        """Парсит информацию о функциях в модуле"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            functions = []
            # Ищем функции с метаданными
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
        """Получает все модули с их метаданными"""
        modules = []

        if not os.path.exists(self.modules_dir):
            print(f"Directory {self.modules_dir} does not exist!")
            return modules

        for filename in sorted(os.listdir(self.modules_dir)):
            if filename.endswith('.sh'):
                filepath = os.path.join(self.modules_dir, filename)
                metadata = self.parse_module_metadata(filepath)

                if metadata:
                    modules.append({
                        'metadata': metadata,
                        'functions': self.parse_functions(filepath),
                        'filepath': filepath,
                        'filename': filename
                    })

        return modules

    def generate_executable_script(self, module_path: str, disabled_functions: List[str] = None) -> str:
        """Генерирует исполняемый скрипт с отключенными функциями"""
        if disabled_functions is None:
            disabled_functions = []

        with open(module_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Создаем новый скрипт
        script_lines = [
            "#!/bin/bash",
            f"# Generated from: {os.path.basename(module_path)}",
            "set -e",
            ""
        ]

        # Копируем весь оригинальный контент, но заменяем вызовы отключенных функций
        lines = content.split('\n')
        in_disabled_function = False
        current_function = None

        for line in lines:
            # Определяем, начинается ли функция
            func_match = re.match(r'^(\w+)\(\)\s*{\s*$', line.strip())
            if func_match:
                current_function = func_match.group(1)
                in_disabled_function = current_function in disabled_functions

            # Если функция отключена - комментируем все её тело
            if in_disabled_function:
                if line.strip() == '}' and current_function in disabled_functions:
                    in_disabled_function = False
                    script_lines.append(f"# {line}  # DISABLED: {current_function}")
                else:
                    script_lines.append(f"# {line}")
            else:
                script_lines.append(line)

        # Комментируем вызовы отключенных функций в main() или других местах
        final_script = '\n'.join(script_lines)
        for func in disabled_functions:
            # Комментируем вызовы типа function_name
            pattern = rf'^\s*{func}\b'
            final_script = re.sub(pattern, f'# {func}  # DISABLED_BY_USER', final_script, flags=re.MULTILINE)

            # Комментируем вызовы типа function_name()
            pattern = rf'^\s*{func}\(\s*\)'
            final_script = re.sub(pattern, f'# {func}()  # DISABLED_BY_USER', final_script, flags=re.MULTILINE)

        return final_script

    def test_module(self, module_path: str) -> bool:
        """Тестирует модуль на синтаксические ошибки"""
        try:
            result = subprocess.run(
                ['bash', '-n', module_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            print(f"Test error: {e}")
            return False
