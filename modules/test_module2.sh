#!/bin/bash
# MODULE_METADATA_START
# ID: test_module
# Name: Тестовый модуль2
# Description: Простой второй тестовый модуль для демонстрации
# Category: test
# Default: enabled
# Dependencies: bash
# MODULE_METADATA_END

echo_info() {
    # MODULE_FUNCTION: echo_info
    # Description: Выводит информацию о системе
    # Configurable: true

    echo "=== Информация о системе ==="
    uname -a
    echo "============================"
}

create_test_file() {
    # MODULE_FUNCTION: create_test_file
    # Description: Скачивает пакет Firefox
    # Configurable: true

    pacman -S firefox --noconfirm
}

optimize_something() {
    # MODULE_FUNCTION: optimize_something
    # Description: Оптимизирует что-то (всегда выполняется)
    # Configurable: false

    echo "Выполняю обязательную оптимизацию..."
    echo "Оптимизация завершена!"
}

# Главная функция модуля
main() {
    echo "Запуск модуля: test_module"
    echo "============================"

    echo_info
    create_test_file
    optimize_something

    echo "============================"
    echo "Модуль завершил работу"
}

# Вызываем main если скрипт запущен напрямую
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
