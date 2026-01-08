#!/bin/bash
# MODULE_METADATA_START
# ID: test_module
# Name: Тестовый модуль
# Description: Простой тестовый модуль для демонстрации
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
    # Description: Создает тестовый файл
    # Configurable: true

    TEST_FILE="/tmp/test_update_$(date +%s).txt"
    echo "Создаю тестовый файл: $TEST_FILE"
    echo "Обновление выполнено: $(date)" > "$TEST_FILE"
    echo "Скрипт: $0" >> "$TEST_FILE"
    echo "Пользователь: $(whoami)" >> "$TEST_FILE"

    echo "Файл создан:"
    cat "$TEST_FILE"
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
