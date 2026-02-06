#!/bin/bash

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Log Analyzer Pro Setup ===${NC}"

# Проверка Python (нужен < 3.14 для GigaChat/Pydantic V1)
if command -v python3.13 &> /dev/null; then
    PYTHON_CMD=python3.13
elif command -v python3.12 &> /dev/null; then
    PYTHON_CMD=python3.12
elif command -v python3.11 &> /dev/null; then
    PYTHON_CMD=python3.11
elif command -v python3.10 &> /dev/null; then
    PYTHON_CMD=python3.10
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
else
    echo "Ошибка: Python 3 не найден"
    exit 1
fi

echo "Используется Python: $($PYTHON_CMD --version)"
# Предупреждение о версии
PY_VER=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [[ $(echo "$PY_VER >= 3.14" | bc 2>/dev/null) -eq 1 ]] || [[ "$PY_VER" == "3.14" ]]; then
    echo -e "${BLUE}Внимание: Используется Python $PY_VER. AI модуль может не работать (требуется < 3.14).${NC}"
fi


# Создание/проверка виртуального окружения
VENV_DIR="venv"
if [ -d "ai_env" ]; then
    echo -e "${GREEN}Обнаружено окружение ai_env, используем его.${NC}"
    VENV_DIR="ai_env"
elif [ -d "venv" ]; then
    echo -e "${BLUE}Обнаружено окружение venv, используем его.${NC}"
else
    echo -e "${GREEN}Создание виртуального окружения (venv)...${NC}"
    $PYTHON_CMD -m venv venv
fi

# Активация и установка зависимостей
echo -e "${GREEN}Установка зависимостей в $VENV_DIR...${NC}"
./$VENV_DIR/bin/pip install --upgrade pip
./$VENV_DIR/bin/pip install -r requirements.txt

echo -e "${GREEN}Установка завершена!${NC}"
echo ""
echo -e "${BLUE}Как запустить:${NC}"
echo "  ./$VENV_DIR/bin/python3 main.py logs/ [опции]"
echo ""
echo -e "${BLUE}Примеры:${NC}"
echo "  1. Базовый анализ:"
echo "     ./$VENV_DIR/bin/python3 main.py logs/"
echo ""
echo "  2. HTML отчет:"
echo "     ./$VENV_DIR/bin/python3 main.py logs/ --format html"
echo ""
echo "  3. Анализ с AI (нужен ключ):"
echo "     ./$VENV_DIR/bin/python3 main.py logs/ --ai --auth-key <YOUR_KEY>"
echo ""
