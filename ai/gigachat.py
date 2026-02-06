
import json
import sys
import time
from typing import Dict, Any, List

HAS_GIGACHAT = False

class GigaChatAnalyzer:
    """Анализатор с использованием GigaChat API"""
    
    def __init__(self, auth_key: str, model: str = "GigaChat", verify_ssl: bool = False):
        self.auth_key = auth_key
        self.model = model
        self.verify_ssl = verify_ssl
        self.client = None
        self.initialize_client()
    
    def initialize_client(self):
        """Инициализирует клиент GigaChat"""
        global HAS_GIGACHAT
        
        try:
            from gigachat import GigaChat
            HAS_GIGACHAT = True
            
            self.client = GigaChat(
                credentials=self.auth_key,
                model=self.model,
                verify_ssl_certs=self.verify_ssl,
                scope="GIGACHAT_API_PERS"
            )
            print(f"GigaChat инициализирован (модель: {self.model})")
        except ImportError:
            print("Ошибка: библиотека gigachat не установлена")
            print("Установите: pip install gigachat")
            sys.exit(1)
        except Exception as e:
            print(f"Ошибка инициализации GigaChat: {e}")
            if "pydantic" in str(e).lower() or "configerror" in str(e).lower():
                print("Возможно, проблема совместимости с Python 3.14. Попробуйте использовать Python 3.12 или 3.11.")
            sys.exit(1)
    
    def analyze_security_threats(self, context: Dict[str, Any]) -> str:
        """Анализирует угрозы безопасности"""
        print("\nАнализ угроз безопасности...")
        
        # Безопасно получаем данные, даже если ключей нет
        summary = context.get('summary', {})
        suspicious_ips = context.get('suspicious_ips', [])
        country_stats = context.get('country_stats', [])
        datacenter_ips = context.get('datacenter_ips', [])
        
        prompt = f"""Ты - эксперт по кибербезопасности и анализу веб-трафика.

Проанализируй данные о подозрительном трафике на веб-сайте:

СВОДНАЯ ИНФОРМАЦИЯ:
{json.dumps(summary, ensure_ascii=False, indent=2)}

ТОП ПОДОЗРИТЕЛЬНЫХ IP:
{json.dumps(suspicious_ips[:5], ensure_ascii=False, indent=2)}

СТАТИСТИКА ПО СТРАНАМ:
{json.dumps(country_stats[:5], ensure_ascii=False, indent=2)}

IP ИЗ ДАТАЦЕНТРОВ:
{json.dumps(datacenter_ips[:5], ensure_ascii=False, indent=2)}

Проведи анализ и предоставь:
1. Оценку уровня угрозы (низкий/средний/высокий/критический)
2. Идентификацию типов атак (DDoS, сканирование, парсинг, боты и т.д.)
3. Конкретные IP или группы IP, требующие немедленного внимания
4. Признаки координированных атак или ботнетов
5. Оценку потенциального ущерба для сайта

Ответ должен быть структурированным и конкретным."""

        return self._send_request(prompt)
    
    def generate_recommendations(self, context: Dict[str, Any], threat_analysis: str) -> str:
        """Генерирует рекомендации по защите"""
        print("Генерация рекомендаций...")
        
        load_anomalies = context.get('load_anomalies', [])
        
        prompt = f"""На основе анализа угроз:

{threat_analysis}

И данных об аномалиях нагрузки:
{json.dumps(load_anomalies[:3], ensure_ascii=False, indent=2) if load_anomalies else 'Нет данных'}

Предоставь конкретные, практические рекомендации:

1. НЕМЕДЛЕННЫЕ ДЕЙСТВИЯ (в течение часа):
   - Какие IP блокировать прямо сейчас
   - Какие правила файрвола добавить
   - Какие параметры сервера изменить

2. КРАТКОСРОЧНЫЕ МЕРЫ (1-7 дней):
   - Настройка систем защиты (WAF, rate limiting)
   - Мониторинг и алертинг
   - Обновление конфигураций

3. ДОЛГОСРОЧНАЯ СТРАТЕГИЯ:
   - Архитектурные улучшения
   - Внедрение защитных сервисов (Cloudflare, Qrator)
   - Процессы и процедуры реагирования

4. КОНКРЕТНЫЕ КОМАНДЫ И ПРАВИЛА:
   - Примеры команд iptables/nginx/apache
   - Правила блокировки по странам/ASN
   - Конфигурации rate limiting

Рекомендации должны быть максимально конкретными и применимыми."""

        return self._send_request(prompt)
    
    def analyze_business_impact(self, context: Dict[str, Any]) -> str:
        """Анализирует влияние на бизнес"""
        print("Анализ влияния на бизнес...")
        
        summary = context.get('summary', {})
        bounce_rate = summary.get('Процент отказов (%)', 'N/A')
        
        suspicious_ips = context.get('suspicious_ips', [])
        datacenter_ips = context.get('datacenter_ips', [])
        load_anomalies = context.get('load_anomalies', [])
        
        prompt = f"""Проанализируй влияние подозрительного трафика на бизнес-метрики:

ТЕКУЩАЯ СИТУАЦИЯ:
- Процент отказов: {bounce_rate}
- Всего записей в логе: {summary.get('Всего записей в логе', 'N/A')}
- Отказов: {summary.get('Отказов', 'N/A')}

ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ:
- Подозрительных IP: {len(suspicious_ips)}
- IP из датацентров: {len(datacenter_ips)}
- Аномалий нагрузки: {len(load_anomalies)}

Оцени:
1. Влияние на пользовательский опыт и конверсию
2. Потери в SEO (как поисковики видят высокий bounce rate)
3. Нагрузку на инфраструктуру и связанные расходы
4. Риски для репутации бренда
5. Потенциальные финансовые потери

Предоставь количественные оценки там, где возможно, и обоснованные предположения."""

        return self._send_request(prompt)
    
    def create_executive_summary(self, threat_analysis: str, recommendations: str, business_impact: str) -> str:
        """Создает краткую сводку для руководства"""
        print("Создание executive summary...")
        
        prompt = f"""Создай краткую сводку (executive summary) для руководства компании на основе:

АНАЛИЗ УГРОЗ:
{threat_analysis}

РЕКОМЕНДАЦИИ:
{recommendations}

ВЛИЯНИЕ НА БИЗНЕС:
{business_impact}

Executive summary должен содержать:
1. Суть проблемы (2-3 предложения)
2. Уровень критичности
3. Ключевые цифры и факты
4. 3-5 главных действий, которые нужно предпринять
5. Ожидаемый результат от внедрения рекомендаций

Язык должен быть понятен нетехническим руководителям. Фокус на бизнес-ценность и риски."""

        return self._send_request(prompt)
    
    def _send_request(self, prompt: str, max_retries: int = 3) -> str:
        """Отправляет запрос в GigaChat с повторными попытками"""
        for attempt in range(max_retries):
            try:
                response = self.client.chat(prompt)
                
                if hasattr(response, 'choices') and len(response.choices) > 0:
                    content = response.choices[0].message.content
                    return content
                else:
                    return "Ошибка: пустой ответ от GigaChat"
            
            except Exception as e:
                error_msg = str(e)
                print(f"  Попытка {attempt + 1}/{max_retries} не удалась: {error_msg}")
                
                if "401" in error_msg or "Unauthorized" in error_msg:
                    print("  Ошибка авторизации. Проверьте ключ авторизации.")
                    break
                elif "429" in error_msg or "rate limit" in error_msg.lower():
                    time.sleep(5 * (attempt + 1))
                else:
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        return f"Ошибка при обращении к GigaChat после {max_retries} попыток: {error_msg}"
        
        return "Не удалось получить ответ от GigaChat"
