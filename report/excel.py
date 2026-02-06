
import pandas as pd
from datetime import datetime

class ExcelReporter:
    """Генератор отчетов в Excel"""
    
    def __init__(self, output_path):
        self.output_path = output_path
        
    def generate(self, bounce_analysis, suspicious_patterns, load_analysis=None, summary_extra=None):
        """Генерирует Excel отчет"""
        print(f"\nГенерация отчета: {self.output_path}")
        
        with pd.ExcelWriter(self.output_path, engine='openpyxl') as writer:
            # Сводка
            summary_data = {
                'Метрика': [
                    'Прямых заходов',
                    'Отказов',
                    'Не отказов',
                    'Процент отказов (%)',
                ],
                'Значение': [
                    bounce_analysis['total_direct'],
                    bounce_analysis['bounces'],
                    bounce_analysis['non_bounces'],
                    f"{bounce_analysis['bounce_rate']:.2f}%",
                ]
            }
            
            if summary_extra:
                for k, v in summary_extra.items():
                    summary_data['Метрика'].append(k)
                    summary_data['Значение'].append(v)
            
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Сводка', index=False)
            
            # Подозрительные IP
            if suspicious_patterns.get('suspicious_ips'):
                suspicious_ips_data = []
                for item in suspicious_patterns['suspicious_ips']:
                    suspicious_ips_data.append({
                        'IP': item['ip'],
                        'Страна': item.get('country', 'Unknown'),
                        'Код страны': item.get('country_code', 'XX'),
                        'Город': item.get('city', 'Unknown'),
                        'Провайдер': item.get('isp', 'Unknown'),
                        'Тип IP': item.get('ip_type', 'Unknown'),
                        'Датацентр': 'Да' if item.get('is_datacenter') else 'Нет',
                        'Количество отказов': item['bounce_count'],
                        'Уникальных URL': item['unique_urls'],
                        'Уникальных User-Agent': item['unique_user_agents'],
                        'User-Agent': '; '.join(item['user_agents'][:3])[:200],
                        'Оценка подозрительности': item['score'],
                        'Причины': '; '.join(item['reasons']),
                        'Первый визит': item['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Последний визит': item['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Примеры URL': '; '.join(item['sample_urls'][:5])[:500]
                    })
                pd.DataFrame(suspicious_ips_data).to_excel(writer, sheet_name='Подозрительные IP', index=False)
            
            # Подозрительные User-Agent
            if suspicious_patterns.get('suspicious_user_agents'):
                ua_data = []
                for item in suspicious_patterns['suspicious_user_agents']:
                    ua_data.append({
                        'User-Agent': item['user_agent'][:200],
                        'Браузер': item.get('browser', 'Unknown'),
                        'Версия браузера': item.get('browser_version', 'Unknown'),
                        'ОС': item.get('os', 'Unknown'),
                        'Версия ОС': item.get('os_version', 'Unknown'),
                        'Тип устройства': item.get('device_type', 'Unknown'),
                        'Бот': 'Да' if item.get('is_bot') else 'Нет',
                        'Мобильное': 'Да' if item.get('is_mobile') else 'Нет',
                        'Количество отказов': item['bounce_count'],
                        'Уникальных IP': item['unique_ips'],
                        'Примеры IP': '; '.join(item['sample_ips'][:5]),
                        'Примеры URL': '; '.join(item['sample_urls'][:5])[:500]
                    })
                pd.DataFrame(ua_data).to_excel(writer, sheet_name='Подозрительные User-Agent', index=False)
            
            # Статистика по странам
            if suspicious_patterns.get('country_stats'):
                country_data = []
                for country, stats in sorted(suspicious_patterns['country_stats'].items(), 
                                           key=lambda x: x[1]['count'], reverse=True):
                    country_data.append({
                        'Страна': country,
                        'Количество отказов': stats['count'],
                        'Уникальных IP': len(stats['ips'])
                    })
                pd.DataFrame(country_data).to_excel(writer, sheet_name='Статистика по странам', index=False)
            
            # IP из датацентров
            if suspicious_patterns.get('datacenter_ips'):
                dc_data = []
                for item in suspicious_patterns['datacenter_ips']:
                    dc_data.append({
                        'IP': item['ip'],
                        'Страна': item['country'],
                        'Провайдер': item['isp'],
                        'Количество отказов': item['bounce_count']
                    })
                pd.DataFrame(dc_data).to_excel(writer, sheet_name='IP из датацентров', index=False)
            
            # Высокочастотные IP
            if suspicious_patterns.get('high_frequency_ips'):
                freq_data = []
                for item in suspicious_patterns['high_frequency_ips']:
                    freq_data.append({
                        'IP': item['ip'],
                        'Количество запросов': item['request_count'],
                        'Средний интервал (сек)': f"{item['avg_interval_seconds']:.2f}",
                        'Временной промежуток (сек)': f"{item['time_span']:.2f}"
                    })
                pd.DataFrame(freq_data).to_excel(writer, sheet_name='Высокочастотные IP', index=False)
            
            # Паттерны ошибок
            if suspicious_patterns.get('error_patterns'):
                error_data = []
                for item in suspicious_patterns['error_patterns']:
                    error_data.append({
                        'IP': item['ip'],
                        'HTTP статус': item['status'],
                        'Количество': item['count']
                    })
                pd.DataFrame(error_data).to_excel(writer, sheet_name='Паттерны ошибок', index=False)
            
            # Детали отказов (первые 1000)
            if bounce_analysis.get('bounce_entries'):
                bounce_data = []
                for entry in bounce_analysis['bounce_entries'][:1000]:
                    bounce_data.append({
                        'IP': entry['ip'],
                        'User-Agent': entry['user_agent'],
                        'URL': entry['url'],
                        'Статус': entry['status'],
                        'Referer': entry['referer'],
                        'Время': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    })
                pd.DataFrame(bounce_data).to_excel(writer, sheet_name='Детали отказов', index=False)
            
            # Анализ нагрузки
            if load_analysis:
                # Периоды высокой нагрузки
                if load_analysis.get('high_load_periods'):
                    high_load_data = []
                    for period in load_analysis['high_load_periods']:
                        top_ips_str = ', '.join([f"{ip}({count})" for ip, count in list(period['top_ips'].items())[:5]])
                        top_urls_str = ', '.join([f"{url[:50]}({count})" for url, count in list(period['top_urls'].items())[:5]])
                        status_codes_str = ', '.join([f"{code}({count})" for code, count in list(period['status_codes'].items())[:5]])
                        
                        high_load_data.append({
                            'Начало периода': period['period_start'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Конец периода': period['period_end'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Количество запросов': period['request_count'],
                            'Уникальных IP': period['unique_ips'],
                            'Уникальных URL': period['unique_urls'],
                            'Запросов на IP': f"{period['requests_per_ip']:.2f}",
                            'Топ IP': top_ips_str[:200],
                            'Топ URL': top_urls_str[:300],
                            'Коды ответов': status_codes_str[:200],
                            'Методы': ', '.join([f"{m}({c})" for m, c in list(period['methods'].items())[:5]]),
                            'Общий размер (МБ)': f"{period['total_size_mb']:.2f}",
                            'Средний размер (КБ)': f"{period['avg_size_kb']:.2f}"
                        })
                    pd.DataFrame(high_load_data).to_excel(writer, sheet_name='Периоды высокой нагрузки', index=False)
                
                # Аномалии в периоды нагрузки
                if load_analysis.get('anomalies'):
                    anomalies_data = []
                    for anomaly in load_analysis['anomalies']:
                        top_ips_str = ', '.join([f"{ip}({count})" for ip, count in list(anomaly['top_ips'].items())[:5]])
                        top_urls_str = ', '.join([f"{url[:50]}({count})" for url, count in list(anomaly['top_urls'].items())[:5]])
                        
                        anomalies_data.append({
                            'Начало периода': anomaly['period_start'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Конец периода': anomaly['period_end'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Количество запросов': anomaly['request_count'],
                            'Уникальных IP': anomaly['unique_ips'],
                            'Процент ошибок': f"{anomaly['error_rate']:.2f}%",
                            'Причины аномалии': '; '.join(anomaly['reasons']),
                            'Топ IP': top_ips_str[:200],
                            'Топ URL': top_urls_str[:300]
                        })
                    pd.DataFrame(anomalies_data).to_excel(writer, sheet_name='Аномалии нагрузки', index=False)
                
                # Сравнение периодов
                if load_analysis.get('comparison'):
                    comp = load_analysis['comparison']
                    comparison_data = {
                        'Метрика': [
                            'Среднее количество запросов',
                            'Среднее уникальных IP',
                            'Среднее запросов на IP',
                            'Среднее уникальных URL',
                            'Количество периодов'
                        ],
                        'Высокая нагрузка': [
                            f"{comp['high_load']['avg_requests']:.0f}",
                            f"{comp['high_load']['avg_unique_ips']:.0f}",
                            f"{comp['high_load']['avg_requests_per_ip']:.2f}",
                            f"{comp['high_load']['avg_unique_urls']:.0f}",
                            comp['high_load']['total_periods']
                        ],
                        'Нормальная нагрузка': [
                            f"{comp['normal_load']['avg_requests']:.0f}",
                            f"{comp['normal_load']['avg_unique_ips']:.0f}",
                            f"{comp['normal_load']['avg_requests_per_ip']:.2f}",
                            f"{comp['normal_load']['avg_unique_urls']:.0f}",
                            comp['normal_load']['total_periods']
                        ],
                        'Разница (%)': [
                            f"{comp['difference'].get('avg_requests', 0):.1f}%",
                            f"{comp['difference'].get('avg_unique_ips', 0):.1f}%",
                            f"{comp['difference'].get('avg_requests_per_ip', 0):.1f}%",
                            f"{comp['difference'].get('avg_unique_urls', 0):.1f}%",
                            '-'
                        ]
                    }
                    pd.DataFrame(comparison_data).to_excel(writer, sheet_name='Сравнение нагрузки', index=False)
        
        print(f"Excel отчет сохранен: {self.output_path}")
        return self.output_path
