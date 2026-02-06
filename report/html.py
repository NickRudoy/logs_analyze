
import json
from datetime import datetime
import html

class HtmlReporter:
    """Генератор отчетов в HTML"""
    
    def __init__(self, output_path):
        self.output_path = output_path.replace('.xlsx', '.html')
        
    def generate(self, bounce_analysis, suspicious_patterns, load_analysis=None, summary_extra=None):
        """Генерирует HTML отчет"""
        print(f"\nГенерация HTML отчета: {self.output_path}")
        
        # Подготовка данных
        summary_rows = [
            ('Прямых заходов', bounce_analysis['total_direct']),
            ('Отказов', bounce_analysis['bounces']),
            ('Не отказов', bounce_analysis['non_bounces']),
            ('Процент отказов', f"{bounce_analysis['bounce_rate']:.2f}%")
        ]
        
        if summary_extra:
            for k, v in summary_extra.items():
                summary_rows.append((k, v))
                
        html_content = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Отчет анализа логов</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
                .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #2c3e50; }}
                h1 {{ border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                h2 {{ margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; font-weight: 600; }}
                tr:hover {{ background-color: #f1f1f1; }}
                .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
                .badge-danger {{ background: #ffebee; color: #c62828; }}
                .badge-warning {{ background: #fff3e0; color: #ef6c00; }}
                .badge-success {{ background: #e8f5e9; color: #2e7d32; }}
                .card {{ background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin-bottom: 15px; }}
                .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }}
                .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
                .stat-label {{ font-size: 14px; color: #7f8c8d; }}
                .chart-container {{ height: 300px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Отчет анализа логов</h1>
                <p>Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Сводка</h2>
                <div class="grid">
        """
        
        for label, value in summary_rows:
            html_content += f"""
                    <div class="stat-box">
                        <div class="stat-value">{value}</div>
                        <div class="stat-label">{label}</div>
                    </div>
            """
        
        html_content += """
                </div>
                
                <h2>Подозрительные IP</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Страна</th>
                            <th>Отказов</th>
                            <th>Score</th>
                            <th>Причины</th>
                            <th>Детали</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for item in suspicious_patterns.get('suspicious_ips', []):
            score_class = 'badge-danger' if item['score'] >= 3 else 'badge-warning'
            html_content += f"""
                        <tr>
                            <td>{item['ip']} <span class="badge {score_class}">{item['score']}</span></td>
                            <td>{item.get('country', 'Unknown')}</td>
                            <td>{item['bounce_count']}</td>
                            <td>{item['score']}</td>
                            <td>{item['reasons'][0] if item['reasons'] else ''}</td>
                            <td>{item.get('isp', '')}</td>
                        </tr>
            """
            
        html_content += """
                    </tbody>
                </table>
        """
        
        if load_analysis and load_analysis.get('high_load_periods'):
            html_content += """
                <h2>Периоды высокой нагрузки</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Запросов</th>
                            <th>Уник. IP</th>
                            <th>Запросов/IP</th>
                            <th>Ошибки</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for period in load_analysis['high_load_periods']:
                error_count = sum(count for code, count in period['status_codes'].items() if code >= 400)
                error_rate = (error_count / period['request_count'] * 100) if period['request_count'] > 0 else 0
                html_content += f"""
                        <tr>
                            <td>{period['period_start'].strftime('%H:%M')} - {period['period_end'].strftime('%H:%M')}</td>
                            <td>{period['request_count']}</td>
                            <td>{period['unique_ips']}</td>
                            <td>{period['requests_per_ip']:.2f}</td>
                            <td>{error_rate:.1f}%</td>
                        </tr>
                """
                
            html_content += """
                    </tbody>
                </table>
            """
            
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"HTML отчет сохранен: {self.output_path}")
        return self.output_path
