
from datetime import datetime
import html

class HtmlReporter:
    """Генератор отчетов в HTML"""
    
    def __init__(self, output_path):
        self.output_path = output_path.replace('.xlsx', '.html')
        
    def generate(self, bounce_analysis, suspicious_patterns, load_analysis=None, summary_extra=None, investigation=None):
        """Генерирует HTML отчет"""
        print(f"\nГенерация HTML отчета: {self.output_path}")

        def esc(value):
            return html.escape(str(value), quote=True)
        
        # Подготовка данных
        summary_rows = [
            ('Прямых заходов', bounce_analysis['total_direct']),
            ('Отказов', bounce_analysis['bounces']),
            ('Не отказов', bounce_analysis['non_bounces']),
            ('Процент отказов', f"{bounce_analysis['bounce_rate']:.2f}%"),
            ('Прямых сессий', bounce_analysis.get('direct_sessions', 0)),
            ('Сессий с отказом', bounce_analysis.get('bounce_sessions', 0)),
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
                .pre {{ white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #f8f9fa; padding: 12px; border-radius: 6px; overflow-x: auto; }}
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
                        <div class="stat-value">{esc(value)}</div>
                        <div class="stat-label">{esc(label)}</div>
                    </div>
            """
        
        html_content += """
                </div>
        """

        if investigation:
            contrib = investigation.get('bounce_contribution', {})
            html_content += f"""
                <h2>Заключение для проверки</h2>
                <div class="card">{esc(investigation.get('conclusion', ''))}</div>

                <h2>Вклад в Bounce Rate</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Метрика</th>
                            <th>Значение</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Исходный Bounce Rate</td><td>{contrib.get('raw_bounce_rate', 0):.2f}%</td></tr>
                        <tr><td>Подозрительных отказов</td><td>{esc(contrib.get('suspicious_bounces', 0))}</td></tr>
                        <tr><td>Доля подозрительных отказов</td><td>{contrib.get('suspicious_bounce_share', 0):.2f}%</td></tr>
                        <tr><td>Bounce Rate после исключения подозрительных</td><td>{contrib.get('cleaned_bounce_rate', 0):.2f}%</td></tr>
                    </tbody>
                </table>
            """

            if investigation.get('period_comparison'):
                html_content += """
                <h2>Сравнение периодов</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Период</th>
                            <th>Даты</th>
                            <th>Direct</th>
                            <th>Отказы</th>
                            <th>Bounce Rate</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in investigation['period_comparison']:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['period'])}</td>
                            <td>{esc(row['start'])} - {esc(row['end'])}</td>
                            <td>{esc(row['direct'])}</td>
                            <td>{esc(row['bounces'])}</td>
                            <td>{row['bounce_rate']:.2f}%</td>
                        </tr>
                    """
                html_content += """
                    </tbody>
                </table>
                """

            if investigation.get('recommendations'):
                html_content += """
                <h2>Рекомендации IP</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Действие</th>
                            <th>Критичность</th>
                            <th>Отказов</th>
                            <th>Категории</th>
                            <th>Причина</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in investigation['recommendations'][:20]:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['ip'])}</td>
                            <td>{esc(row['action'])}</td>
                            <td>{esc(row['severity'])}</td>
                            <td>{esc(row['bounce_count'])}</td>
                            <td>{esc(row['attack_categories'])}</td>
                            <td>{esc(row['reason'])}</td>
                        </tr>
                    """
                html_content += """
                    </tbody>
                </table>
                """

            if investigation.get('rules'):
                html_content += "<h2>Готовые правила</h2>"
                for rule in investigation['rules']:
                    html_content += f"""
                    <h3>{esc(rule['type'])}</h3>
                    <p>{esc(rule['description'])}</p>
                    <div class="pre">{esc(rule['rule'])}</div>
                    """

            security = investigation.get('security', {})
            if security.get('mitre_matrix'):
                html_content += """
                <h2>Матрица угроз</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Стадия</th>
                            <th>MITRE</th>
                            <th>Technique</th>
                            <th>Событий</th>
                            <th>Риск</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in security['mitre_matrix'][:10]:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['stage'])}</td>
                            <td>{esc(row['mitre_tactic'])}</td>
                            <td>{esc(row['technique'])}</td>
                            <td>{esc(row['events'])}</td>
                            <td>{esc(row['risk'])}</td>
                        </tr>
                    """
                html_content += "</tbody></table>"

            if security.get('successful_sensitive'):
                html_content += """
                <h2>Возможные успешные обращения</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>IP</th>
                            <th>Статус</th>
                            <th>Категория</th>
                            <th>URL</th>
                            <th>Риск</th>
                            <th>Интерпретация</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in security['successful_sensitive'][:20]:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['time'].strftime('%Y-%m-%d %H:%M:%S'))}</td>
                            <td>{esc(row['ip'])}</td>
                            <td>{esc(row['status'])}</td>
                            <td>{esc(row['category'])}</td>
                            <td>{esc(row['url'])}</td>
                            <td>{esc(row['risk'])}</td>
                            <td>{esc(row.get('interpretation', ''))}</td>
                        </tr>
                    """
                html_content += "</tbody></table>"

            if security.get('campaigns'):
                html_content += """
                <h2>Волны активности</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Час</th>
                            <th>Запросов</th>
                            <th>IP</th>
                            <th>Категории</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in security['campaigns'][:15]:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['period_start'].strftime('%Y-%m-%d %H:%M'))}</td>
                            <td>{esc(row['request_count'])}</td>
                            <td>{esc(row['top_ips'])}</td>
                            <td>{esc(row['top_categories'])}</td>
                        </tr>
                    """
                html_content += "</tbody></table>"

            if security.get('manual_checklist'):
                html_content += """
                <h2>Чеклист ручной проверки</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Приоритет</th>
                            <th>Проверка</th>
                            <th>Зачем</th>
                            <th>Как</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for row in security['manual_checklist']:
                    html_content += f"""
                        <tr>
                            <td>{esc(row['priority'])}</td>
                            <td>{esc(row['check'])}</td>
                            <td>{esc(row['why'])}</td>
                            <td>{esc(row['how'])}</td>
                        </tr>
                    """
                html_content += "</tbody></table>"
        
        html_content += """
                
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
                            <td>{esc(item['ip'])} <span class="badge {score_class}">{esc(item['score'])}</span></td>
                            <td>{esc(item.get('country', 'Unknown'))}</td>
                            <td>{esc(item['bounce_count'])}</td>
                            <td>{esc(item['score'])}</td>
                            <td>{esc(item['reasons'][0] if item['reasons'] else '')}</td>
                            <td>{esc(item.get('isp', ''))}</td>
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
                            <td>{esc(period['period_start'].strftime('%H:%M'))} - {esc(period['period_end'].strftime('%H:%M'))}</td>
                            <td>{esc(period['request_count'])}</td>
                            <td>{esc(period['unique_ips'])}</td>
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
