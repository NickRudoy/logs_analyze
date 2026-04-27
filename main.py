
import argparse
import sys
from pathlib import Path
from datetime import datetime

from config import Config
from core.analyzer import DirectTrafficAnalyzer
from report.excel import ExcelReporter, load_excel_for_ai
from report.html import HtmlReporter
from report.pdf import PdfReporter
from ai.gigachat import GigaChatAnalyzer


def write_text_summary(output_path: Path, analyzer: DirectTrafficAnalyzer, bounce_analysis: dict, suspicious_patterns: dict, load_analysis: dict, investigation: dict = None) -> None:
    """Сохраняет краткий текстовый итог анализа."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("LOG ANALYSIS SUMMARY\n")
        f.write("====================\n")
        f.write(f"Домен: {analyzer.domain} ({analyzer.domain_source})\n")
        f.write(f"Всего записей обработано: {len(analyzer.entries):,}\n")
        f.write(f"Прямых заходов: {bounce_analysis['total_direct']:,}\n")
        f.write(f"Отказов: {bounce_analysis['bounces']:,}\n")
        f.write(f"Bounce Rate: {bounce_analysis['bounce_rate']:.2f}%\n")
        f.write(f"Прямых сессий: {bounce_analysis.get('direct_sessions', 0):,}\n")
        f.write(f"Сессий с отказом: {bounce_analysis.get('bounce_sessions', 0):,}\n")
        f.write(f"Подозрительных IP: {len(suspicious_patterns.get('suspicious_ips', []))}\n")
        if investigation and not investigation.get('geoip_enabled', True):
            f.write("IP из датацентров: GeoIP отключён\n")
        else:
            f.write(f"IP из датацентров: {len(suspicious_patterns.get('datacenter_ips', []))}\n")
        f.write("\n")

        if investigation:
            f.write("ЗАКЛЮЧЕНИЕ ДЛЯ ПРОВЕРКИ\n")
            f.write("-----------------------\n")
            f.write(investigation.get('conclusion', '') + "\n\n")

            contrib = investigation.get('bounce_contribution', {})
            f.write("ВКЛАД ПОДОЗРИТЕЛЬНОГО ТРАФИКА В DIRECT BOUNCE\n")
            f.write("---------------------------------------------\n")
            f.write(f"Сырые отказы direct: {contrib.get('total_bounces', 0):,}\n")
            f.write(f"Подозрительные отказы: {contrib.get('suspicious_bounces', 0):,}\n")
            f.write(f"Доля подозрительных отказов: {contrib.get('suspicious_bounce_share', 0):.2f}%\n")
            f.write(f"Bounce Rate после исключения подозрительных: {contrib.get('cleaned_bounce_rate', 0):.2f}%\n\n")

            if investigation.get('recommendations'):
                f.write("РЕКОМЕНДОВАНО К БЛОКИРОВКЕ / МОНИТОРИНГУ\n")
                f.write("----------------------------------------\n")
                for row in investigation['recommendations'][:15]:
                    f.write(
                        f"{row['ip']} | action={row['action']} | severity={row['severity']} | "
                        f"bounces={row['bounce_count']} | categories={row['attack_categories']}\n"
                    )
                f.write("\n")

            if investigation.get('rules'):
                f.write("ГОТОВЫЕ ПРАВИЛА\n")
                f.write("---------------\n")
                for rule in investigation['rules']:
                    f.write(f"[{rule['type']}] {rule['description']}\n{rule['rule']}\n\n")

            security = investigation.get('security', {})
            if security.get('mitre_matrix'):
                f.write("МАТРИЦА УГРОЗ\n")
                f.write("-------------\n")
                for row in security['mitre_matrix'][:10]:
                    f.write(
                        f"{row['stage']} | {row['mitre_tactic']} | "
                        f"events={row['events']} | risk={row['risk']} | {row['evidence']}\n"
                    )
                f.write("\n")

            if security.get('successful_sensitive'):
                f.write("ВОЗМОЖНЫЕ УСПЕШНЫЕ ОБРАЩЕНИЯ К ЧУВСТВИТЕЛЬНЫМ ПУТЯМ\n")
                f.write("----------------------------------------------------\n")
                for row in security['successful_sensitive'][:15]:
                    f.write(
                        f"{row['time'].strftime('%Y-%m-%d %H:%M:%S')} | {row['ip']} | "
                        f"{row['status']} | {row['risk']} | {row['category']} | {row['url']} | "
                        f"{row.get('interpretation', '')}\n"
                    )
                f.write("\n")

            if security.get('payload_summary'):
                f.write("PAYLOAD-ПАТТЕРНЫ\n")
                f.write("----------------\n")
                for row in security['payload_summary'][:10]:
                    f.write(f"{row['payload_type']}: {row['count']}\n")
                f.write("\n")

            if security.get('manual_checklist'):
                f.write("ЧЕКЛИСТ РУЧНОЙ ПРОВЕРКИ\n")
                f.write("-----------------------\n")
                for row in security['manual_checklist']:
                    f.write(f"[{row['priority']}] {row['check']}\n")
                    f.write(f"  Зачем: {row['why']}\n")
                    f.write(f"  Как: {row['how']}\n")
                f.write("\n")

        if bounce_analysis.get('daily_stats'):
            f.write("КРАТКИЙ ОБЗОР ПО ДАТАМ\n")
            f.write("----------------------\n")
            for row in bounce_analysis['daily_stats']:
                f.write(
                    f"{row['date']}: "
                    f"всего={row['total_requests']:,}, "
                    f"direct={row['direct']:,}, "
                    f"bounce={row['bounces']:,}, "
                    f"rate={row['bounce_rate']:.2f}%\n"
                )
            f.write("\n")

        top_suspicious = sorted(
            suspicious_patterns.get('suspicious_ips', []),
            key=lambda x: x.get('score', 0),
            reverse=True
        )[:10]
        if top_suspicious:
            f.write("ТОП ПОДОЗРИТЕЛЬНЫХ IP\n")
            f.write("---------------------\n")
            for ip in top_suspicious:
                f.write(
                    f"{ip['ip']} | score={ip['score']} | "
                    f"bounces={ip['bounce_count']} | country={ip.get('country', 'Unknown')}\n"
                )
            f.write("\n")

        if load_analysis and load_analysis.get('high_load_periods'):
            f.write("НАГРУЗКА\n")
            f.write("--------\n")
            f.write(f"Периодов высокой нагрузки: {len(load_analysis['high_load_periods'])}\n")
            f.write(f"Порог нагрузки: {load_analysis.get('threshold', 0):.0f} запросов/{load_analysis.get('window_minutes', 15)}мин\n")
            if load_analysis.get('anomalies'):
                f.write(f"Аномалий нагрузки: {len(load_analysis['anomalies'])}\n")


def run_ai_from_excel(excel_path: str, auth_key: str, cfg: Config) -> None:
    """Запускает AI-анализ на основании Excel-отчёта (таблицы), без парсинга логов."""
    excel_path = Path(excel_path)
    if not excel_path.exists():
        print(f"Ошибка: файл не найден: {excel_path}")
        sys.exit(1)
    
    print(f"AI-анализ на основании таблицы: {excel_path}")
    context = load_excel_for_ai(str(excel_path))
    
    ai = GigaChatAnalyzer(auth_key=auth_key, model=cfg.get('ai.model'))
    threats = ai.analyze_security_threats(context)
    ips_to_block = ai.get_ips_to_block(context, threats)
    recs = ai.generate_recommendations(context, threats)
    impact = ai.analyze_business_impact(context)
    summary = ai.create_executive_summary(threats, recs, impact)
    
    results_dir = excel_path.parent
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    ai_report_file = results_dir / f"{excel_path.stem}_ai_{timestamp}.txt"
    
    with open(ai_report_file, 'w', encoding='utf-8') as f:
        f.write("AI ANALYSIS REPORT\n")
        f.write("==================\n")
        f.write(f"Источник данных: {excel_path}\n\n")
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-----------------\n")
        f.write(summary + "\n\n")
        f.write("IP РЕКОМЕНДУЕМЫЕ ДЛЯ БЛОКИРОВКИ\n")
        f.write("-------------------------------\n")
        f.write(ips_to_block + "\n\n")
        f.write("THREAT ANALYSIS\n")
        f.write("---------------\n")
        f.write(threats + "\n\n")
        f.write("RECOMMENDATIONS\n")
        f.write("---------------\n")
        f.write(recs + "\n\n")
        f.write("BUSINESS IMPACT\n")
        f.write("---------------\n")
        f.write(impact + "\n\n")
    
    print(f"AI-отчёт сохранён: {ai_report_file}")


def export_iocs(results_dir: Path, domain_slug: str, timestamp: str, investigation: dict) -> Path:
    """Экспортирует IOC и готовые правила отдельными файлами для админа/SOC."""
    export_dir = results_dir / f"{domain_slug}_iocs_{timestamp}"
    export_dir.mkdir(parents=True, exist_ok=True)

    security = investigation.get('security', {})
    iocs = security.get('iocs', {})
    files = {
        'blocklist_ips.txt': iocs.get('block_ips', []),
        'monitor_ips.txt': iocs.get('monitor_ips', []),
        'suspicious_user_agents.txt': iocs.get('user_agents', []),
        'suspicious_paths.txt': iocs.get('paths', []),
    }
    for filename, rows in files.items():
        with open(export_dir / filename, 'w', encoding='utf-8') as f:
            for row in rows:
                f.write(str(row) + '\n')

    nginx_rules = []
    iptables_rules = []
    for rule in investigation.get('rules', []):
        if rule.get('type') == 'nginx deny':
            nginx_rules.append(rule.get('rule', ''))
        elif rule.get('type') == 'iptables':
            iptables_rules.append(rule.get('rule', ''))
        elif rule.get('type', '').startswith('nginx'):
            nginx_rules.append(rule.get('rule', ''))

    with open(export_dir / 'nginx_security_rules.conf', 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(nginx_rules))
        f.write('\n')

    with open(export_dir / 'iptables_drop.sh', 'w', encoding='utf-8') as f:
        f.write('#!/bin/sh\n')
        f.write('\n'.join(iptables_rules))
        f.write('\n')

    with open(export_dir / 'ioc_summary.md', 'w', encoding='utf-8') as f:
        f.write(f"# IOC Summary: {domain_slug}\n\n")
        f.write(investigation.get('conclusion', '') + "\n\n")
        f.write("## MITRE / Kill Chain\n\n")
        for row in security.get('mitre_matrix', [])[:20]:
            f.write(f"- {row['stage']} ({row['mitre_tactic']}): {row['events']} events, risk={row['risk']}\n")
        f.write("\n## Possible Successful Sensitive Requests\n\n")
        for row in security.get('successful_sensitive', [])[:30]:
            f.write(f"- {row['time'].strftime('%Y-%m-%d %H:%M:%S')} {row['ip']} {row['status']} {row['risk']} {row['url']}\n")

    return export_dir


def main():
    parser = argparse.ArgumentParser(description='Log Analyzer Pro')
    parser.add_argument('log_path', nargs='?', help='Path to access.log or directory (не нужен для --ai-report)')
    parser.add_argument('--domain', default='auto', help='Target domain')
    parser.add_argument('--start-date', help='YYYY-MM-DD')
    parser.add_argument('--end-date', help='YYYY-MM-DD')
    parser.add_argument('--config', help='Path to config.yaml')
    parser.add_argument('--no-geoip', action='store_true', help='Disable GeoIP')
    parser.add_argument('--ai', action='store_true', help='Enable AI analysis (requires auth_key in config or args)')
    parser.add_argument('--ai-report', metavar='PATH', help='Run AI analysis on existing Excel report (no log parsing)')
    parser.add_argument('--auth-key', help='GigaChat auth key')
    parser.add_argument('--model', help='GigaChat model (e.g. GigaChat, GigaChat-Light)')
    parser.add_argument('--format', choices=['excel', 'html', 'pdf', 'all'], default='excel', help='Report format')
    parser.add_argument('--max-entries', type=int, default=None, metavar='N', help='Макс. число записей для анализа (для больших логов задайте и используйте --start-date/--end-date по частям)')
    parser.add_argument('--no-cache', action='store_true', help='Не сохранять распознанные логи на диск; каждый запуск парсит заново')
    parser.add_argument('--cache-dir', default=None, metavar='DIR', help='Папка кэша (по умолчанию: <лог_директория>/.log_analyz_cache)')

    
    args = parser.parse_args()
    
    # Режим AI по готовому Excel-отчёту (без парсинга логов)
    if args.ai_report:
        cfg = Config(args.config)
        if args.auth_key:
            cfg.config['ai']['auth_key'] = args.auth_key
        if args.model:
            cfg.config['ai']['model'] = args.model
        auth_key = args.auth_key or cfg.get('ai.auth_key')
        if not auth_key:
            print("Ошибка: для AI-анализа укажите --auth-key или auth_key в config")
            sys.exit(1)
        run_ai_from_excel(args.ai_report, auth_key, cfg)
        return
    
    if not args.log_path:
        print("Ошибка: укажите путь к логам (файл или папка)")
        sys.exit(1)
    
    # Init config
    cfg = Config(args.config)
    
    # Override config with args
    if args.no_geoip:
        cfg.config['geoip']['enabled'] = False
    
    if args.auth_key:
        cfg.config['ai']['auth_key'] = args.auth_key
    if args.model:
        cfg.config['ai']['model'] = args.model
    
    start_date = datetime.strptime(args.start_date, '%Y-%m-%d') if args.start_date else None
    end_date = datetime.strptime(args.end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59) if args.end_date else None
    
    # Run Analysis
    analyzer = DirectTrafficAnalyzer(
        log_path=args.log_path,
        domain=args.domain,
        start_date=start_date,
        end_date=end_date,
        use_geoip=cfg.get('geoip.enabled'),
        max_entries=args.max_entries,
        use_cache=not args.no_cache,
        cache_dir=args.cache_dir,
    )
    
    analyzer.parse_logs()
    analyzer.ensure_domain()
    analyzer.identify_direct_traffic()
    bounce_analysis = analyzer.analyze_bounce_rate()
    suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis)
    
    # Load analysis
    load_analysis = analyzer.analyze_load_periods(
        window_minutes=cfg.get('analyzer.load_window_minutes'),
        threshold_percentile=cfg.get('analyzer.load_threshold_percentile')
    )
    investigation = analyzer.build_investigation_report(bounce_analysis, suspicious_patterns, load_analysis)
    
    analyzer.print_summary(bounce_analysis, suspicious_patterns, load_analysis)
    
    # Generate Report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    domain_slug = analyzer._slugify_filename(analyzer.domain or 'site')
    
    # Create results directory
    results_dir = Path("results") / domain_slug
    results_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nРезультаты будут сохранены в папку: {results_dir}")
    
    report_file_excel = results_dir / f"{domain_slug}_report_{timestamp}.xlsx"
    
    formats = [args.format] if args.format != 'all' else ['excel', 'html', 'pdf']
    
    if 'excel' in formats:
        # Convert path to string for compatibility with openpyxl/pandas if needed, though pathlib usually works
        reporter = ExcelReporter(str(report_file_excel))
        reporter.generate(bounce_analysis, suspicious_patterns, load_analysis, investigation=investigation)
        
    if 'html' in formats:
        reporter = HtmlReporter(str(report_file_excel))
        reporter.generate(bounce_analysis, suspicious_patterns, load_analysis, investigation=investigation)

    if 'pdf' in formats:
        reporter = PdfReporter(str(report_file_excel))
        reporter.generate(bounce_analysis, suspicious_patterns, load_analysis, investigation=investigation)

    # Краткий итоговый txt-отчёт
    summary_file_txt = results_dir / f"{domain_slug}_summary_{timestamp}.txt"
    write_text_summary(summary_file_txt, analyzer, bounce_analysis, suspicious_patterns, load_analysis, investigation)
    print(f"Краткий txt-отчёт сохранён: {summary_file_txt}")

    ioc_dir = export_iocs(results_dir, domain_slug, timestamp, investigation)
    print(f"IOC и правила сохранены: {ioc_dir}")
    
    # AI Analysis (на основании таблицы — bounce_analysis, suspicious_patterns, load_analysis, не сырых логов)
    if args.ai or cfg.get('ai.enabled'):
        auth_key = cfg.get('ai.auth_key')
        if not auth_key:
            print("AI analysis skipped: No auth_key provided")
        else:
            print("\nAI-анализ на основании таблицы (Excel)...")
            ai = GigaChatAnalyzer(auth_key=auth_key, model=cfg.get('ai.model'))
            
            # Context = структурированные данные (как в Excel), не сырые логи
            context = {
                'summary': {
                    'Всего записей в логе': len(analyzer.entries),
                    'Прямых заходов': bounce_analysis['total_direct'],
                    'Отказов': bounce_analysis['bounces'],
                    'Процент отказов (%)': f"{bounce_analysis['bounce_rate']:.2f}%"
                },
                'suspicious_ips': suspicious_patterns['suspicious_ips'],
                'country_stats': [{'country': k, 'count': v['count']} for k, v in suspicious_patterns['country_stats'].items()],
                'datacenter_ips': suspicious_patterns['datacenter_ips'],
                'load_anomalies': load_analysis['anomalies']
            }
            
            threats = ai.analyze_security_threats(context)
            ips_to_block = ai.get_ips_to_block(context, threats)
            recs = ai.generate_recommendations(context, threats)
            impact = ai.analyze_business_impact(context)
            summary = ai.create_executive_summary(threats, recs, impact)
            
            # AI-отчёт в .txt в той же папке, что и таблица Excel
            ai_report_file = results_dir / f"{domain_slug}_ai_report_{timestamp}.txt"
            with open(ai_report_file, 'w', encoding='utf-8') as f:
                f.write("AI ANALYSIS REPORT\n")
                f.write("==================\n")
                f.write(f"Источник данных: {report_file_excel}\n\n")
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-----------------\n")
                f.write(summary + "\n\n")
                f.write("IP РЕКОМЕНДУЕМЫЕ ДЛЯ БЛОКИРОВКИ\n")
                f.write("-------------------------------\n")
                f.write(ips_to_block + "\n\n")
                f.write("THREAT ANALYSIS\n")
                f.write("---------------\n")
                f.write(threats + "\n\n")
                f.write("RECOMMENDATIONS\n")
                f.write("---------------\n")
                f.write(recs + "\n\n")
                f.write("BUSINESS IMPACT\n")
                f.write("---------------\n")
                f.write(impact + "\n\n")
            
            print(f"AI-отчёт сохранён: {ai_report_file}")

if __name__ == '__main__':
    main()
