
import argparse
import sys
from pathlib import Path
from datetime import datetime

from config import Config
from core.analyzer import DirectTrafficAnalyzer
from report.excel import ExcelReporter
from report.html import HtmlReporter
from ai.gigachat import GigaChatAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Log Analyzer Pro')
    parser.add_argument('log_path', help='Path to access.log or directory')
    parser.add_argument('--domain', default='auto', help='Target domain')
    parser.add_argument('--start-date', help='YYYY-MM-DD')
    parser.add_argument('--end-date', help='YYYY-MM-DD')
    parser.add_argument('--config', help='Path to config.yaml')
    parser.add_argument('--no-geoip', action='store_true', help='Disable GeoIP')
    parser.add_argument('--mmdb', help='Path to GeoLite2-City.mmdb or GeoIP2-City.mmdb (fast local lookup)')
    parser.add_argument('--ai', action='store_true', help='Enable AI analysis (requires auth_key in config or args)')
    parser.add_argument('--auth-key', help='GigaChat auth key')
    parser.add_argument('--format', choices=['excel', 'html', 'all'], default='excel', help='Report format')

    
    args = parser.parse_args()
    
    # Init config
    cfg = Config(args.config)
    
    # Override config with args
    if args.no_geoip:
        cfg.config['geoip']['enabled'] = False
    
    if args.auth_key:
        cfg.config['ai']['auth_key'] = args.auth_key
    
    start_date = datetime.strptime(args.start_date, '%Y-%m-%d') if args.start_date else None
    end_date = datetime.strptime(args.end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59) if args.end_date else None
    
    # Run Analysis
    mmdb_path = args.mmdb or cfg.get('geoip.mmdb_path') or None
    analyzer = DirectTrafficAnalyzer(
        log_path=args.log_path,
        domain=args.domain,
        start_date=start_date,
        end_date=end_date,
        use_geoip=cfg.get('geoip.enabled'),
        mmdb_path=mmdb_path
    )
    
    analyzer.ensure_domain()
    
    # Create results directory early (for DB)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    domain_slug = analyzer._slugify_filename(analyzer.domain or 'site')
    results_dir = Path("results") / domain_slug
    results_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nРезультаты будут сохранены в папку: {results_dir}")
    
    # Init Database
    analyzer.init_db(results_dir / "logs.db")
    
    analyzer.parse_logs()
    analyzer.identify_direct_traffic()
    bounce_analysis = analyzer.analyze_bounce_rate()
    suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
    
    # Load analysis
    load_analysis = analyzer.analyze_load_periods(
        window_minutes=cfg.get('analyzer.load_window_minutes'),
        threshold_percentile=cfg.get('analyzer.load_threshold_percentile')
    )
    
    analyzer.print_summary(bounce_analysis, suspicious_patterns, load_analysis)
    
    # Generate Report
    report_file_excel = results_dir / f"{domain_slug}_report_{timestamp}.xlsx"
    
    formats = [args.format] if args.format != 'all' else ['excel', 'html']
    
    if 'excel' in formats:
        # Convert path to string for compatibility with openpyxl/pandas if needed, though pathlib usually works
        reporter = ExcelReporter(str(report_file_excel))
        reporter.generate(bounce_analysis, suspicious_patterns, load_analysis)
        
    if 'html' in formats:
        reporter = HtmlReporter(str(report_file_excel))
        reporter.generate(bounce_analysis, suspicious_patterns, load_analysis)
    
    # AI Analysis
    if args.ai or cfg.get('ai.enabled'):
        auth_key = cfg.get('ai.auth_key')
        if not auth_key:
            print("AI analysis skipped: No auth_key provided")
        else:
            print("\nStarting AI Analysis...")
            ai = GigaChatAnalyzer(auth_key=auth_key, model=cfg.get('ai.model'))
            
            # Prepare context
            context = {
                'summary': {
                    'Всего записей в логе': analyzer.total_records,
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
            recs = ai.generate_recommendations(context, threats)
            impact = ai.analyze_business_impact(context)
            summary = ai.create_executive_summary(threats, recs, impact)
            
            # Save AI report
            ai_report_file = results_dir / f"{domain_slug}_ai_report_{timestamp}.txt"
            with open(ai_report_file, 'w', encoding='utf-8') as f:
                f.write("AI ANALYSIS REPORT\n")
                f.write("==================\n\n")
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-----------------\n")
                f.write(summary + "\n\n")
                f.write("THREAT ANALYSIS\n")
                f.write("---------------\n")
                f.write(threats + "\n\n")
                f.write("RECOMMENDATIONS\n")
                f.write("---------------\n")
                f.write(recs + "\n\n")
                f.write("BUSINESS IMPACT\n")
                f.write("---------------\n")
                f.write(impact + "\n\n")
            
            print(f"AI report saved to {ai_report_file}")

if __name__ == '__main__':
    main()
