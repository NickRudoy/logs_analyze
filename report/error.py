import pandas as pd


class ErrorExcelReporter:
    """Генератор Excel-отчёта по error-логам."""

    def __init__(self, output_path):
        self.output_path = output_path

    def generate(self, analysis):
        print(f"\nГенерация error Excel отчёта: {self.output_path}")
        summary = analysis.get('summary', {})
        with pd.ExcelWriter(self.output_path, engine='openpyxl') as writer:
            summary_rows = [
                {'Метрика': 'Всего error-событий', 'Значение': summary.get('total_events', 0)},
                {'Метрика': 'Первое событие', 'Значение': self._fmt_dt(summary.get('first_seen'))},
                {'Метрика': 'Последнее событие', 'Значение': self._fmt_dt(summary.get('last_seen'))},
                {'Метрика': 'Пропущено строк', 'Значение': summary.get('skipped_lines', 0)},
                {'Метрика': 'Файлы', 'Значение': '; '.join(summary.get('files', []))[:30000]},
            ]
            pd.DataFrame(summary_rows).to_excel(writer, sheet_name='Сводка', index=False)

            pd.DataFrame([{'Заключение': analysis.get('conclusion', '')}]).to_excel(
                writer, sheet_name='Заключение', index=False
            )

            pd.DataFrame([{'Наблюдение': row} for row in analysis.get('findings', [])]).to_excel(
                writer, sheet_name='Наблюдения', index=False
            )

            self._counter_sheet(writer, 'Уровни', summary.get('levels', []), 'Уровень')
            self._counter_sheet(writer, 'Категории', summary.get('categories', []), 'Категория')
            self._counter_sheet(writer, 'Риски', summary.get('risks', []), 'Риск')

            if analysis.get('daily_stats'):
                pd.DataFrame([
                    {
                        'Дата': row['date'],
                        'Всего': row['total'],
                        'Уровни': self._dict_to_text(row.get('levels', {})),
                        'Категории': self._dict_to_text(row.get('categories', {})),
                        'Риски': self._dict_to_text(row.get('risks', {})),
                    }
                    for row in analysis['daily_stats']
                ]).to_excel(writer, sheet_name='По датам', index=False)

            if analysis.get('peak_periods'):
                pd.DataFrame([
                    {
                        'Начало': self._fmt_dt(row['period_start']),
                        'Конец': self._fmt_dt(row['period_end']),
                        'Событий': row['events'],
                        'Уникальных IP': row['unique_ips'],
                        'Топ IP': row['top_ip'],
                        'Событий топ IP': row['top_ip_count'],
                        'Доля топ IP (%)': f"{row['top_ip_share']:.2f}%",
                        'Категории': self._dict_to_text(row.get('categories', {})),
                        'Риски': self._dict_to_text(row.get('risks', {})),
                    }
                    for row in analysis['peak_periods']
                ]).to_excel(writer, sheet_name='Пики', index=False)

            if analysis.get('top_ips'):
                pd.DataFrame([
                    {
                        'IP': row['ip'],
                        'Событий': row['events'],
                        'Категории': self._dict_to_text(row.get('categories', {})),
                        'Действие': row['action'],
                    }
                    for row in analysis['top_ips']
                ]).to_excel(writer, sheet_name='Топ IP', index=False)

            self._counter_sheet(writer, 'Топ URL', analysis.get('top_urls', []), 'URL')
            self._counter_sheet(writer, 'Топ host', analysis.get('top_hosts', []), 'Host')
            self._counter_sheet(writer, 'Топ referrer', analysis.get('top_referrers', []), 'Referrer')
            self._counter_sheet(writer, 'Топ сообщений', analysis.get('top_messages', []), 'Сообщение')

            if analysis.get('samples'):
                pd.DataFrame([
                    {
                        'Время': self._fmt_dt(row['time']),
                        'Источник': row['source'],
                        'Уровень': row['level'],
                        'Риск': row['risk'],
                        'Категории': row['categories'],
                        'IP': row['client'],
                        'Host': row['host'],
                        'Request': row['request'],
                        'URL': row['url'],
                        'Сообщение': row['message'],
                        'Файл': row['source_file'],
                    }
                    for row in analysis['samples']
                ]).to_excel(writer, sheet_name='Примеры high risk', index=False)

        print(f"Error Excel отчёт сохранён: {self.output_path}")
        return self.output_path

    def _counter_sheet(self, writer, sheet_name, rows, label):
        if not rows:
            return
        pd.DataFrame([{label: key, 'Количество': count} for key, count in rows]).to_excel(
            writer, sheet_name=sheet_name, index=False
        )

    def _dict_to_text(self, data):
        return '; '.join(f"{k}: {v}" for k, v in data.items())

    def _fmt_dt(self, value):
        return value.strftime('%Y-%m-%d %H:%M:%S') if hasattr(value, 'strftime') else str(value or '')


def write_error_text_summary(output_path, analyzer, analysis):
    summary = analysis.get('summary', {})
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("ERROR LOG ANALYSIS SUMMARY\n")
        f.write("==========================\n")
        f.write(f"Домен: {analyzer.domain} ({analyzer.domain_source})\n")
        f.write(f"Всего error-событий: {summary.get('total_events', 0):,}\n")
        if summary.get('first_seen'):
            f.write(f"Период: {summary['first_seen'].strftime('%Y-%m-%d %H:%M:%S')} - {summary['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Файлов обработано: {len(summary.get('files', []))}\n")
        f.write(f"Пропущено строк: {summary.get('skipped_lines', 0):,}\n\n")

        f.write("ЗАКЛЮЧЕНИЕ\n")
        f.write("----------\n")
        f.write(analysis.get('conclusion', '') + "\n\n")

        f.write("КЛЮЧЕВЫЕ НАБЛЮДЕНИЯ\n")
        f.write("-------------------\n")
        for row in analysis.get('findings', []):
            f.write(f"- {row}\n")
        f.write("\n")

        f.write("УРОВНИ\n")
        f.write("------\n")
        for level, count in summary.get('levels', []):
            f.write(f"{level}: {count:,}\n")
        f.write("\n")

        f.write("КАТЕГОРИИ\n")
        f.write("---------\n")
        for category, count in summary.get('categories', []):
            f.write(f"{category}: {count:,}\n")
        f.write("\n")

        if analysis.get('daily_stats'):
            f.write("ПО ДАТАМ\n")
            f.write("--------\n")
            for row in analysis['daily_stats']:
                f.write(
                    f"{row['date']}: total={row['total']:,}; "
                    f"categories={_dict_to_text(row.get('categories', {}))}\n"
                )
            f.write("\n")

        if analysis.get('top_ips'):
            f.write("ТОП IP\n")
            f.write("------\n")
            for row in analysis['top_ips'][:20]:
                f.write(f"{row['ip']}: {row['events']:,}; action={row['action']}; categories={_dict_to_text(row.get('categories', {}))}\n")
            f.write("\n")

        if analysis.get('peak_periods'):
            f.write("ПИКИ ERROR-СОБЫТИЙ\n")
            f.write("------------------\n")
            for row in analysis['peak_periods'][:20]:
                f.write(
                    f"{row['period_start'].strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"{row['period_end'].strftime('%Y-%m-%d %H:%M:%S')}: "
                    f"events={row['events']:,}, top_ip={row['top_ip']}, "
                    f"categories={_dict_to_text(row.get('categories', {}))}\n"
                )
            f.write("\n")

        if analysis.get('samples'):
            f.write("ПРИМЕРЫ HIGH/CRITICAL\n")
            f.write("---------------------\n")
            for row in analysis['samples'][:30]:
                f.write(
                    f"{row['time'].strftime('%Y-%m-%d %H:%M:%S')} | {row['risk']} | "
                    f"{row['categories']} | {row['client']} | {row['request'] or row['url']} | {row['message']}\n"
                )


def _dict_to_text(data):
    return '; '.join(f"{k}: {v}" for k, v in data.items())
