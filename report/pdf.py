import html
import shutil
import subprocess
import tempfile
import textwrap
from datetime import datetime
from pathlib import Path


class PdfReporter:
    """Генератор профессионального PDF-резюме через системный HTML->PDF converter."""

    def __init__(self, output_path):
        self.output_path = str(output_path).replace(".xlsx", ".pdf")

    def generate(self, bounce_analysis, suspicious_patterns, load_analysis=None, investigation=None, summary_extra=None):
        print(f"\nГенерация PDF отчета: {self.output_path}")
        try:
            self._write_reportlab_pdf(bounce_analysis, suspicious_patterns, load_analysis, investigation)
        except Exception as reportlab_exc:
            print(f"ReportLab PDF недоступен, пробуем HTML->PDF: {reportlab_exc}")
            html_content = self._build_html(bounce_analysis, suspicious_patterns, load_analysis, investigation, summary_extra)
            try:
                self._html_to_pdf(html_content)
            except Exception as html_exc:
                print(f"HTML->PDF недоступен, используем встроенный PDF renderer: {html_exc}")
                self._write_simple_pdf(bounce_analysis, suspicious_patterns, load_analysis, investigation)
        print(f"PDF отчет сохранен: {self.output_path}")
        return self.output_path

    def _write_reportlab_pdf(self, bounce_analysis, suspicious_patterns, load_analysis, investigation):
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        font_path = self._find_ttf_font()
        pdfmetrics.registerFont(TTFont("ReportFont", str(font_path)))
        pdfmetrics.registerFont(TTFont("ReportFontBold", str(font_path)))

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="TitleRu", parent=styles["Title"], fontName="ReportFontBold",
            fontSize=22, leading=27, textColor=colors.HexColor("#102A43"),
            alignment=TA_CENTER, spaceAfter=12,
        ))
        styles.add(ParagraphStyle(
            name="H2Ru", parent=styles["Heading2"], fontName="ReportFontBold",
            fontSize=14, leading=18, textColor=colors.HexColor("#102A43"),
            spaceBefore=12, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            name="H3Ru", parent=styles["Heading3"], fontName="ReportFontBold",
            fontSize=11, leading=14, textColor=colors.HexColor("#243B53"),
            spaceBefore=8, spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="BodyRu", parent=styles["BodyText"], fontName="ReportFont",
            fontSize=9.3, leading=12.2, textColor=colors.HexColor("#243B53"),
        ))
        styles.add(ParagraphStyle(
            name="LeadRu", parent=styles["BodyText"], fontName="ReportFont",
            fontSize=10.2, leading=14, textColor=colors.HexColor("#243B53"),
            backColor=colors.HexColor("#F0F4F8"), borderColor=colors.HexColor("#BCCCDC"),
            borderWidth=0.5, borderPadding=7, spaceAfter=8,
        ))
        styles.add(ParagraphStyle(
            name="CodeRu", parent=styles["Code"], fontName="ReportFont",
            fontSize=7.2, leading=9, textColor=colors.HexColor("#102A43"),
            backColor=colors.HexColor("#F8FAFC"), borderColor=colors.HexColor("#D9E2EC"),
            borderWidth=0.3, borderPadding=5,
        ))

        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            rightMargin=14 * mm,
            leftMargin=14 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
            title="Log Analyzer Pro Report",
            author="Log Analyzer Pro",
        )

        investigation = investigation or {}
        security = investigation.get("security", {})
        contrib = investigation.get("bounce_contribution", {})
        story = []

        story.append(Paragraph("Отчет по direct-трафику и подозрительной активности", styles["TitleRu"]))
        story.append(Paragraph(f"Сформировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyRu"]))
        story.append(Spacer(1, 6))

        anomaly_count = len(load_analysis.get("anomalies", [])) if load_analysis else 0
        high_load_count = len(load_analysis.get("high_load_periods", [])) if load_analysis else 0
        metrics = [
            ["Direct", f"{bounce_analysis.get('total_direct', 0):,}", "Отказы", f"{bounce_analysis.get('bounces', 0):,}"],
            ["Bounce Rate", f"{bounce_analysis.get('bounce_rate', 0):.2f}%", "Подозрительные IP", str(len(suspicious_patterns.get("suspicious_ips", [])))],
            ["Аномалии", str(anomaly_count), "Высокая нагрузка", str(high_load_count)],
        ]
        story.append(self._rl_table(metrics, [34 * mm, 38 * mm, 40 * mm, 38 * mm], font_size=9, header=False))

        if investigation.get("conclusion"):
            story.append(Paragraph("Executive Summary", styles["H2Ru"]))
            story.append(Paragraph(self._p(investigation["conclusion"]), styles["LeadRu"]))

        solution_rows = self._task_solution_rows(bounce_analysis, suspicious_patterns, investigation)
        if solution_rows:
            story.append(Paragraph("Решение для задачи", styles["H2Ru"]))
            story.append(self._rl_table(solution_rows, [44 * mm, 120 * mm]))

        charts = self._build_chart_table(bounce_analysis, suspicious_patterns, security)
        if charts:
            story.append(Paragraph("Визуальная сводка", styles["H2Ru"]))
            story.append(charts)

        if contrib:
            story.append(Paragraph("Вклад подозрительного трафика в bounce", styles["H2Ru"]))
            rows = [
                ["Метрика", "Значение"],
                ["Исходный Bounce Rate", f"{contrib.get('raw_bounce_rate', 0):.2f}%"],
                ["Подозрительные отказы", f"{contrib.get('suspicious_bounces', 0):,}"],
                ["Доля подозрительных отказов", f"{contrib.get('suspicious_bounce_share', 0):.2f}%"],
                ["Bounce Rate после исключения", f"{contrib.get('cleaned_bounce_rate', 0):.2f}%"],
            ]
            story.append(self._rl_table(rows, [80 * mm, 50 * mm]))

        if security.get("mitre_matrix"):
            story.append(Paragraph("Матрица угроз", styles["H2Ru"]))
            rows = [["Стадия", "MITRE", "Событий", "Риск", "Доказательства"]]
            for row in security["mitre_matrix"][:10]:
                rows.append([row["stage"], row["mitre_tactic"], str(row["events"]), row["risk"], row["evidence"]])
            story.append(self._rl_table(rows, [45 * mm, 24 * mm, 18 * mm, 22 * mm, 55 * mm]))

        if investigation.get("recommendations"):
            story.append(Paragraph("Рекомендации по IP", styles["H2Ru"]))
            rows = [["IP", "Действие", "Критичность", "Отказов", "Категории"]]
            for row in investigation["recommendations"][:15]:
                rows.append([row["ip"], row["action"], row["severity"], str(row["bounce_count"]), row["attack_categories"]])
            story.append(self._rl_table(rows, [29 * mm, 22 * mm, 26 * mm, 18 * mm, 68 * mm]))

        if security.get("successful_sensitive"):
            story.append(PageBreak())
            story.append(Paragraph("Возможные успешные обращения к чувствительным путям", styles["H2Ru"]))
            story.append(Paragraph(
                "2xx/3xx по чувствительным URL не означает подтвержденный взлом, но требует ручной проверки конечного ответа, редиректа и наличия файла.",
                styles["BodyRu"],
            ))
            rows = [["Время", "IP", "Статус", "Категория", "URL", "Риск", "Интерпретация"]]
            for row in security["successful_sensitive"][:25]:
                rows.append([
                    row["time"].strftime("%Y-%m-%d %H:%M"),
                    row["ip"],
                    str(row["status"]),
                    row["category"],
                    row["url"],
                    row["risk"],
                    row.get("interpretation", ""),
                ])
            story.append(self._rl_table(rows, [24 * mm, 24 * mm, 13 * mm, 25 * mm, 42 * mm, 13 * mm, 32 * mm], font_size=6.4))

        if security.get("payload_summary") or security.get("campaigns"):
            story.append(Paragraph("Payload и волны активности", styles["H2Ru"]))
            if security.get("payload_summary"):
                rows = [["Payload", "Количество"]]
                for row in security["payload_summary"][:10]:
                    rows.append([row["payload_type"], str(row["count"])])
                story.append(self._rl_table(rows, [70 * mm, 35 * mm]))
            if security.get("campaigns"):
                story.append(Paragraph("Крупные волны", styles["H3Ru"]))
                rows = [["Час", "Запросов", "IP", "Категории"]]
                for row in security["campaigns"][:10]:
                    rows.append([
                        row["period_start"].strftime("%Y-%m-%d %H:%M"),
                        str(row["request_count"]),
                        row["top_ips"],
                        row["top_categories"],
                    ])
                story.append(self._rl_table(rows, [30 * mm, 19 * mm, 56 * mm, 60 * mm], font_size=7.2))

        if investigation.get("rules"):
            story.append(PageBreak())
            story.append(Paragraph("Приложение: готовые правила", styles["H2Ru"]))
            for rule in investigation["rules"][:5]:
                story.append(Paragraph(rule["type"], styles["H3Ru"]))
                story.append(Paragraph(self._p(rule["description"]), styles["BodyRu"]))
                story.append(Spacer(1, 5))
                story.append(self._code_block(rule["rule"]))
                story.append(Spacer(1, 8))

        if investigation.get("allowlist_notes"):
            story.append(Paragraph("Что не блокировать автоматически", styles["H2Ru"]))
            rows = [["Объект", "Действие", "Комментарий"]]
            for row in investigation["allowlist_notes"]:
                rows.append([row["item"], row["action"], row["note"]])
            story.append(self._rl_table(rows, [45 * mm, 35 * mm, 85 * mm]))

        if security.get("manual_checklist"):
            story.append(Paragraph("Чеклист ручной проверки", styles["H2Ru"]))
            rows = [["Приоритет", "Проверка", "Зачем", "Как"]]
            for row in security["manual_checklist"]:
                rows.append([row["priority"], row["check"], row["why"], row["how"]])
            story.append(self._rl_table(rows, [20 * mm, 42 * mm, 55 * mm, 52 * mm], font_size=7.1))

        doc.build(story, onFirstPage=self._page_footer, onLaterPages=self._page_footer)

    def _task_solution_rows(self, bounce_analysis, suspicious_patterns, investigation):
        contrib = investigation.get("bounce_contribution", {})
        security = investigation.get("security", {})
        block_count = len(investigation.get("block_ips", []))
        rows = [
            ["Проблема", f"Рост отказов по direct-трафику. В текущем срезе Bounce Rate: {bounce_analysis.get('bounce_rate', 0):.2f}%."],
            ["Основная причина", f"Подозрительные отказы: {contrib.get('suspicious_bounces', 0):,} ({contrib.get('suspicious_bounce_share', 0):.2f}% direct-отказов)."],
            ["Рекомендуемое действие", f"Заблокировать/ограничить {block_count} IP, закрыть sensitive paths, включить rate-limit и проверить allowlist."],
        ]
        if security.get("payload_summary"):
            payloads = ", ".join(f"{x['payload_type']} ({x['count']})" for x in security["payload_summary"][:3])
            rows.append(["Payload-признаки", payloads])
        if security.get("successful_sensitive"):
            rows.append(["Ручная проверка", f"{len(security['successful_sensitive'])} sensitive-запросов с 2xx/3xx требуют проверки конечного ответа."])
        return rows

    def _build_chart_table(self, bounce_analysis, suspicious_patterns, security):
        from reportlab.lib.units import mm
        from reportlab.platypus import Table, TableStyle

        charts = []
        daily = bounce_analysis.get("daily_stats", [])
        if daily:
            charts.append(self._line_chart(
                "Bounce Rate по дням",
                [(row["date"][5:], row.get("bounce_rate", 0)) for row in daily[-21:]],
                value_suffix="%",
            ))
        top_ips = sorted(
            suspicious_patterns.get("suspicious_ips", []),
            key=lambda x: x.get("bounce_count", 0),
            reverse=True,
        )[:10]
        if top_ips:
            charts.append(self._bar_chart(
                "Топ IP по отказам",
                [(row["ip"], row.get("bounce_count", 0)) for row in top_ips],
            ))
        categories = suspicious_patterns.get("attack_categories", [])[:8]
        if categories:
            charts.append(self._bar_chart(
                "Категории атак",
                [(row["category"], row.get("count", 0)) for row in categories],
            ))
        payloads = security.get("payload_summary", [])[:6]
        if payloads:
            charts.append(self._bar_chart(
                "Payload patterns",
                [(row["payload_type"], row.get("count", 0)) for row in payloads],
            ))
        if not charts:
            return None
        rows = []
        for idx in range(0, len(charts), 2):
            row = charts[idx:idx + 2]
            if len(row) == 1:
                row.append("")
            rows.append(row)
        table = Table(rows, colWidths=[82 * mm, 82 * mm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    def _line_chart(self, title, points, value_suffix=""):
        from reportlab.graphics.charts.lineplots import LinePlot
        from reportlab.graphics.shapes import Drawing, String
        from reportlab.lib import colors
        from reportlab.lib.units import mm

        drawing = Drawing(78 * mm, 45 * mm)
        drawing.add(String(0, 116, title, fontName="ReportFont", fontSize=8.5, fillColor=colors.HexColor("#102A43")))
        if not points:
            return drawing
        values = [float(v) for _, v in points]
        data = [(idx, value) for idx, value in enumerate(values)]
        chart = LinePlot()
        chart.x = 8
        chart.y = 20
        chart.width = 190
        chart.height = 80
        chart.data = [data]
        chart.lines[0].strokeColor = colors.HexColor("#2F80ED")
        chart.lines[0].strokeWidth = 1.8
        chart.xValueAxis.valueMin = 0
        chart.xValueAxis.valueMax = max(1, len(values) - 1)
        chart.xValueAxis.valueStep = max(1, len(values) // 4)
        chart.yValueAxis.valueMin = 0
        chart.yValueAxis.valueMax = max(values) * 1.15 if max(values) else 1
        chart.yValueAxis.valueStep = max(1, round(chart.yValueAxis.valueMax / 4))
        drawing.add(chart)
        latest_label = f"{values[-1]:.1f}{value_suffix}"
        drawing.add(String(158, 104, latest_label, fontName="ReportFont", fontSize=8, fillColor=colors.HexColor("#486581")))
        return drawing

    def _bar_chart(self, title, items):
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.shapes import Drawing, String
        from reportlab.lib import colors
        from reportlab.lib.units import mm

        drawing = Drawing(78 * mm, 45 * mm)
        drawing.add(String(0, 116, title, fontName="ReportFont", fontSize=8.5, fillColor=colors.HexColor("#102A43")))
        values = [float(v) for _, v in items] or [0]
        chart = VerticalBarChart()
        chart.x = 8
        chart.y = 20
        chart.width = 190
        chart.height = 80
        chart.data = [values]
        chart.bars[0].fillColor = colors.HexColor("#3E7CB1")
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(values) * 1.15 if max(values) else 1
        chart.valueAxis.valueStep = max(1, round(chart.valueAxis.valueMax / 4))
        chart.categoryAxis.labels.boxAnchor = "ne"
        chart.categoryAxis.labels.angle = 35
        chart.categoryAxis.labels.fontName = "ReportFont"
        chart.categoryAxis.labels.fontSize = 5.6
        chart.categoryAxis.categoryNames = [self._short_label(label) for label, _ in items]
        drawing.add(chart)
        return drawing

    def _short_label(self, label):
        label = str(label)
        return label if len(label) <= 12 else label[:10] + "…"

    def _find_ttf_font(self):
        candidates = [
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial Unicode.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
        for candidate in candidates:
            path = Path(candidate)
            if path.exists():
                return path
        raise FileNotFoundError("Не найден TTF-шрифт с кириллицей")

    def _rl_table(self, rows, col_widths, font_size=8, header=True):
        from reportlab.lib import colors
        from reportlab.platypus import Paragraph, Table, TableStyle
        from reportlab.lib.styles import ParagraphStyle

        cell_style = ParagraphStyle("Cell", fontName="ReportFont", fontSize=font_size, leading=font_size + 2)
        header_style = ParagraphStyle("HeaderCell", fontName="ReportFontBold", fontSize=font_size, leading=font_size + 2, textColor=colors.HexColor("#102A43"))
        data = []
        for r_idx, row in enumerate(rows):
            style = header_style if header and r_idx == 0 else cell_style
            data.append([Paragraph(self._p(value), style) for value in row])
        table = Table(data, colWidths=col_widths, repeatRows=1 if header else 0, hAlign="LEFT")
        table_style = [
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D9E2EC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        if header:
            table_style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6EEF6")))
        table.setStyle(TableStyle(table_style))
        return table

    def _code_block(self, text):
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import Preformatted, Table, TableStyle
        from reportlab.lib.styles import ParagraphStyle

        style = ParagraphStyle(
            "CodeBlock",
            fontName="ReportFont",
            fontSize=7.2,
            leading=9.2,
            textColor=colors.HexColor("#102A43"),
        )
        block = Preformatted(str(text), style, maxLineLength=118)
        table = Table([[block]], colWidths=[165 * mm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.35, colors.HexColor("#D9E2EC")),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return table

    def _p(self, value):
        return html.escape(str(value), quote=True).replace("\n", "<br/>")

    def _page_footer(self, canvas, doc):
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm

        canvas.saveState()
        canvas.setFont("ReportFont", 7)
        canvas.setFillColorRGB(0.38, 0.49, 0.6)
        canvas.drawString(doc.leftMargin, 9 * mm, "Log Analyzer Pro")
        canvas.drawRightString(A4[0] - doc.rightMargin, 9 * mm, f"Стр. {doc.page}")
        canvas.restoreState()

    def _html_to_pdf(self, html_content):
        converter = shutil.which("cupsfilter")
        if not converter:
            raise RuntimeError("Не найден cupsfilter: PDF можно создать на macOS/Linux с установленным CUPS.")

        output_path = Path(self.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", suffix=".html", encoding="utf-8", delete=False) as tmp:
            tmp.write(html_content)
            tmp_path = Path(tmp.name)
        try:
            result = subprocess.run(
                [converter, "-m", "application/pdf", str(tmp_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode != 0 or not result.stdout:
                err = result.stderr.decode("utf-8", errors="ignore").strip()
                raise RuntimeError(f"cupsfilter не смог создать PDF: {err}")
            output_path.write_bytes(result.stdout)
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def _write_simple_pdf(self, bounce_analysis, suspicious_patterns, load_analysis, investigation):
        lines = self._build_plain_lines(bounce_analysis, suspicious_patterns, load_analysis, investigation or {})
        writer = _SimpleUnicodePdf(self.output_path)
        writer.write(lines)

    def _build_plain_lines(self, bounce_analysis, suspicious_patterns, load_analysis, investigation):
        security = investigation.get("security", {})
        contrib = investigation.get("bounce_contribution", {})
        lines = [
            ("h1", "Отчет по direct-трафику и подозрительной активности"),
            ("p", f"Сформировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"),
            ("h2", "Ключевые показатели"),
            ("p", f"Direct: {bounce_analysis.get('total_direct', 0):,}"),
            ("p", f"Отказы: {bounce_analysis.get('bounces', 0):,}"),
            ("p", f"Bounce Rate: {bounce_analysis.get('bounce_rate', 0):.2f}%"),
            ("p", f"Подозрительные IP: {len(suspicious_patterns.get('suspicious_ips', []))}"),
        ]
        if load_analysis:
            lines.extend([
                ("p", f"Периоды высокой нагрузки: {len(load_analysis.get('high_load_periods', []))}"),
                ("p", f"Аномальные периоды: {len(load_analysis.get('anomalies', []))}"),
            ])
        if investigation.get("conclusion"):
            lines.extend([("h2", "Executive Summary"), ("p", investigation["conclusion"])])
        if contrib:
            lines.extend([
                ("h2", "Вклад подозрительного трафика в bounce"),
                ("p", f"Исходный Bounce Rate: {contrib.get('raw_bounce_rate', 0):.2f}%"),
                ("p", f"Подозрительные отказы: {contrib.get('suspicious_bounces', 0):,}"),
                ("p", f"Доля подозрительных отказов: {contrib.get('suspicious_bounce_share', 0):.2f}%"),
                ("p", f"Bounce Rate после исключения: {contrib.get('cleaned_bounce_rate', 0):.2f}%"),
            ])
        if security.get("mitre_matrix"):
            lines.append(("h2", "Матрица угроз"))
            for row in security["mitre_matrix"][:10]:
                lines.append(("p", f"{row['stage']} | {row['mitre_tactic']} | events={row['events']} | risk={row['risk']} | {row['evidence']}"))
        if investigation.get("recommendations"):
            lines.append(("h2", "Рекомендации по IP"))
            for row in investigation["recommendations"][:15]:
                lines.append(("p", f"{row['ip']} | {row['action']} | {row['severity']} | bounces={row['bounce_count']} | {row['attack_categories']}"))
        if security.get("successful_sensitive"):
            lines.append(("h2", "Возможные успешные обращения"))
            for row in security["successful_sensitive"][:20]:
                lines.append(("p", f"{row['time'].strftime('%Y-%m-%d %H:%M')} | {row['ip']} | {row['status']} | {row['risk']} | {row['category']} | {row['url']}"))
        if security.get("payload_summary"):
            lines.append(("h2", "Payload summary"))
            for row in security["payload_summary"][:10]:
                lines.append(("p", f"{row['payload_type']}: {row['count']}"))
        if security.get("campaigns"):
            lines.append(("h2", "Крупные волны активности"))
            for row in security["campaigns"][:10]:
                lines.append(("p", f"{row['period_start'].strftime('%Y-%m-%d %H:%M')} | requests={row['request_count']} | ips={row['top_ips']} | {row['top_categories']}"))
        if investigation.get("rules"):
            lines.append(("h2", "Готовые правила"))
            for rule in investigation["rules"][:5]:
                lines.append(("h3", rule["type"]))
                lines.append(("p", rule["description"]))
                for rule_line in rule["rule"].splitlines()[:30]:
                    lines.append(("code", rule_line))
        if investigation.get("allowlist_notes"):
            lines.append(("h2", "Что не блокировать автоматически"))
            for row in investigation["allowlist_notes"]:
                lines.append(("p", f"{row['item']} | {row['action']} | {row['note']}"))
        return lines

    def _build_html(self, bounce_analysis, suspicious_patterns, load_analysis, investigation, summary_extra):
        esc = lambda value: html.escape(str(value), quote=True)
        investigation = investigation or {}
        security = investigation.get("security", {})
        contrib = investigation.get("bounce_contribution", {})
        suspicious_ips = sorted(
            suspicious_patterns.get("suspicious_ips", []),
            key=lambda x: (x.get("score", 0), x.get("bounce_count", 0)),
            reverse=True,
        )
        top_recs = investigation.get("recommendations", [])[:12]
        top_rules = investigation.get("rules", [])[:5]

        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        anomaly_count = len(load_analysis.get("anomalies", [])) if load_analysis else 0
        high_load_count = len(load_analysis.get("high_load_periods", [])) if load_analysis else 0

        parts = [self._styles()]
        parts.append("<body>")
        parts.append(f"""
            <section class="cover">
                <div class="eyebrow">Log Analyzer Pro</div>
                <h1>Отчет по direct-трафику и подозрительной активности</h1>
                <div class="subtitle">Сформировано: {esc(generated)}</div>
                <div class="summary-grid">
                    {self._metric("Direct", f"{bounce_analysis.get('total_direct', 0):,}")}
                    {self._metric("Отказы", f"{bounce_analysis.get('bounces', 0):,}")}
                    {self._metric("Bounce Rate", f"{bounce_analysis.get('bounce_rate', 0):.2f}%")}
                    {self._metric("Подозрительные IP", len(suspicious_ips))}
                    {self._metric("Аномальные периоды", anomaly_count)}
                    {self._metric("Высокая нагрузка", high_load_count)}
                </div>
            </section>
        """)

        if investigation.get("conclusion"):
            parts.append(f"""
                <section>
                    <h2>Executive Summary</h2>
                    <p class="lead">{esc(investigation['conclusion'])}</p>
                </section>
            """)

        if contrib:
            parts.append("""
                <section>
                    <h2>Вклад подозрительного трафика в bounce</h2>
                    <table>
                        <thead><tr><th>Метрика</th><th>Значение</th></tr></thead>
                        <tbody>
            """)
            rows = [
                ("Исходный Bounce Rate", f"{contrib.get('raw_bounce_rate', 0):.2f}%"),
                ("Подозрительных отказов", f"{contrib.get('suspicious_bounces', 0):,}"),
                ("Доля подозрительных отказов", f"{contrib.get('suspicious_bounce_share', 0):.2f}%"),
                ("Bounce Rate после исключения", f"{contrib.get('cleaned_bounce_rate', 0):.2f}%"),
            ]
            for label, value in rows:
                parts.append(f"<tr><td>{esc(label)}</td><td>{esc(value)}</td></tr>")
            parts.append("</tbody></table></section>")

        if security.get("mitre_matrix"):
            parts.append("""
                <section>
                    <h2>Матрица угроз</h2>
                    <table>
                        <thead><tr><th>Стадия</th><th>MITRE</th><th>Событий</th><th>Риск</th><th>Доказательства</th></tr></thead>
                        <tbody>
            """)
            for row in security["mitre_matrix"][:10]:
                parts.append(
                    "<tr>"
                    f"<td>{esc(row['stage'])}</td>"
                    f"<td>{esc(row['mitre_tactic'])}</td>"
                    f"<td>{esc(row['events'])}</td>"
                    f"<td>{esc(row['risk'])}</td>"
                    f"<td>{esc(row['evidence'])}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table></section>")

        if top_recs:
            parts.append("""
                <section>
                    <h2>Рекомендации по IP</h2>
                    <table>
                        <thead><tr><th>IP</th><th>Действие</th><th>Критичность</th><th>Отказов</th><th>Категории</th></tr></thead>
                        <tbody>
            """)
            for row in top_recs:
                parts.append(
                    "<tr>"
                    f"<td>{esc(row['ip'])}</td>"
                    f"<td>{esc(row['action'])}</td>"
                    f"<td>{esc(row['severity'])}</td>"
                    f"<td>{esc(row['bounce_count'])}</td>"
                    f"<td>{esc(row['attack_categories'])}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table></section>")

        if security.get("successful_sensitive"):
            parts.append("""
                <section class="page-break">
                    <h2>Возможные успешные обращения к чувствительным путям</h2>
                    <p class="note">2xx/3xx по чувствительным URL не означает подтвержденный взлом, но требует ручной проверки конечного ответа, редиректа и наличия файла.</p>
                    <table>
                        <thead><tr><th>Время</th><th>IP</th><th>Статус</th><th>Категория</th><th>URL</th><th>Риск</th></tr></thead>
                        <tbody>
            """)
            for row in security["successful_sensitive"][:25]:
                parts.append(
                    "<tr>"
                    f"<td>{esc(row['time'].strftime('%Y-%m-%d %H:%M'))}</td>"
                    f"<td>{esc(row['ip'])}</td>"
                    f"<td>{esc(row['status'])}</td>"
                    f"<td>{esc(row['category'])}</td>"
                    f"<td class='url'>{esc(row['url'])}</td>"
                    f"<td>{esc(row['risk'])}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table></section>")

        if security.get("payload_summary") or security.get("campaigns"):
            parts.append("<section><h2>Payload и волны активности</h2>")
            if security.get("payload_summary"):
                parts.append("<h3>Payload summary</h3><table><thead><tr><th>Payload</th><th>Количество</th></tr></thead><tbody>")
                for row in security["payload_summary"][:10]:
                    parts.append(f"<tr><td>{esc(row['payload_type'])}</td><td>{esc(row['count'])}</td></tr>")
                parts.append("</tbody></table>")
            if security.get("campaigns"):
                parts.append("<h3>Крупные волны</h3><table><thead><tr><th>Час</th><th>Запросов</th><th>IP</th><th>Категории</th></tr></thead><tbody>")
                for row in security["campaigns"][:10]:
                    parts.append(
                        "<tr>"
                        f"<td>{esc(row['period_start'].strftime('%Y-%m-%d %H:%M'))}</td>"
                        f"<td>{esc(row['request_count'])}</td>"
                        f"<td>{esc(row['top_ips'])}</td>"
                        f"<td>{esc(row['top_categories'])}</td>"
                        "</tr>"
                    )
                parts.append("</tbody></table>")
            parts.append("</section>")

        if top_rules:
            parts.append("<section class='page-break'><h2>Приложение: готовые правила</h2>")
            for rule in top_rules:
                parts.append(f"<h3>{esc(rule['type'])}</h3><p>{esc(rule['description'])}</p><pre>{esc(rule['rule'])}</pre>")
            parts.append("</section>")

        if investigation.get("allowlist_notes"):
            parts.append("<section><h2>Что не блокировать автоматически</h2><table><thead><tr><th>Объект</th><th>Действие</th><th>Комментарий</th></tr></thead><tbody>")
            for row in investigation["allowlist_notes"]:
                parts.append(f"<tr><td>{esc(row['item'])}</td><td>{esc(row['action'])}</td><td>{esc(row['note'])}</td></tr>")
            parts.append("</tbody></table></section>")

        parts.append("</body>")
        return "\n".join(parts)

    def _metric(self, label, value):
        return f"<div class='metric'><div class='metric-value'>{html.escape(str(value))}</div><div class='metric-label'>{html.escape(str(label))}</div></div>"

    def _styles(self):
        return """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
        <meta charset="UTF-8">
        <style>
            @page { size: A4; margin: 16mm 14mm 16mm 14mm; }
            * { box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif; color: #1f2933; line-height: 1.45; font-size: 11px; }
            section { margin-bottom: 18px; page-break-inside: avoid; }
            .cover { border-bottom: 2px solid #243b53; padding-bottom: 12px; margin-bottom: 20px; }
            .eyebrow { color: #486581; text-transform: uppercase; letter-spacing: 1px; font-size: 10px; font-weight: 700; }
            h1 { font-size: 25px; margin: 8px 0 8px; color: #102a43; line-height: 1.15; }
            h2 { font-size: 17px; margin: 18px 0 8px; color: #102a43; border-bottom: 1px solid #d9e2ec; padding-bottom: 4px; }
            h3 { font-size: 13px; margin: 12px 0 5px; color: #243b53; }
            .subtitle, .note { color: #52606d; }
            .lead { font-size: 12px; background: #f0f4f8; border-left: 4px solid #3e7cb1; padding: 10px 12px; }
            .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 12px; }
            .metric { border: 1px solid #d9e2ec; padding: 8px; background: #f8fafc; }
            .metric-value { font-size: 18px; font-weight: 700; color: #102a43; }
            .metric-label { color: #627d98; font-size: 10px; }
            table { width: 100%; border-collapse: collapse; margin-top: 6px; page-break-inside: auto; }
            tr { page-break-inside: avoid; page-break-after: auto; }
            th { background: #e6eef6; color: #102a43; font-weight: 700; }
            th, td { border: 1px solid #d9e2ec; padding: 5px 6px; vertical-align: top; }
            td.url { font-family: Menlo, Consolas, monospace; font-size: 9px; word-break: break-all; }
            pre { white-space: pre-wrap; font-family: Menlo, Consolas, monospace; font-size: 9px; background: #f8fafc; border: 1px solid #d9e2ec; padding: 8px; }
            .page-break { page-break-before: always; }
        </style>
        </head>
        """


class _SimpleUnicodePdf:
    """Минимальный PDF writer с Type0 Unicode font fallback."""

    def __init__(self, output_path):
        self.output_path = Path(output_path)
        self.width = 595
        self.height = 842
        self.margin_x = 46
        self.margin_y = 48
        self.line_gap = 4
        self.objects = []

    def write(self, styled_lines):
        pages = self._paginate(styled_lines)
        catalog_id = 1
        pages_id = 2
        font_id = 3
        descendant_id = 4
        tounicode_id = 5
        self.objects = [None] * 5
        self.objects[catalog_id - 1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        self.objects[font_id - 1] = b"<< /Type /Font /Subtype /Type0 /BaseFont /ArialUnicodeMS /Encoding /Identity-H /DescendantFonts [4 0 R] /ToUnicode 5 0 R >>"
        self.objects[descendant_id - 1] = (
            b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ArialUnicodeMS "
            b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
            b"/DW 1000 >>"
        )
        cmap = self._to_unicode_cmap()
        self.objects[tounicode_id - 1] = f"<< /Length {len(cmap)} >>\nstream\n".encode("latin1") + cmap + b"\nendstream"

        content_ids = []
        for page in pages:
            content = self._page_content(page)
            content_ids.append(self._add_obj(f"<< /Length {len(content)} >>\nstream\n".encode("latin1") + content + b"\nendstream"))

        page_obj_ids = []
        for content_id in content_ids:
            page_obj_ids.append(self._add_obj(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width} {self.height}] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode("latin1")
            ))
        kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        self.objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_ids)} >>".encode("latin1")

        self._write_pdf()

    def _add_obj(self, data):
        self.objects.append(data)
        return len(self.objects)

    def _paginate(self, styled_lines):
        pages = []
        page = []
        y = self.height - self.margin_y
        for style, text in styled_lines:
            font_size = self._font_size(style)
            max_chars = self._max_chars(style)
            wrapped = []
            for part in str(text).splitlines() or [""]:
                wrapped.extend(textwrap.wrap(part, width=max_chars, break_long_words=True, replace_whitespace=False) or [""])
            for idx, line in enumerate(wrapped):
                needed = font_size + self.line_gap + (8 if style in {"h1", "h2"} and idx == 0 else 0)
                if y - needed < self.margin_y:
                    pages.append(page)
                    page = []
                    y = self.height - self.margin_y
                page.append((style, line, y))
                y -= needed
            if style in {"h1", "h2", "h3"}:
                y -= 4
        if page:
            pages.append(page)
        return pages or [[("p", "Нет данных", self.height - self.margin_y)]]

    def _page_content(self, page):
        chunks = [b"BT\n"]
        for style, text, y in page:
            font_size = self._font_size(style)
            x = self.margin_x
            chunks.append(f"/F1 {font_size} Tf\n".encode("latin1"))
            chunks.append(f"1 0 0 1 {x} {y} Tm\n".encode("latin1"))
            chunks.append(f"<{self._hex_utf16(text)}> Tj\n".encode("latin1"))
        chunks.append(b"ET")
        return b"".join(chunks)

    def _font_size(self, style):
        return {"h1": 19, "h2": 15, "h3": 12, "code": 8}.get(style, 10)

    def _max_chars(self, style):
        return {"h1": 54, "h2": 66, "h3": 78, "code": 112}.get(style, 96)

    def _hex_utf16(self, text):
        return str(text).encode("utf-16-be", errors="replace").hex().upper()

    def _to_unicode_cmap(self):
        return b"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
1 beginbfrange
<0000> <FFFF> <0000>
endbfrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end"""

    def _write_pdf(self):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        offsets = []
        data = bytearray(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
        for idx, obj in enumerate(self.objects, 1):
            offsets.append(len(data))
            data.extend(f"{idx} 0 obj\n".encode("latin1"))
            data.extend(obj)
            data.extend(b"\nendobj\n")
        xref = len(data)
        data.extend(f"xref\n0 {len(self.objects) + 1}\n".encode("latin1"))
        data.extend(b"0000000000 65535 f \n")
        for off in offsets:
            data.extend(f"{off:010d} 00000 n \n".encode("latin1"))
        data.extend(
            f"trailer\n<< /Size {len(self.objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("latin1")
        )
        self.output_path.write_bytes(bytes(data))
