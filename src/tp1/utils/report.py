import pygal
from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from markdown_pdf import MarkdownPdf, Section


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str, title: str = "Rapport Réseau") -> None:
        self.capture = capture
        self.filename = filename
        self.title = title
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report (Markdown)
        """
        content = ""
        content += f"# {self.title}\n\n"
        content += f"## Résumé\n\n{self.summary}\n\n"
        content += f"## Tableau des protocoles\n\n{self.array}\n\n"
        content += f"## Graph \n\n![Répartition des protocoles]({self.graph})\n"
        return content

    def save(self) -> None:
        """
        Save report in a Markdown file + PDF
        """
        final_content = self.concat_report()

        pdf = MarkdownPdf()
        pdf.meta["title"] = self.title
        pdf.add_section(Section(final_content, toc=False))
        pdf.save(self.filename.replace(".md", ".pdf"))

        logger.info(f"Rapport sauvegardé en Markdown ({self.filename}) et PDF")


    def generate(self, param: str) -> None:
        """
        Generate graph or array
        """
        protocols = self.capture.protocols

        if not protocols:
            logger.info("Aucune donnée à afficher")
            return

        if param == "array":
            self.array = self._generate_array(protocols)

        elif param == "graph":
            self.graph = self._generate_graph(protocols)

    def _generate_array(self, protocols: dict) -> str:
        """
        Generate a Markdown table of protocols
        """
        lines = []
        lines.append("| Protocole | Nombre de paquets |")
        lines.append("|-----------|-------------------|")

        for proto, count in protocols.items():
            lines.append(f"| {proto} | {count} |")

        return "\n".join(lines)

    def _generate_graph(self, protocols: dict) -> str:
        """
        Generate a pygal bar chart and save it as PNG (for PDF compatibility)
        """
        bar_chart = pygal.Bar()
        bar_chart.title = "Répartition des protocoles réseau"

        for protocol, count in protocols.items():
            bar_chart.add(protocol, count)

        graph_filename = self.filename.replace(".md", "_graph.png")
        bar_chart.render_to_png(graph_filename)

        logger.info(f"Graphe Pygal sauvegardé dans {graph_filename}")
        return graph_filename

