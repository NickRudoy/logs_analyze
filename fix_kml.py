import argparse
from pathlib import Path
import xml.etree.ElementTree as ET


KML_NS = "http://www.opengis.net/kml/2.2"
NS = {"k": KML_NS}
ET.register_namespace("", KML_NS)


def get_text(el):
    return (el.text or "").strip() if el is not None else ""


def build_description(data_map, placemark):
    obj_name = data_map.get("Название объекта") or get_text(placemark.find("k:name", NS))
    addr = data_map.get("Адрес", "")
    city = data_map.get("Город", "")

    parts = [f"Название объекта: {obj_name or '(не указано)'}"]
    if addr:
        parts.append(f"Адрес: {addr}")
    if city:
        parts.append(f"Город: {city}")
    return "<br>".join(parts)


def write_with_cdata(tree, output_path, cdata_values):
    xml_text = ET.tostring(tree.getroot(), encoding="unicode")
    for placeholder, value in cdata_values.items():
        safe_value = value.replace("]]>", "]]]]><![CDATA[>")
        xml_text = xml_text.replace(placeholder, f"<![CDATA[{safe_value}]]>")
    Path(output_path).write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_text,
        encoding="utf-8",
    )


def fix_kml(input_path, output_path):
    tree = ET.parse(input_path)
    root = tree.getroot()
    cdata_values = {}

    for idx, placemark in enumerate(root.findall(".//k:Placemark", NS)):
        ext = placemark.find("k:ExtendedData", NS)
        data_map = {}
        if ext is not None:
            for data in ext.findall("k:Data", NS):
                name = (data.get("name") or "").strip()
                val = get_text(data.find("k:value", NS))
                if name:
                    data_map[name] = val

        lat = data_map.get("latitude") or data_map.get("Latitude")
        lon = data_map.get("longitude") or data_map.get("Longitude")

        desc_el = placemark.find("k:description", NS)
        if desc_el is None:
            desc_el = ET.SubElement(placemark, f"{{{KML_NS}}}description")
        placeholder = f"__KML_DESCRIPTION_CDATA_{idx}__"
        desc_el.text = placeholder
        cdata_values[placeholder] = build_description(data_map, placemark)

        has_geom = any(
            placemark.find(tag, NS) is not None
            for tag in ("k:Point", "k:LineString", "k:Polygon")
        )
        if not has_geom and lat and lon:
            point = ET.SubElement(placemark, f"{{{KML_NS}}}Point")
            coords = ET.SubElement(point, f"{{{KML_NS}}}coordinates")
            coords.text = f"{lon},{lat}"

    write_with_cdata(tree, output_path, cdata_values)


def main():
    parser = argparse.ArgumentParser(description="Fix KML descriptions and missing point geometry.")
    parser.add_argument("input", help="Path to source .kml file")
    parser.add_argument("output", nargs="?", help="Path to fixed .kml file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Файл не найден: {input_path}")

    output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_fixed.kml")
    fix_kml(input_path, output_path)
    print("Готово:", output_path)


if __name__ == "__main__":
    main()
