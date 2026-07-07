"""
Semgrep stage 0 — build named_graphs_cwe.trig from the MITRE CWE XML.

Replaces ontology_clean.ipynb (no hand-typed XML path). Produces the CWE
hierarchy that semgrep_4_evaluate.py consumes, as (child) schema:child_of (parent)
edges. ParentOf relations are inverted to child_of so there is one relation type,
and duplicate edges (MITRE lists most relations from both sides) are removed.

VIEW selection MATTERS for the HP rate:
  VIEW = None   -> all views (view-agnostic; matches the paper's get_*_ontov path
                   and how stage 4 traverses). DEFAULT.
  VIEW = "1000" -> Research view only (restrict if the paper filtered to one view).

Run:  python semgrep_0_build_cwe_ontology.py
Requires: pip install rdflib lxml requests
Output:   named_graphs_cwe.trig  (+ cwe_ontology_provenance.txt)
"""

import zipfile
import logging
from pathlib import Path

import requests
from lxml import etree
from rdflib import Dataset, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
ZIP_PATH = Path("cwec_latest.xml.zip")
LOCAL_XML = None                 # set to a path to skip download (offline/pinned)
OUT_TRIG = Path("named_graphs_cwe.trig")
PROVENANCE = Path("cwe_ontology_provenance.txt")

VIEW = None                      # None = all views (default). e.g. "1000" to restrict.

CWE = Namespace("https://cwe.mitre.org/data/definitions/")
CWEV = Namespace("https://cwe.mitre.org/views/")
SCHEMA = Namespace("http://schema.org/")


def get_xml():
    if LOCAL_XML:
        return Path(LOCAL_XML)
    if not ZIP_PATH.exists():
        logging.info(f"Downloading {CWE_ZIP_URL}")
        r = requests.get(CWE_ZIP_URL, timeout=180)
        r.raise_for_status()
        ZIP_PATH.write_bytes(r.content)
        logging.info(f"Wrote {ZIP_PATH} ({len(r.content)} bytes)")
    with zipfile.ZipFile(ZIP_PATH) as z:
        member = next((n for n in z.namelist() if n.lower().endswith(".xml")), None)
        if not member:
            raise RuntimeError("No XML inside the CWE ZIP.")
        out = Path("cwec_latest.xml")
        out.write_bytes(z.read(member))
        logging.info(f"Extracted {member} -> {out}")
        return out


def build(xml_path):
    root = etree.parse(str(xml_path)).getroot()
    # namespace-agnostic: don't hardcode the cwe-7 schema URI (it bumps over versions)
    def lx(node, name):
        return node.xpath(f".//*[local-name()='{name}']")

    catalog = {"version": root.get("Version"), "date": root.get("Date"),
               "name": root.get("Name")}
    logging.info(f"CWE catalog: {catalog}")

    ds = Dataset()
    ds.add((CWE.Weakness, RDF.type, SCHEMA.Thing))
    weaknesses = root.xpath("//*[local-name()='Weakness']")
    logging.info(f"Weaknesses: {len(weaknesses)}")

    edges = set()                # (child_id, parent_id, view_id) -> dedup
    raw = 0
    for w in weaknesses:
        wid = w.get("ID")
        if not wid:
            continue
        cwe_uri = URIRef(CWE[wid])
        ds.add((cwe_uri, RDF.type, CWE.Weakness))
        if w.get("Name"):
            ds.add((cwe_uri, RDFS.label, Literal(w.get("Name"))))
        for rw in lx(w, "Related_Weakness"):
            nature = rw.get("Nature")
            rel = rw.get("CWE_ID")
            view = rw.get("View_ID") or "default"
            if not rel or (VIEW is not None and view != VIEW):
                continue
            if nature == "ChildOf":            # this weakness is a child of `rel`
                edges.add((wid, rel, view)); raw += 1
            elif nature == "ParentOf":          # `rel` is a child of this weakness
                edges.add((rel, wid, view)); raw += 1

    for child, parent, view in edges:
        ds.add((URIRef(CWE[child]), SCHEMA.child_of, URIRef(CWE[parent]), URIRef(CWEV[view])))

    logging.info(f"child_of edges: {len(edges)} unique (from {raw} raw; "
                 f"{raw - len(edges)} duplicates removed)")
    return ds, catalog, len(edges)


def main():
    ds, catalog, n_edges = build(get_xml())
    ds.serialize(destination=str(OUT_TRIG), format="trig")
    PROVENANCE.write_text(
        f"CWE catalog name: {catalog.get('name')}\n"
        f"CWE catalog version: {catalog.get('version')}\n"
        f"CWE catalog date: {catalog.get('date')}\n"
        f"Source: {CWE_ZIP_URL}\n"
        f"View filter: {VIEW if VIEW is not None else 'all views (view-agnostic)'}\n"
        f"child_of edges: {n_edges}\n", encoding="utf-8")
    logging.info(f"Wrote {OUT_TRIG.resolve()}")
    logging.info(f"Provenance -> {PROVENANCE} (cite the catalog version for reproducibility)")
    logging.info("Next: python semgrep_4_evaluate.py")


if __name__ == "__main__":
    main()
