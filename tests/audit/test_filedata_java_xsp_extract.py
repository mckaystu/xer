"""Regression: $FileData Java / XPage extraction on DXL load."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from xml.etree import ElementTree as ET

from analytics.code_auditor.extractor import extract_units_from_dxl_bytes, extract_units_from_path
from analytics.code_auditor.function_inventory import build_inventory, run_function_inventory
from dxl_filedata import decode_filedata_chunks, extract_javascript_from_xpage
from dxl_parser import build_graph_from_dxl_bytes


def _b64(source: str, header: bytes = b"a\x00\x18\x00" + b"\x00" * 37) -> str:
    return base64.b64encode(header + source.encode("utf-8")).decode("ascii")


JAVA_SRC = """\
package com.mbre.rest;

import lotus.domino.Database;
import lotus.domino.Document;
import lotus.domino.Session;

public class Reporting {
  public Document load(Session s, String unid) throws Exception {
    Database db = s.getDatabase(null, "abms/bossrest.nsf");
    Document doc = db.getDocumentByUNID(unid);
    return doc;
  }
}
"""

XSP_SRC = """\
<?xml version="1.0" encoding="UTF-8"?>
<xp:view xmlns:xp="http://www.ibm.com/xsp/core">
  <xp:this.beforePageLoad><![CDATA[#{javascript:accounting.claimsPayments.exportUnprocessed()}]]></xp:this.beforePageLoad>
  <xp:button id="btn">
    <xp:eventHandler event="onclick" submit="true">
      <xp:this.action><![CDATA[#{javascript:var db = session.getDatabase("", "x.nsf"); db.recycle();}]]></xp:this.action>
    </xp:eventHandler>
  </xp:button>
</xp:view>
"""


def _note_dxl(title: str, body: str) -> str:
    payload = _b64(body)
    return f"""
<note class='form'>
  <item name='$TITLE'><text>{title}</text></item>
  <item name='$FileData' sign='true'>
    <rawitemdata type='1'>{payload}</rawitemdata>
  </item>
</note>
"""


def _database_dxl(*notes: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<database xmlns="http://www.lotus.com/dxl" title="T" path="t.nsf">\n'
        + "\n".join(notes)
        + "\n</database>\n"
    )


class TestFileDataDecode:
    def test_decode_java(self):
        body = decode_filedata_chunks([_b64(JAVA_SRC)])
        assert "package com.mbre.rest;" in body
        assert "getDocumentByUNID" in body

    def test_xpage_js_fragments(self):
        frags = extract_javascript_from_xpage(XSP_SRC)
        bodies = [b for _, b in frags]
        assert any("exportUnprocessed" in b for b in bodies)
        assert any("getDatabase" in b for b in bodies)


class TestGraphLoadIncludesJavaAndJs:
    def test_build_graph_from_dxl_bytes(self):
        dxl = _database_dxl(
            _note_dxl("com/mbre/rest/Reporting.java", JAVA_SRC),
            _note_dxl("xagentExport.xsp", XSP_SRC),
        )
        graph = build_graph_from_dxl_bytes(dxl.encode("utf-8"), "fixture.dxl")
        langs = {b["language"] for b in graph["business_logic"]}
        assert "java" in langs
        assert "javascript" in langs or "xpages" in langs
        assert graph["meta"]["totals"].get("file_resources", 0) >= 2
        owners = {b["owner_name"] for b in graph["business_logic"]}
        assert "com/mbre/rest/Reporting.java" in owners
        assert "xagentExport.xsp" in owners
        # Inventory from graph must see Java method + SSJS fragments
        inv = run_function_inventory(graph=graph)
        names = {r["function_name"] for r in inv["inventory"]}
        assert "load" in names or any("Reporting" in str(r.get("design_element")) for r in inv["inventory"])
        blob = "\n".join(
            f"{r.get('function_name')}\n{r.get('code_snippet_as_is') or ''}" for r in inv["inventory"]
        )
        assert "getDocumentByUNID" in blob or "exportUnprocessed" in blob or "getDatabase" in blob


class TestAuditorExtractorFileData:
    def test_extract_units(self):
        dxl = _database_dxl(
            _note_dxl("com/mbre/rest/Reporting.java", JAVA_SRC),
            _note_dxl("xagentExport.xsp", XSP_SRC),
        )
        units = extract_units_from_dxl_bytes(dxl, "fixture.dxl")
        java = [u for u in units if u.language == "java"]
        js = [u for u in units if u.language in {"javascript", "ssjs", "xpages"}]
        assert java
        assert any("Reporting" in u.element_name for u in java)
        assert js
        recs = build_inventory(java)
        assert any(r.function_name == "load" for r in recs)


@pytest.mark.skipif(
    not Path("dxl_input_fromboss/Code_FrombossRest.dxl").exists(),
    reason="FrombossRest DXL not present",
)
class TestFrombossRestJavaXspLive:
    def test_load_extracts_java_and_xpage_js(self):
        path = Path("dxl_input_fromboss/Code_FrombossRest.dxl")
        content = path.read_bytes()
        graph = build_graph_from_dxl_bytes(content, path.name)
        bl = graph["business_logic"]
        java = [b for b in bl if b.get("language") == "java"]
        js = [b for b in bl if b.get("language") in {"javascript", "ssjs"}]
        xpages = [b for b in bl if b.get("language") == "xpages"]
        assert len(java) >= 100, f"expected ~109 java files, got {len(java)}"
        assert len(xpages) >= 50, f"expected many xpages, got {len(xpages)}"
        assert len(js) >= 100, f"expected XPage SSJS fragments, got {len(js)}"
        bodies = "\n".join(b.get("body") or "" for b in js + java)
        assert "exportUnprocessed" in bodies
        assert "uploadFile" in bodies or "getDocumentByUNID" in bodies

        units = extract_units_from_path(path)
        assert sum(1 for u in units if u.language == "java") >= 100
