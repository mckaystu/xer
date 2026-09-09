"""Regression: Domino $ServerJavaScriptLibrary SSJS extraction."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from analytics.code_auditor.extractor import extract_units_from_dxl_bytes, extract_units_from_path
from analytics.code_auditor.function_inventory import build_inventory
from dxl_parser import parse_script_library
from dxl_ssjs import decode_server_javascript_chunks, extract_server_javascript_library
from xml.etree import ElementTree as ET


def _b64_chunk(source: str, *, header: bytes = b"\xf9\xff \x00N\x00N\x00N\x00") -> str:
    return base64.b64encode(header + source.encode("latin-1")).decode("ascii")


MINI_SSJS = """\
/****************************************************************************
 * test library
 */
var accounting = {
	claimsPayments : {
		exportUnprocessed : function() {
			var db:NotesDatabase = session.getDatabase("", "abms\\\\claimspaymentconfig.nsf");
			var doc:NotesDocument = db.getDocumentByUNID(unid);
			doc.recycle();
		},
		uploadFile : function() {
			var db:NotesDatabase = session.getDatabase("", "abms\\\\claimspaymentconfig.nsf");
			var doc:NotesDocument = db.getDocumentByUNID(docid);
			doc.recycle();
		}
	}
};
var blueprism = {
	getAttachment : function() {
		var db:NotesDatabase = session.getCurrentDatabase();
		print(db.getTitle());
	}
};
"""


def _scriptlibrary_dxl(name: str, source: str, *, client: bool = False) -> str:
    payload = _b64_chunk(source)
    item = "$ClientJavaScriptLibrary" if client else "$ServerJavaScriptLibrary"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<database xmlns="http://www.lotus.com/dxl">
  <scriptlibrary name="{name}" hide="v3 v4strict">
    <item name="{item}" sign="true">
      <rawitemdata type="1">{payload}</rawitemdata>
    </item>
  </scriptlibrary>
</database>
"""


class TestDecodeServerJavaScript:
    def test_decode_concatenates_chunks(self):
        a = _b64_chunk("var a = 1;\n")
        b = _b64_chunk("var b = 2;\n")
        body = decode_server_javascript_chunks([a, b])
        assert "var a = 1;" in body
        assert "var b = 2;" in body

    def test_extract_from_element(self):
        root = ET.fromstring(_scriptlibrary_dxl("ssjs", MINI_SSJS))
        lib = next(e for e in root.iter() if e.tag.endswith("scriptlibrary"))
        body = extract_server_javascript_library(lib)
        assert body
        assert "exportUnprocessed : function" in body
        assert "uploadFile : function" in body
        assert "getAttachment : function" in body


class TestParserAndExtractor:
    def test_parse_script_library_includes_server_js(self):
        root = ET.fromstring(_scriptlibrary_dxl("ssjs", MINI_SSJS))
        lib_elem = next(e for e in root.iter() if e.tag.endswith("scriptlibrary"))
        model = parse_script_library(lib_elem, "t.dxl", "db1")
        assert model.code_events
        body = model.code_events[0].body
        assert model.code_events[0].language == "ssjs"
        assert "exportUnprocessed" in body
        assert "uploadFile" in body
        assert "getAttachment" in body

    def test_auditor_extractor_emits_unit(self):
        units = extract_units_from_dxl_bytes(_scriptlibrary_dxl("ssjs", MINI_SSJS), "t.dxl")
        ssjs = [u for u in units if u.element_name == "ssjs"]
        assert len(ssjs) == 1
        assert ssjs[0].language == "ssjs"
        assert "exportUnprocessed" in ssjs[0].body

    def test_client_js_tagged_csjs_low_priority_not_removed(self):
        from analytics.code_auditor.context import inventory_risk_severity
        from analytics.code_auditor.function_inventory import run_function_inventory

        dxl = _scriptlibrary_dxl("csjsClaims", "var x = 1;\nfunction hi(){ return 1; }\n", client=True)
        units = extract_units_from_dxl_bytes(dxl, "t.dxl")
        assert units
        assert units[0].language == "csjs"
        assert units[0].event == "client_library"
        assert (
            inventory_risk_severity(
                status="UNPROTECTED_ALLOCATION",
                in_loop=True,
                language="csjs",
                element_name="csjsClaims",
            )
            == "LOW"
        )
        graph = {
            "business_logic": [
                {
                    "owner_type": "scriptlibrary",
                    "owner_name": "csjsClaims",
                    "language": "javascript",
                    "event": "client_library",
                    "body": "function hi(){ var doc = db.getDocumentByUNID(id); while(doc){ doc = db.getDocumentByUNID(id); } }\n",
                },
                {
                    "owner_type": "scriptlibrary",
                    "owner_name": "ssjsApi",
                    "language": "javascript",
                    "event": "library",
                    "body": "function exportUnprocessed(){ var doc = db.getDocumentByUNID(id); while(doc!=null){ doc = db.getDocumentByUNID(id); } }\n",
                },
            ]
        }
        out = run_function_inventory(graph=graph)
        inv = out["inventory"]
        names = [r["function_name"] for r in inv]
        assert "exportUnprocessed" in names
        assert "hi" in names  # CSJS kept, not removed
        # SSJS sorts before CSJS
        assert names.index("exportUnprocessed") < names.index("hi")
        csjs_rows = [r for r in inv if "csjs" in (r.get("design_element") or "").lower()]
        assert csjs_rows
        assert all(r.get("risk_severity") == "LOW" for r in csjs_rows)
        assert out["summary"].get("csjs_functions_low_priority", 0) >= 1

    def test_inventory_sees_claims_payments_methods(self):
        units = extract_units_from_dxl_bytes(_scriptlibrary_dxl("ssjs", MINI_SSJS), "t.dxl")
        recs = build_inventory(units)
        names = {r.function_name for r in recs}
        # Brace extractor should find nested object methods
        assert "exportUnprocessed" in names or any("exportUnprocessed" in (r.function_name or "") for r in recs)
        assert "uploadFile" in names or any("uploadFile" in (r.function_name or "") for r in recs)
        assert "getAttachment" in names or any("getAttachment" in (r.function_name or "") for r in recs)


@pytest.mark.skipif(
    not Path("dxl_input_fromboss/Code_FrombossRest.dxl").exists(),
    reason="FrombossRest DXL not present",
)
class TestFrombossRestLive:
    def test_ssjs_library_contains_claims_payments_apis(self):
        path = Path("dxl_input_fromboss/Code_FrombossRest.dxl")
        units = extract_units_from_path(path)
        ssjs = [u for u in units if u.element_name == "ssjs"]
        assert ssjs, "ssjs script library not extracted"
        body = ssjs[0].body
        assert "exportUnprocessed : function" in body
        assert "uploadFile : function" in body
        assert "getAttachment : function" in body
        recs = build_inventory(ssjs)
        blob = "\n".join(f"{r.function_name}\n{r.code_snippet_as_is or ''}" for r in recs)
        assert "exportUnprocessed" in blob
        assert "uploadFile" in blob
        assert "getAttachment" in blob
