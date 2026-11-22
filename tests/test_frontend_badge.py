"""Scan-brand data label badge colour: synthetic data must be purple ("syn"), even though its text says "NOT recorded"."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from baseera.serp import SYNTH_LABEL_AR, SYNTH_LABEL_EN, recorded_label

APP = Path(__file__).resolve().parent.parent / "frontend" / "app.js"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_data_label_class_order():
    ar, en = recorded_label("2026-11-20")
    labels = {
        f"{SYNTH_LABEL_AR} / {SYNTH_LABEL_EN}": "syn",
        f"SerpAPI unavailable (ConnectError); {SYNTH_LABEL_AR} / {SYNTH_LABEL_EN}": "syn",
        f"{ar} / {en}": "rec",
        "live (SerpAPI)": "off",
        "لا توجد بيانات مسجلة لهذه الجهة / no recorded or example data for this brand": "na",
    }
    js = ("const src=require('fs').readFileSync(process.argv[1],'utf8');"
          "eval(src.match(/function dataLabelClass[\\s\\S]*?\\n}/)[0]);"
          "const L=JSON.parse(process.argv[2]);console.log(JSON.stringify(L.map(dataLabelClass)));")
    out = subprocess.run(["node", "-e", js, str(APP), json.dumps(list(labels))], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == list(labels.values())
