"""Paper-compatible metric definitions (IRIS, ICLR 2025, Table 1), shared by evaluate.py.

Per evaluation row (one project analysed for one CWE), from the IRIS evaluator output
(src/modules/evaluation_pipeline.py, fixed-location rule = a path is a true positive when one
of its locations lies in a fixed (file, class, method) of fix_info.csv, excluding src/test):
  Alerts     = num_results
  Paths      = num_paths
  TP Alerts  = num_tp_results_method
  TP Paths   = num_tp_paths_method
  Recall     = 1 if recall_method else 0
  Precision  = TP Alerts / Alerts            (undefined when Alerts == 0)
  F1         = 2PR / (P + R)                 (0 when Precision is undefined or P + R == 0)

Aggregates, reverse-engineered from and validated against vendor/iris-v1/results/*.csv:
  #Detected  = number of rows with Recall == 1
  AvgFDR     = mean over rows with Alerts > 0 of (1 - Precision)
  AvgF1      = mean over ALL rows of F1 (rows without alerts contribute 0)
Rows that failed to execute contribute Recall 0 / F1 0 and are excluded from AvgFDR (no alerts);
they are always listed separately, and completed-only variants are reported alongside.
MicroFDR (1 - sum TP Alerts / sum Alerts) is reported separately and is NOT the paper's AvgFDR.
"""


def row_metrics(ev):
    """ev: dict from IRIS evaluator (num_results, num_paths, recall_method, ...) or None."""
    if not ev:
        return None
    alerts = int(ev.get("num_results", 0))
    tp_alerts = int(ev.get("num_tp_results_method", 0))
    recall = 1 if ev.get("recall_method") else 0
    precision = (tp_alerts / alerts) if alerts > 0 else None
    if precision is None or (precision + recall) == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"alerts": alerts, "paths": int(ev.get("num_paths", 0)), "tp_alerts": tp_alerts,
            "tp_paths": int(ev.get("num_tp_paths_method", 0)), "recall": recall,
            "precision": precision, "f1": f1,
            "recall_file": 1 if ev.get("recall_file") else 0}


def aggregate(rows):
    """rows: list of dicts with keys status ('completed' or other), recall, precision, f1, alerts, tp_alerts, cwe."""
    n = len(rows)
    done = [r for r in rows if r["status"] == "completed"]
    detected = sum(1 for r in done if r["recall"] == 1)
    with_alerts = [r for r in done if r["alerts"] > 0]
    avg_fdr = (sum(1 - r["precision"] for r in with_alerts) / len(with_alerts)) if with_alerts else None
    avg_f1 = (sum(r["f1"] for r in done) / n) if n else None
    avg_f1_completed = (sum(r["f1"] for r in done) / len(done)) if done else None
    tot_alerts = sum(r["alerts"] for r in done)
    micro_fdr = (1 - sum(r["tp_alerts"] for r in done) / tot_alerts) if tot_alerts else None
    out = {
        "n_rows": n,
        "n_completed": len(done),
        "n_not_completed": n - len(done),
        "not_completed": sorted(r["eval_id"] for r in rows if r["status"] != "completed"),
        "detected": detected,
        "detection_rate": detected / n if n else None,
        "detection_rate_completed_only": detected / len(done) if done else None,
        "avg_fdr": avg_fdr,
        "avg_fdr_n_rows_with_alerts": len(with_alerts),
        "avg_f1": avg_f1,
        "avg_f1_completed_only": avg_f1_completed,
        "micro_fdr_NOT_PAPER_METRIC": micro_fdr,
        "total_alerts": tot_alerts,
        "total_tp_alerts": sum(r["tp_alerts"] for r in done),
        "total_paths": sum(r["paths"] for r in done),
    }
    per_cwe = {}
    for cwe in sorted({r["cwe"] for r in rows}):
        sub = [r for r in rows if r["cwe"] == cwe]
        sd = [r for r in sub if r["status"] == "completed"]
        swa = [r for r in sd if r["alerts"] > 0]
        per_cwe[cwe] = {"n_rows": len(sub), "n_completed": len(sd),
                        "detected": sum(1 for r in sd if r["recall"] == 1),
                        "avg_fdr": (sum(1 - r["precision"] for r in swa) / len(swa)) if swa else None,
                        "avg_f1": sum(r["f1"] for r in sd) / len(sub) if sub else None}
    out["per_cwe"] = per_cwe
    return out


def artifact_csv_rows(path):
    """Rows of an original IRIS results/*.csv file in the same shape as aggregate() expects."""
    import csv
    rows = []
    for r in csv.DictReader(open(path)):
        try:
            prec = float(r["Precision"])
        except ValueError:
            prec = None
        try:
            f1 = float(r["F1"])
        except ValueError:
            f1 = 0.0
        alerts = int(r["Alerts"]) if r["Alerts"].isdigit() else 0
        tp_alerts = int(r["TP Alerts"]) if r["TP Alerts"].isdigit() else 0
        rows.append({"eval_id": f"{r['CVE']}/{r['CWE ID']}", "cve": r["CVE"], "cwe": r["CWE ID"],
                     "status": "completed", "recall": 1 if r["Recall"] == "1" else 0,
                     "precision": prec, "f1": f1, "alerts": alerts if prec is not None else 0,
                     "tp_alerts": tp_alerts, "paths": int(r["Paths"]) if r["Paths"].isdigit() else 0})
    return rows
