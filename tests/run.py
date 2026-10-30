"""Run Harrier's tests: python tests/run.py [--ai] [name-filter]

Replay tests need nothing. --ai also runs the red-team suite against the real Ollama model.
Writes tests/report.json so results can be compared between runs.
"""
import importlib
import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]
os.environ.setdefault("DASHBOARD_PASSWORD", "pw")


def main():
    args = sys.argv[1:]
    modules = ["test_detection", "test_safety", "test_learning", "test_network", "test_auth", "test_plumbing"] + (["test_ai"] if "--ai" in args else [])
    filt = next((a for a in args if not a.startswith("--")), "")
    results, t0 = [], time.time()
    for name in modules:
        mod = importlib.import_module(name)
        for fn in [getattr(mod, f) for f in dir(mod) if f.startswith("test_") and filt in f]:
            import harrier
            import netwatch
            saved_net = netwatch.fetch_queries
            saved = {k: getattr(harrier, k) for k in ("dns_records", "http_info", "tls_info", "notify", "INTEL",
                                                       "CADDY_LOG", "AUTH_LOG", "UFW_LOG", "KESTREL_DB", "SCHEMA")}
            start = time.time()
            try:
                fn()
                status, detail = "pass", ""
            except AssertionError as e:
                where = traceback.extract_tb(e.__traceback__)[-1]
                status, detail = "fail", f"line {where.lineno}: {where.line}" + (f"\n     {str(e)[:600]}" if str(e) else "")
            except Exception:
                status, detail = "error", traceback.format_exc(limit=3)[-900:]
            finally:
                for k, v in saved.items():
                    setattr(harrier, k, v)
                netwatch.fetch_queries = saved_net
            results.append({"test": f"{name}.{fn.__name__}", "status": status, "detail": detail,
                            "seconds": round(time.time() - start, 2)})
            mark = {"pass": "PASS", "fail": "FAIL", "error": "ERR "}[status]
            print(f"{mark} {name}.{fn.__name__}" + (f"\n     {detail.strip()[:400]}" if detail else ""), flush=True)
    try:  # drop every throwaway test schema
        import db as dbmod
        c = dbmod.connect()
        for (name,) in c.execute("select schema_name from information_schema.schemata where schema_name like 't\\_%'").fetchall():
            c.execute(f"drop schema {name} cascade")
        c.close()
    except Exception as e:
        print(f"(couldn't clean up test schemas: {e})")
    bad = [r for r in results if r["status"] != "pass"]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed in {time.time() - t0:.0f}s")
    with open(os.path.join(HERE, "report.json"), "w") as f:
        json.dump({"at": time.time(), "results": results}, f, indent=1)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
