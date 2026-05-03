import yaml, sys

d = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else r"api/openapi.yaml", "r", encoding="utf-8"))
paths = d["paths"]
print(f"paths total: {len(paths)}")
ops = 0
by_tag = {}
for p, item in paths.items():
    for m in ["get", "post", "put", "patch", "delete"]:
        if m in item:
            ops += 1
            tags = item[m].get("tags", ["?"])
            for t in tags:
                by_tag.setdefault(t, []).append(f"{m.upper()} {p}")
print(f"operations total: {ops}")
print()
for t in sorted(by_tag):
    print(f"[{t}] ({len(by_tag[t])})")
    for op in by_tag[t]:
        print(f"  {op}")
print()
print("schemas:", len(d["components"]["schemas"]))
print("responses:", len(d["components"]["responses"]))
print("security schemes:", list(d["components"]["securitySchemes"].keys()))
print("OK")
