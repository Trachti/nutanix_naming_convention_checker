import http.client, json, ssl

NTNX_PRISMCENTRAL_IP = "YOUR_IP:9440"
PC_TOKEN = "YOUR GENERATED TOKEN FROM nutanix_auth.py"

def api_request(method, url, payload=None):
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(NTNX_PRISMCENTRAL_IP, context=context)
    headers = {"Accept": "application/json", "Authorization": PC_TOKEN, "Content-Type": "application/json"}
    body = json.dumps(payload) if isinstance(payload, dict) else payload
    conn.request(method, url, body=body, headers=headers)
    res = conn.getresponse()
    raw = res.read().decode("utf-8")
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {"raw": raw}
    if res.status >= 400:
        raise RuntimeError(f"API error {res.status} on {url}: {data}")
    return data

def list_entities(kind, endpoint):
    offset = 0
    out = []
    while True:
        data = api_request("POST", endpoint, {"kind": kind, "length": 100, "offset": offset})
        entities = data.get("entities", [])
        if not entities:
            break
        out.extend(entities)
        total = data.get("metadata", {}).get("total_matches")
        offset += 100
        if total is not None and offset >= total:
            break
    return out

import argparse, re
from datetime import datetime, timezone

def vm_info(vm):
    meta=vm.get("metadata",{}); spec=vm.get("spec",{}); status=vm.get("status",{}); cluster=status.get("cluster_reference") or spec.get("cluster_reference") or {}
    return {"name":spec.get("name") or status.get("name"),"uuid":meta.get("uuid"),"description":spec.get("description") or "","categories":meta.get("categories") or {},"project_reference":meta.get("project_reference") or {},"cluster":cluster.get("name") or cluster.get("uuid")}

def allowed_rules(items):
    out={}
    for item in items or []:
        if "=" not in item: raise ValueError(f"Invalid rule: {item}. Expected KEY=value1,value2.")
        k,v=item.split("=",1); out[k.strip()]={x.strip() for x in v.split(",") if x.strip()}
    return out

def check(info,args):
    f=[]; cats=info["categories"]
    if args.name_regex and not re.fullmatch(args.name_regex, info["name"] or ""): f.append({"type":"invalid_vm_name","severity":"medium","reason":f"Name does not match regex: {args.name_regex}"})
    if args.require_description and not info["description"].strip(): f.append({"type":"missing_description","severity":"low","reason":"VM description is empty."})
    if args.require_project and not info["project_reference"]: f.append({"type":"missing_project","severity":"low","reason":"VM has no project reference."})
    for cat in args.required_category or []:
        if cat not in cats: f.append({"type":"missing_category","severity":"medium","reason":f"Required category is missing: {cat}"})
    for k,vals in allowed_rules(args.allowed_category_values).items():
        if k in cats and str(cats[k]) not in vals: f.append({"type":"invalid_category_value","severity":"medium","reason":f"Category {k} has invalid value '{cats[k]}'."})
    return f

def main():
    p=argparse.ArgumentParser(description="Check Nutanix VM names, descriptions, projects, and categories.")
    p.add_argument("--name-regex",default=r"[a-z0-9][a-z0-9-]{2,62}"); p.add_argument("--required-category",action="append"); p.add_argument("--allowed-category-values",action="append"); p.add_argument("--require-description",action="store_true"); p.add_argument("--require-project",action="store_true"); p.add_argument("--json-file")
    a=p.parse_args(); results=[]
    for vm in list_entities("vm","/api/nutanix/v3/vms/list"):
        info=vm_info(vm); findings=check(info,a)
        if findings: results.append({"name":info["name"],"uuid":info["uuid"],"cluster":info["cluster"],"findings":findings})
    print(json.dumps(results,indent=2,ensure_ascii=False))
    if a.json_file:
        out={"generated_at":datetime.now(timezone.utc).isoformat(),"results":results,"vm_count_with_findings":len(results),"finding_count":sum(len(x["findings"]) for x in results)}
        open(a.json_file,"w",encoding="utf-8").write(json.dumps(out,indent=2,ensure_ascii=False))
    if results: raise SystemExit(1)
if __name__=="__main__": main()
