from planner import plan
from executor import execute
from memory import retrieve_memory, store_memory
from utils.parser import parse_dependency_file
from datetime import datetime, timezone


def merge_all_deps(parsed_data):
    combined = {}
    combined.update(parsed_data.get("dependencies", {}))
    combined.update(parsed_data.get("devDependencies", {}))
    combined.update(parsed_data.get("peerDependencies", {}))
    return combined

def agent_main(file_key,dep_file_path):
    with open(dep_file_path, "r") as f:
        content = f.read()

    parsed_data, file_type = parse_dependency_file(dep_file_path, content)
    combined_deps = merge_all_deps(parsed_data)

    last_scan = retrieve_memory(file_key)
    plan_tasks = plan(combined_deps, last_scan)

    parsed_results, patched_file, risk_score = execute(plan_tasks, combined_deps, parsed_data, file_type)

    improvement = None
    if last_scan and "risk_score" in last_scan:
        previous_score = last_scan["risk_score"]
        improvement = previous_score - risk_score

    store_memory(file_key, {
        'dependencies': parsed_data,
        'risk_score': risk_score,
        'report': parsed_results,
        'patched_file': patched_file,
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'file_type': file_type
    })


    return parsed_results, patched_file, risk_score, improvement