import glob
import json
import pandas as pd
from tqdm import tqdm


file_paths = glob.glob(f'../../security_dir_link/phishing/cve/*/*/*/*.json')
data = []
for file_path in tqdm(file_paths, desc="Processing files", unit="file"):
    with open(file_path, "r") as f:
        json_data = json.load(f)
        cve_info = json_data.get("cve", {})
        
        if "added_references" in cve_info:
            del cve_info["added_references"]
        data_dict = {
            "id": cve_info.get("id"),
            "sourceIdentifier": cve_info.get("sourceIdentifier"),
            "published": cve_info.get("published"),
            "lastModified": cve_info.get("lastModified"),
            "vulnStatus": cve_info.get("vulnStatus"),
            "description": next(
                (
                    desc["value"].replace(',', '').replace('\n', '').replace('\r', '')
                    for desc in cve_info.get("descriptions", [])
                    if desc.get("lang") == "en"
                ),
                None,
            ),
        }
        
        for metric_version in ["cvssMetricV4", "cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]:
            if key_metrics := cve_info.get("metrics", {}).get(metric_version):
                primary_metric_info = next(
                    (
                        metric_info
                        for metric_info in key_metrics
                        if metric_info.get("type") == "Primary"
                    ),
                    None,
                )
                if primary_metric_info:
                    cvss_data = primary_metric_info.get("cvssData", {})
                    data_dict.update(
                        {
                            "cvssVersion": cvss_data.get("version"),
                            "cvssVectorString": cvss_data.get("vectorString"),
                            "cvssBaseScore": cvss_data.get("baseScore"),
                            "cvssExploitabilityScore": primary_metric_info.get(
                                "exploitabilityScore"
                            ),
                            "cvssImpactScore": primary_metric_info.get("impactScore"),
                        }
                    )
                    break
                    
        if key_weaknesses := cve_info.get("weaknesses"):
            data_dict["weaknesses"] = ";".join(
                e["value"]
                for weakness in key_weaknesses
                if weakness.get("type") == "Primary"
                for e in weakness.get("description", [])
            )
            
        if key_configurations := cve_info.get("configurations"):
            data_dict["CPEs"] = ";".join(
                sub_sub_node["criteria"]
                for node in key_configurations
                for sub_node in node.get("nodes", [])
                for sub_sub_node in sub_node.get("cpeMatch", [])
            )
            
        if key_references := cve_info.get("references"):
            data_dict["references"] = ";".join(ref["url"].split("/")[2] for ref in key_references)
        data.append(data_dict)
        
df = pd.DataFrame(data)
df = df.sort_values(by=['id'])
df.to_csv(f'../datasets_new/cve_info.csv', index=False)

