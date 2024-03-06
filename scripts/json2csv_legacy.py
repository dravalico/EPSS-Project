import glob
import json
import pandas as pd
from tqdm import tqdm


file_paths = glob.glob(f'../../security_dir_link/phishing/cve/*/*/*/*.json')
data = []
for file_path in tqdm(file_paths, desc="Processing files", unit="file"):
    data_dict = {}
    with open(file_path, 'r') as f:
        json_data = json.load(f)
        cve_info = json_data.get('cve', {})
        if 'added_references' in cve_info:
            del cve_info['added_references']
        data_dict['id'] = cve_info['id']
        data_dict['sourceIdentifier'] = cve_info['sourceIdentifier']
        data_dict['published'] = cve_info['published']
        data_dict['lastModified'] = cve_info['lastModified']
        data_dict['vulnStatus'] = cve_info['vulnStatus']
        
        key_descriptions = 'descriptions'
        if key_descriptions in cve_info:
            for description in cve_info[key_descriptions]:
                if description['lang'] == 'en':
                    data_dict['description'] = description['value']
                    break
                
        key_metrics = 'metrics'
        if key_metrics in cve_info:
            metrics = ['cvssMetricV4', 'cvssMetricV31', 'cvssMetricV3', 'cvssMetricV2']
            for metric in metrics:
                if metric in cve_info[key_metrics]:
                    for metric_name in cve_info[key_metrics]:
                        for metric_info in cve_info[key_metrics][metric_name]:
                            if metric_info['type'] == 'Primary':
                                data_dict['cvssVersion'] = metric_info['cvssData']['version']
                                data_dict['cvssVectorString'] = metric_info['cvssData']['vectorString']
                                data_dict['cvssBaseScore'] = metric_info['cvssData']['baseScore']
                                data_dict['cvssExploitabilityScore'] = metric_info['exploitabilityScore']
                                data_dict['cvssImpactScore'] = metric_info['impactScore']
                                break
                        break
        
        key_weaknesses = 'weaknesses'
        if key_weaknesses in cve_info:
            weakness_list = []
            for weakness in cve_info[key_weaknesses]:
                if weakness['type'] == 'Primary':
                    for e in weakness['description']:
                        weakness_list.append(e['value'])
                    break
            data_dict[key_weaknesses] = ";".join(weakness_list)
        
        key_configurations = 'configurations'
        if key_configurations in cve_info:
            cpe_list = []
            for node in cve_info[key_configurations]:
                for sub_node in node['nodes']:
                    for sub_sub_node in sub_node['cpeMatch']:
                        cpe_list.append(sub_sub_node['criteria'])
            data_dict['CPEs'] = ";".join(cpe_list)
        
        key_references = 'references'
        if key_references in cve_info:
            ref_list = []
            for ref in cve_info[key_references]:
                ref_list.append(ref['url'].split('/')[2])
            data_dict[key_references] = ";".join(ref_list)
        data.append(data_dict)
        
df = pd.DataFrame(data)
df = df.sort_values(by=['id'])
df.to_csv(f'./datasets/cve_info.csv', index=False)