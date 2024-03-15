import json
import logging
import os
import time
import requests
import datetime
from tqdm import tqdm


class CVECrawler:
    ENDPOINT_NIST = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def __init__(self,
                 path_storage='./cve',
                 request_timeout=25,
                 retry_interval=300,
                 retries_for_request=9):
        self.path_storage = path_storage
        self.request_timeout = request_timeout
        self.retry_interval = retry_interval
        self.retries_for_request = retries_for_request

    def run(self):
        if not os.path.exists(self.path_storage):
            os.makedirs(self.path_storage)
        self.download_cve()
        print('ok')

    def download_cve(self):
        with open('cve2download.txt', 'r') as file:
            for cve in file:
                cve = cve.rstrip()
                query = f"?cveId={cve}"
                url = self.ENDPOINT_NIST + query
                print(url)
                try:
                    response = requests.get(url, timeout=self.request_timeout)
                    if response.status_code == 200:
                        self.add_references_to_json_and_save(response.json())
                        print(f"ok {cve}")
                    else:
                        print(f"err {cve}, err: {response.status_code}")
                        # with open('still_missing.txt', 'a') as f:
                            # f.write(cve + '\n')
                except Exception as e:
                    print(f"err {cve}, exp: {e}")
                    # with open('still_missing.txt', 'a') as f:
                            # f.write(cve + '\n')
                time.sleep(6)

    def add_references_to_json_and_save(self, response_json):
        json_list = response_json['vulnerabilities']
        print(response_json)
        logging.info("Adding raw references to items")
        for e in json_list:
            complete_json = self.fetch_and_add_references_to_json(e)
            self.save_data(complete_json)

    @staticmethod
    def fetch_and_add_references_to_json(json_data):
        references = []
        try:
            for ref in json_data['cve']['references']:
                references.append(ref['url'])
            read_references = []
            for ref_url in references:
                try:
                    response = requests.get(ref_url, timeout=3)
                    if response.status_code == 200:
                        read_references.append((ref_url, response.text))
                    else:
                        read_references.append((ref_url, response.status_code))
                except:
                    read_references.append((ref_url, "Error with the request"))
            json_data['cve']['added_references'] = read_references
        except:
            pass
        return json_data

    def save_data(self, json_data):
        try:
            cve = json_data['cve']['id']
            split_cve = cve.split('-')
            year = split_cve[1]
            cve_padded = str('{:06d}'.format(int(split_cve[2])))
            year_path = os.path.join(self.path_storage, year)
            if not os.path.exists(year_path):
                os.makedirs(year_path)
            two_digits_path = os.path.join(year_path, cve_padded[:2])
            if not os.path.exists(two_digits_path):
                os.makedirs(two_digits_path)
            one_digit_path = os.path.join(two_digits_path, cve_padded[2:4])
            if not os.path.exists(one_digit_path):
                os.makedirs(one_digit_path)
            with open(os.path.join(one_digit_path, f'CVE-{year}-{cve_padded}.json'), 'w') as file:
                file.write(json.dumps(json_data))
        except Exception as e:
            print(f"err {e}")


CVECrawler().run()