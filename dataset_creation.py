import os
import pandas as pd
import gzip
import glob
import json


def init(threshold, storage_path):
    if not os.path.exists(storage_path):
        os.mkdir(storage_path)
    complete_dataset_path = os.path.join(storage_path, 'dataset.csv')
    if not os.path.exists(complete_dataset_path):
        path_epss_folder = '/share/smartdata/security/phishing/epss'
        print('Starting reading from filesystem...')
        all_files = glob.glob(os.path.join(path_epss_folder, '*', '*', '*.csv.gz'))
        dfs = []
        for file in all_files:
            with gzip.open(file, 'rt') as file_gz:
                df_temp = pd.read_csv(file_gz, comment='#')
                df_temp['date'] = str(os.path.splitext(os.path.basename(file))[0]).replace('.csv', '')
                dfs.append(df_temp)
        df_dataset = pd.concat(dfs, ignore_index=True)
        df_dataset['date'] = pd.to_datetime(df_dataset['date'], format='%Y-%m-%d')
        df_dataset = df_dataset.sort_values(by=['date'])
        df_dataset.to_csv(complete_dataset_path, index=False)
        print('Complete dataset saved')
        date_new_model = '03-07-2023'
        dataset_epss_v2_path = os.path.join(storage_path, 'epss_v2.csv')
        df_epss_v2 = df_dataset[df_dataset['date'] < date_new_model]
        df_epss_v2.to_csv(dataset_epss_v2_path, index=False)
        print('EPSS v2 dataset saved')
        dataset_epss_v3_path = os.path.join(storage_path, 'epss_v3.csv')
        df_epss_v3 = df_dataset[df_dataset['date'] >= date_new_model]
        df_epss_v3.to_csv(dataset_epss_v3_path, index=False)
        print('EPSS v3 dataset saved')
        filter_by_threshold(df_dataset, threshold, os.path.join(storage_path, 'dataset_highest.csv'))
        filter_by_threshold(df_epss_v2, threshold, os.path.join(storage_path, 'epss_v2_highest.csv'))
        filter_by_threshold(df_epss_v3, threshold, os.path.join(storage_path, 'epss_v3_highest.csv'))
        print('Datasets with highest EPSS saved')


def filter_by_threshold(df, threshold, path):
    highest_cve = set(df.groupby('cve').filter(lambda e: (e['epss'] > threshold).any())['cve'])
    df_highest = df[df['cve'].isin(highest_cve)]
    df_highest.to_csv(path, index=False)


def download_dataset_and_extract_cve_pz():
    doc_id = '1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY'
    tab_name = 'All'
    url = f"https://docs.google.com/spreadsheets/d/{doc_id}/gviz/tq?tqx=out:csv&sheet={tab_name}"
    df_pz_sheet = pd.read_csv(url)
    cve_pz = set(df_pz_sheet['CVE'].dropna().apply(lambda r: r if 'CVE' in r else None).dropna())
    return df_pz_sheet, cve_pz


def download_dataset_and_extract_cve_kev():
    url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
    df_kev_sheet = pd.read_csv(url)
    cve_kev = set(df_kev_sheet['cveID'].dropna().apply(lambda r: r if 'CVE' in r else None).dropna())
    return df_kev_sheet, cve_kev


def save_or_read_filtered_df(path, df, cve_list):
    if not os.path.exists(path):
        df_res = df[df['cve'].isin(cve_list)]
        df_res.to_csv(path, index=False)
    else:
        with open(path, 'r') as file_csv:
            df_res = pd.read_csv(file_csv)
        df_res['date'] = pd.to_datetime(df_res['date'])
    print('df of CVEs from Google Project Zero ready')
    return df_res
