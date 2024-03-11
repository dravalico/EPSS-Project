import os
import pandas as pd
import gzip
import glob
import json


def init(threshold=0.7, storage_path='../datasets_new'):
    if not os.path.exists(storage_path):
        os.mkdir(storage_path)
    complete_dataset_path = os.path.join(storage_path, 'dataset.csv')
    if not os.path.exists(complete_dataset_path):
        path_epss_folder = '/share/smartdata/security/phishing/epss'
        print('Reading from filesystem...')
        all_files = glob.glob(os.path.join(path_epss_folder, '*', '*', '*.csv.gz'))
        dfs = []
        for file in all_files:
            with gzip.open(file, 'rt') as file_gz:
                df_temp = pd.read_csv(file_gz, comment='#')
                df_temp['date'] = str(os.path.splitext(os.path.basename(file))[0]).replace('.csv', '')
                dfs.append(df_temp)

        # Save base datasets
        df_dataset = pd.concat(dfs, ignore_index=True)
        df_dataset['date'] = pd.to_datetime(df_dataset['date'], format='%Y-%m-%d')
        df_dataset = df_dataset.sort_values(by=['date'])
        df_dataset.to_csv(complete_dataset_path, index=False)
        df_dataset.to_pickle(os.path.join(storage_path, 'dataset.pkl'))
        date_new_model = '03-07-2023'
        dataset_epss_v2_path = os.path.join(storage_path, 'epss_v2.csv')
        df_epss_v2 = df_dataset[df_dataset['date'] < date_new_model]
        df_epss_v2.to_csv(dataset_epss_v2_path, index=False)
        df_epss_v2.to_pickle(os.path.join(storage_path, 'epss_v2.pkl'))
        dataset_epss_v3_path = os.path.join(storage_path, 'epss_v3.csv')
        df_epss_v3 = df_dataset[df_dataset['date'] >= date_new_model]
        df_epss_v3.to_csv(dataset_epss_v3_path, index=False)
        df_epss_v3.to_pickle(os.path.join(storage_path, 'epss_v3.pkl'))

        # Save dataset with CVE >T and <=T
        save_by_filter_threshold(df_dataset, threshold, storage_path, 'dataset')
        save_by_filter_threshold(df_epss_v2, threshold, storage_path, 'epss_v2')
        save_by_filter_threshold(df_epss_v3, threshold, storage_path, 'epss_v3')
        print('Completed')


def save_by_filter_threshold(df, threshold, path, name):
    highest_cve = set(df.groupby('cve').filter(lambda e: (e['epss'] > threshold).any())['cve'])
    df_highest = df[df['cve'].isin(highest_cve)]
    df_highest.to_csv(os.path.join(path, name + '_highest.csv'), index=False)
    df_highest.to_pickle(os.path.join(path, name + '_highest.pkl'))
    df_lowest = df[~df['cve'].isin(highest_cve)]
    df_lowest.to_csv(os.path.join(path, name + '_lowest.csv'), index=False)
    df_lowest.to_pickle(os.path.join(path, name + '_lowest.pkl'))


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


if __name__ == '__main__':
    init()
