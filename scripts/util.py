import matplotlib.pyplot as plt
import fastplot
import pandas as pd
import datetime
import os
import numpy as np


def plot_cve_timeseries_of(dataset, cve_list):
    path = f"outputs/timeseries_{str(datetime.datetime.now()).replace(' ', '')}"
    os.mkdir(path)
    for cve in cve_list:
        full_path = os.path.join(path, f'{cve}.png')
        data = dataset[dataset['cve'] == cve][['epss', 'date', 'percentile']]
        ts = pd.Series(data['epss'].values, index=data['date'].values)
        date_from = pd.Timestamp(str(data['date'].min()).split(' ')[0])
        date_to = pd.Timestamp(str(data['date'].max()).split(' ')[0])
        fastplot.plot(ts, full_path, mode='timeseries', xlabel='Date', ylabel=f'{cve}', xticks_rotate=30, 
                      grid=True, ylim=(0.0, 1.0), xlim=(pd.Timestamp(date_from), pd.Timestamp(date_to)),
                      yticks=(np.arange(0, 1.25, step=0.25), None))