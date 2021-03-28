import subprocess
import os
from pprint import pprint
import json
import pandas as pd
#path_to_file = "/opt/exploit-database/exploits/windows/dos/9691.pl"
#os.system('pp -M PAR -M Data::Dumper -x -o 9691 /opt/exploit-database/exploits/windows/dos/9691.pl')
with open('cvelist.json', 'r') as f:
    cvelist = json.load(f)
#pprint(cvelist)
df = pd.read_csv('/home/mattia/Downloads/cve_with_exploits.csv')
print(df)