import os
import sys
from tqdm import tqdm

try:
    folder = sys.argv[1]
except:
    print('Usage: python check_folder_similarity.py <folder_path>')
    exit(-1)

ls = list(filter(lambda elem: 'exe' in elem, os.listdir(folder)))

for exe in tqdm(ls):
    os.system('python exe_similarity.py ' + folder + exe + ' PRINT_RESULT')