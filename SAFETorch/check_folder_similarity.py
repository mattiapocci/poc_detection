import os
import sys
from tqdm import tqdm
import torch

try:
    folder = sys.argv[1]
except:
    print('Usage: python check_folder_similarity.py <folder_path>')
    exit(-1)

ls = list(filter(lambda elem: 'exe' in elem, os.listdir(folder)))

try:
    already_processed = torch.load('already_processed.pt')
except:
    already_processed = []

for exe in tqdm(ls):
    if exe in already_processed:
        print('Skipping ' + exe + ': already processed')
        continue
    print('Beginning ' + exe)
    os.system('python exe_similarity.py ' + folder + exe + ' Malwarebazaar')
    os.system('python check_similarity_scores.py ' + 'Malwarebazaar/' + exe.replace('.exe','.pt'))
    already_processed.append(exe)
    torch.save(already_processed,'already_processed.pt')
    print('Finished ' + exe)
