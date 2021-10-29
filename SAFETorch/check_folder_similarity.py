import os
import sys
from tqdm import tqdm
import torch
import subprocess

try:
    folder = sys.argv[1]
except:
    print('Usage: python check_folder_similarity.py <folder_path>')
    exit(-1)

try:
    i = int(sys.argv[2])
except:
    i = 5

ls = list(filter(lambda elem: 'exe' in elem, os.listdir(folder)))

try:
    already_processed = torch.load('already_processed.pt')
except:
    already_processed = []

for exe in tqdm(ls):
    if i == 0:
        sys.exit(1)
    if exe in already_processed:
        print('Skipping ' + exe + ': already processed')
        continue
    print('Beginning ' + exe)
    cmd = subprocess.Popen(['python', '/root/poc_detection/SAFETorch/exe_similarity.py', folder + exe, 'Malwarebazaar/'], cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    cmd.communicate()
    # subprocess.run('python exe_similarity.py ' + folder + exe + ' Malwarebazaar/', cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    cmd = subprocess.Popen(['python', '/root/poc_detection/SAFETorch/check_similarity_scores.py', 'Malwarebazaar/' + exe.replace('.exe','.pt')], cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    cmd.communicate()
    # subprocess.run('python check_similarity_scores.py ' + 'Malwarebazaar/' + exe.replace('.exe','.pt'), cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    already_processed.append(exe)
    torch.save(already_processed,'already_processed.pt')
    print('Finished ' + exe)
    i = i - 1