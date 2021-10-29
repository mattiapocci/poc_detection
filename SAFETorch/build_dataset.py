import os
import sys
import torch
from tqdm import tqdm
import subprocess
os.chdir('/root/poc_detection/SAFETorch')
folder = sys.argv[1]

#pick all exes in folder
ls = list(filter(lambda elem: 'exe' in elem, os.listdir(folder)))

exploits_embeddings = {}

for exe in tqdm(ls):
    tqdm.write('Beginning ' + exe)
    exploits_embeddings[exe.replace('.exe','')] = {}
    cmd = subprocess.Popen(['python', '/root/poc_detection/SAFETorch/embeddings_extractor.py', folder + exe], cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    cmd.communicate()
    # subprocess.run('python embeddings_extractor.py ' + folder + exe, cwd="/root/poc_detection/SAFETorch/SAFEtorch")
    exploits_embeddings[exe.replace('.exe','')] = torch.load('/root/poc_detection/SAFETorch/SAFEtorch/input_exe_embeddings.pt')
    os.remove('/root/poc_detection/SAFETorch/SAFEtorch/input_exe_embeddings.pt')
    tqdm.write('Finished ' + exe)

# remove invalid entries in exploits_embeddings
from copy import deepcopy
d = deepcopy(exploits_embeddings)
# Check if a tensor is zero: if my_tensor.float().sum().data[0] == 0:
for key in d:
    for minikey in d[key]:
        if d[key][minikey].float().sum().item() == 0:
            del exploits_embeddings[key][minikey]

torch.save(exploits_embeddings,'/root/poc_detection/datasets/exploits_embeddings_complete.pt')