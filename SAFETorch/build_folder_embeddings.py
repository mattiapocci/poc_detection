import os
import sys
import torch
from tqdm import tqdm
import subprocess
os.chdir('/root/poc_detection/SAFETorch')
folder = sys.argv[1]
output_file = sys.argv[3]
#pick all exes in folder
ls = list(filter(lambda elem: 'exe' in elem, os.listdir(folder)))

embeddings_dict = {}
i = int(sys.argv[2])
for exe in tqdm(ls):
    if i == 0:
        break
    tqdm.write('Beginning ' + exe)
    try:
        embeddings_dict[exe.replace('.exe','')] = torch.load('/root/poc_detection/SAFETorch/SAFEtorch/' + exe.replace('.exe','.pt'))
        tqdm.write('Already processed ' + exe)
    except:
        embeddings_dict[exe.replace('.exe','')] = {}
        cmd = subprocess.Popen(['python', '/root/poc_detection/SAFETorch/embeddings_extractor.py', folder + exe], cwd="/root/poc_detection/SAFETorch/SAFEtorch")
        cmd.communicate()
        # subprocess.run('python embeddings_extractor.py ' + folder + exe, cwd="/root/poc_detection/SAFETorch/SAFEtorch")
        embeddings_dict[exe.replace('.exe','')] = torch.load('/root/poc_detection/SAFETorch/SAFEtorch/' + exe.replace('.exe','.pt'))
        # os.remove('/root/poc_detection/SAFETorch/SAFEtorch/' + exe.replace('.exe','.pt'))
        tqdm.write('Finished ' + exe + '. Updating dict at ' + output_file)
        torch.save(embeddings_dict,output_file)
        i = i - 1

# remove invalid entries in embeddings_dict
from copy import deepcopy
d = deepcopy(embeddings_dict)
# Check if a tensor is zero: if my_tensor.float().sum().data[0] == 0:
for exe in tqdm[d]:
    for key in tqdm[d[exe]]:
        tqdm.write('Checking ' + key + ' for duplicates')
        for minikey in d[exe][key]:
            if d[exe][key][minikey].float().sum().item() == 0:
                del embeddings_dict[exe][key][minikey]

torch.save(embeddings_dict,output_file)