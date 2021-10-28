import os
import sys
from tqdm import tqdm
import torch

try:
    folder = sys.argv[1]
except:
    print('Usage: python check_folder_scores.py <folder_path> <threshold>')
    exit(-1)

try:
    threshold = int(sys.argv[2])
except:
    threshold = 0.8

ls = list(filter(lambda elem: '.pt' in elem, os.listdir(folder)))


for pt in tqdm(ls):
    
    values = torch.load(folder + pt)
    # os.system('python exe_similarity.py ' + folder + exe + ' Malwarebazaar/')
    # os.system('python check_similarity_scores.py ' + 'Malwarebazaar/' + exe.replace('.exe','.pt'))
    for key in values:
        # print('key: ' + str(key))
        # print('values[key]: ' + str(values[key]))
        # print('threshold: ' + str(threshold))
        if values[key] > threshold:
            print(pt + ' has similarity ' + str(values[key]) + ' with poc ' + str(key) + '.')
    # already_processed.append(exe)
    # torch.save(already_processed,'already_processed.pt')
    # print('Finished ' + exe)
    # i = i - 1