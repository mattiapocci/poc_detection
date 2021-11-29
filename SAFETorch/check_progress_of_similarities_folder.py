import os
import sys
import torch
from tqdm import tqdm
a = os.getcwd()
try:
    folder = sys.argv[1]
except:
    print("Please provide a folder path as an argument")
#pick all pts in folder
ls = list(filter(lambda elem: 'pt' in elem, os.listdir(folder)))
embeddings_dict = {}

for elem in ls:
    similarities = torch.load(os.path.join(folder, elem))
    print(elem, len(similarities.keys()))
    embeddings_dict.update(similarities)

print('Total length: ', len(embeddings_dict.keys()))