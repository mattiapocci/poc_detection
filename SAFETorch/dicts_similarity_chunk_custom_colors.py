import os
import sys
from tqdm import tqdm
import torch

def cosine_similarity(fun1,fun2):
    cos = torch.nn.CosineSimilarity(dim=1, eps=1e-6)
    c = cos(fun1, fun2)
    return c

def euclidean_distance(fun1,fun2):
    dist = torch.nn.PairwiseDistance(p=2)
    d = dist(fun1, fun2)
    return d

# colors contains already seen functions
def max_similarity(nome, embedding, exploit_dict, colors,distance_type):
# def max_similarity(nome, embedding, exploit_dict, distance_type):
    res = 0
    n2 = '' # name of function of the exploit which is max similar to input function
    for key in exploit_dict:
        if not (key in colors):
            if embedding.float().sum().item() == 0:
                # return 0,'','empty',colors
                return 0,'','empty'
            nome2 = key
            embedding2 = exploit_dict[key]
            if distance_type == 'COSINE':
                cos = cosine_similarity(embedding, embedding2)
            elif distance_type == 'EUCLIDEAN':
                cos = euclidean_distance(embedding, embedding2)
            if(cos > res):
                res = cos
                n2 = nome2
        else: continue
    colors.append(n2) #function has been chosen, cannot be chosen by another embedding
    return res,nome,n2,colors
    # return res,nome,n2

try:
    exploits_embeddings_path = sys.argv[1]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)

try:
    malware_embeddings_path = sys.argv[2]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)

try:
    output_file = sys.argv[3]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)
try:
    distance_type = sys.argv[4].upper()
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)

try:
    first_index = int(sys.argv[5])
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)

try:
    last_index = int(sys.argv[6])
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN> <first_index> <last_index>')
    exit(-1)
#cwd = os.getcwd()


exploits_embeddings = torch.load(exploits_embeddings_path)
malware_embeddings = torch.load(malware_embeddings_path)
try:
    means = torch.load(sys.argv[3])
except:
    means = {}

i = first_index
pbar = tqdm(total=last_index-first_index)
confronti_da_fare = ['2210','37052','40745','2204']
# confronti_da_fare = ['10563','42161','49964']
confronti_da_fare = list(set([item.split('_')[-1] for item in list(exploits_embeddings.keys())]))
keyss = list(malware_embeddings.keys())
hashlist = []

for elem in keyss:
    if elem.split('_')[0] in confronti_da_fare:
        hashlist.append(elem)


while i < last_index:
    exe_hash = hashlist[j]
    
#for exe_hash in tqdm(malware_embeddings.keys()):    
    tqdm.write('Beginning ' + exe_hash)
    if exe_hash in means.keys():
        tqdm.write(exe_hash + ' Already calculated')
        i += 1
        pbar.update(1)
        continue
    means[exe_hash] = {}
    key = ''

    for poc in tqdm(exploits_embeddings.keys()):
        tqdm.write(poc + ' Starting')
        count = 0
        acc = 0
        colors = []
        for embedding_key in tqdm(malware_embeddings[exe_hash]):
            cos = max_similarity(embedding_key, malware_embeddings[exe_hash][embedding_key], exploits_embeddings[poc], colors, distance_type)
            # cos = max_similarity(embedding_key, malware_embeddings[exe_hash][embedding_key], exploits_embeddings[poc], distance_type)
            if cos[2] == '':
                break
            elif cos[2] == 'empty':
                continue
            colors = cos[3]
            acc = acc + cos[0]
            count = count + 1
        if count == 0:
            means[exe_hash][poc] = 0
        else:
            means[exe_hash][poc] = acc/count
    tqdm.write('Saving intermediate results')
    torch.save(means, output_file)
    tqdm.write('Finished ' + exe_hash)
    i += 1
    pbar.update(1)
print('Saving results')
torch.save(means, output_file)