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
    res = 0
    n2 = '' # name of function of the exploit which is max similar to input function
    for key in exploit_dict:
        if not (key in colors):
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

try:
    exploits_embeddings_path = sys.argv[1]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN>')
    exit(-1)

try:
    malware_embeddings_path = sys.argv[2]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN>')
    exit(-1)

try:
    output_file = sys.argv[3]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN>')
    exit(-1)
try:
    distance_type = sys.argv[4].upper()
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <COSINE/EUCLIDEAN>')
    exit(-1)

exploits_embeddings = torch.load(exploits_embeddings_path)
malware_embeddings = torch.load(malware_embeddings_path)

means = {}
for exe_hash in tqdm(malware_embeddings.keys()):    
    tqdm.write('Beginning ' + exe_hash)
    means[exe_hash] = {}
    key = ''

    for poc in tqdm(exploits_embeddings.keys()):
        count = 0
        acc = 0
        colors = []
        for embedding_key in tqdm(malware_embeddings[exe_hash]):
            cos = max_similarity(embedding_key, malware_embeddings[exe_hash][embedding_key], exploits_embeddings[poc], colors, distance_type)
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

print('Saving results')
torch.save(means, output_file)