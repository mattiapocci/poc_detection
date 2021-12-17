import os
import sys
from tqdm import tqdm
import torch

def cosine_similarity(fun1,fun2):
    cos = torch.nn.CosineSimilarity(dim=1, eps=1e-6)
    c = cos(fun1, fun2)
    return c

# colors contains already seen functions
# def max_similarity(nome, embedding, exploit_dict, colors):
def max_similarity(nome, embedding, exploit_dict):
    res = 0
    n2 = '' # name of function of the exploit which is max similar to input function
    for key in exploit_dict:
        # if not (key in colors):
            if embedding.float().sum().item() == 0:
                # return 0,'','empty',colors
                return 0,'','empty'
            nome2 = key
            embedding2 = exploit_dict[key]
            cos = cosine_similarity(embedding, embedding2)
            if(cos > res):
                res = cos
                n2 = nome2
        # else: continue
    # colors.append(n2) #function has been chosen, cannot be chosen by another embedding
    # return res,nome,n2,colors
    return res,nome,n2

try:
    exploits_embeddings_path = sys.argv[1]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

try:
    malware_embeddings_path = sys.argv[2]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

try:
    output_file = sys.argv[3]
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

try:
    threshold = float(sys.argv[4])
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

try:
    first_index = int(sys.argv[5])
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

try:
    last_index = int(sys.argv[6])
except:
    print('Usage: python check_dicts_similarity.py <exploits_embeddings_path> <malware_embeddings_path> <output_file> <threshold> <first_index> <last_index>')
    exit(-1)

#cwd = os.getcwd()


exploits_embeddings = torch.load(exploits_embeddings_path)
num_poc_functions = {}
malware_embeddings = torch.load(malware_embeddings_path)
try:
    result = torch.load(sys.argv[3])
except:
    result = {}

interesting_functions = {}


# qui metti solo le poc di interesse da calcolare
def is_relevant_poc(name):
    pocs_to_check = ['759','802','967','978','988','6389','9222','9800','7536','4157','3464','4017','6831','19034','3617','4745','4001','8783','8767']
    # pocs_to_check = ['2278','2800','4263','8390','8444','20784','40069','44462','3648','4998','43773','149','388','403','1223','2650','2824','2861','2873','3648','3684','3777','7929','8180','10164','11174','12497','13509','13887','14092','15063','15420','16022','17273','41072']
    for n in pocs_to_check:
        if n in name:
            return True
    return False



hashlist = list(malware_embeddings.keys())
i = first_index
pbar = tqdm(total=last_index-first_index)
while i < last_index:
    exe_hash = hashlist[i]
#for exe_hash in tqdm(malware_embeddings.keys()):    
    tqdm.write('Beginning ' + exe_hash)
    if exe_hash in result.keys():
        tqdm.write('Already calculated')
        i += 1
        pbar.update(1)
        continue

    interesting_functions[exe_hash] = {}
    result[exe_hash] = {}
    key = ''

    for poc in tqdm(exploits_embeddings.keys()):
        if not (is_relevant_poc(poc)):
            tqdm.write('Skipping ' + poc)
            continue
        interesting_functions[exe_hash][poc] = {}
        if not (poc in num_poc_functions.keys()):
            num_poc_functions[poc] = len(exploits_embeddings[poc])
        count = 0
        for embedding_key in tqdm(malware_embeddings[exe_hash]):
            cos = max_similarity(embedding_key, malware_embeddings[exe_hash][embedding_key], exploits_embeddings[poc])
            if cos[0] > threshold:
                count += 1
                if not (cos[2] in interesting_functions[exe_hash][poc].keys()):
                    interesting_functions[exe_hash][poc][cos[2]] = [cos[0]]
                else :
                    interesting_functions[exe_hash][poc][cos[2]].append(cos[0])
            else:
                continue
        # se una funzione è stata trovata più volte, prendo la media delle similarities
        for key in interesting_functions[exe_hash][poc].keys():
            res = 0
            for value in interesting_functions[exe_hash][poc][key]:
                res += value
            res = res/len(interesting_functions[exe_hash][poc][key])
            interesting_functions[exe_hash][poc][key] = [res]
        # il risultato finale contiene (funzioni interessanti, numero funzioni poc)
        result[exe_hash][poc] = (len(list(interesting_functions[exe_hash][poc].keys())), num_poc_functions[poc])
                


    tqdm.write('Saving intermediate results')
    torch.save(result, output_file)
    tqdm.write('Finished ' + exe_hash)
    i += 1
    pbar.update(1)
print('Saving results')
torch.save(result, output_file)