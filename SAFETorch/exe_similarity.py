from SAFEtorch.utils.function_normalizer import FunctionNormalizer
from SAFEtorch.utils.instructions_converter import InstructionsConverter
from SAFEtorch.utils.capstone_disassembler import disassemble
from SAFEtorch.utils.radare_analyzer import BinaryAnalyzer
from SAFEtorch.safetorch.safe_network import SAFE
from SAFEtorch.safetorch.parameters import Config
import torch
import sys
import os
import embeddings_extractor
os.chdir('C:\\Users\\matti\\Desktop\\Magistrale\\tesi\\poc_detection\\SAFETorch')
def cosine_similarity(fun1,fun2):
    cos = torch.nn.CosineSimilarity(dim=1, eps=1e-6)
    return cos(fun1, fun2)

def max_similarity(nome, embedding, lista2):
    res = 0
    n1,n2 = ''
    for(nome2,embedding2) in lista2:
        cos = cosine_similarity(embedding,embedding2)
        if(cos > res):
            res = cos
            n1 = nome
            n2 = nome2
    return res,n1,n2


exploits_embeddings = torch.load('C:\\Users\\matti\\Desktop\\Magistrale\\tesi\\poc_detection\\datasets\\exploits_embeddings_complete.pt')
print('exploits_embeddings loaded')
for entry in exploits_embeddings:
    print(entry)
exe = sys.argv[1]

config = Config()
safe = SAFE(config)

# load instruction converter and normalizer
I2V_FILENAME = "SAFEtorch/model/word2id.json"
converter = InstructionsConverter(I2V_FILENAME)
normalizer = FunctionNormalizer(max_instruction=150)

# load SAFE weights
SAFE_torch_model_path = "SAFEtorch/model/SAFEtorch.pt"
state_dict = torch.load(SAFE_torch_model_path)
safe.load_state_dict(state_dict)
safe = safe.eval()
#listone = embeddings_extractor(exe)

import subprocess
getListone =  subprocess.Popen(['python','embeddings_extractor.py',str(exe)], shell=True, stdout=subprocess.PIPE).stdout
listone =  getListone.read()

result = os.popen('python embeddings_extractor.py ' + exe)
listone = result

#listone = str(os.system('python embeddings_extractor.py ' + str(exe)))


for elem in listone:
    for entry in exploits_embeddings:
        cos = max_similarity(elem[0],elem[1],exploits_embeddings[entry])
        print('La max similarity tra ' + str(elem[0]) + ' e l\'exploit ' + str(entry) + ': ' + str(cos[0]) + ' . Relativo alle funzioni ' + str(cos[1]) + ' e ' + str(cos[2]))




