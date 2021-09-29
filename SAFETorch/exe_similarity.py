import torch
import sys
import os
import embeddings_extractor

#UBUNTU
import sys 
sys.path.append('/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch')
from utils.function_normalizer import FunctionNormalizer
from utils.instructions_converter import InstructionsConverter
from utils.capstone_disassembler import disassemble
from utils.radare_analyzer import BinaryAnalyzer
from safetorch.safe_network import SAFE
from safetorch.parameters import Config
os.chdir('/home/mattia/Desktop/tesi_magistrale/poc_detection/SAFETorch')
exploits_embeddings = torch.load('../datasets/exploits_embeddings_complete.pt')
print('exploits_embeddings loaded')
I2V_FILENAME = "/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/model/word2id.json"
SAFE_torch_model_path = "/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/model/SAFEtorch.pt"



#WINDOWS
#from SAFEtorch.utils.function_normalizer import FunctionNormalizer
#from SAFEtorch.utils.instructions_converter import InstructionsConverter
#from SAFEtorch.utils.capstone_disassembler import disassemble
#from SAFEtorch.utils.radare_analyzer import BinaryAnalyzer
#from SAFEtorch.safetorch.safe_network import SAFE
#from SAFEtorch.safetorch.parameters import Config
#os.chdir('C:\\Users\\matti\\Desktop\\Magistrale\\tesi\\poc_detection\\SAFETorch')
#exploits_embeddings = torch.load('C:\\Users\\matti\\Desktop\\Magistrale\\tesi\\poc_detection\\datasets\\exploits_embeddings_complete.pt')
#print('exploits_embeddings loaded')
#I2V_FILENAME = "SAFEtorch/model/word2id.json"
#SAFE_torch_model_path = "SAFEtorch/model/SAFEtorch.pt"



import torch
import sys
import os
import embeddings_extractor


def cosine_similarity(fun1,fun2):
    cos = torch.nn.CosineSimilarity(dim=1, eps=1e-6)
    return cos(fun1, fun2)

def max_similarity(nome, embedding, lista2):
    res = 0
    n1 = ''
    n2 = ''
    for elem in lista2:
        nome2 = elem[0]
        embedding2 = elem[1]
        print(lista2)
        print(type(elem))
        cos = cosine_similarity(embedding,embedding2)
        if(cos > res):
            res = cos
            n1 = nome
            n2 = nome2
    return res,n1,n2


'''
for entry in exploits_embeddings:
    print(entry)
'''
exe = sys.argv[1]

config = Config()
safe = SAFE(config)

# load instruction converter and normalizer
converter = InstructionsConverter(I2V_FILENAME)
normalizer = FunctionNormalizer(max_instruction=150)

# load SAFE weights
state_dict = torch.load(SAFE_torch_model_path)
safe.load_state_dict(state_dict)
safe = safe.eval()
#listone = embeddings_extractor(exe)
'''
import subprocess
getListone =  subprocess.Popen(['python','embeddings_extractor.py',str(exe)], shell=True, stdout=subprocess.PIPE).stdout
listone =  getListone.read()

result = os.popen('python embeddings_extractor.py ' + exe)
listone = result
'''
os.system('python embeddings_extractor.py ' + exe)
#listone = os.popen('python embeddings_extractor.py ' + exe).read()
#listone = str(os.system('python embeddings_extractor.py ' + str(exe)))
dizionarione = torch.load('/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/dizionarione.pt')

for elem in dizionarione:
    for entry in exploits_embeddings:
        cos = max_similarity(elem,dizionarione[elem],exploits_embeddings[entry])
        print('La max similarity tra ' + str(elem[0]) + ' e l\'exploit ' + str(entry) + ': ' + str(cos[0]) + ' . Relativo alle funzioni ' + str(cos[1]) + ' e ' + str(cos[2]))




