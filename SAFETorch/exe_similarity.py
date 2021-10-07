import torch
import sys
import os
import embeddings_extractor
from tqdm import tqdm
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
#exploits_embeddings = torch.load('/media/mattia/2068D30968D2DC9A1/Users/matti/Desktop/Magistrale/tesi/poc_detection/temp_dir/exploits_embeddings_complete.pt')

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

def max_similarity(nome, embedding, exploit_dict):
    res = 0
    n1 = ''
    n2 = ''
    for key in exploit_dict:
        nome2 = key
        embedding2 = exploit_dict[key]
        #print(lista2)
        cos = cosine_similarity(embedding,embedding2).item()
        if(cos > res):
            res = cos
            n1 = nome
            n2 = nome2
    return res,n1,n2

exe = sys.argv[1]
output_name = exe.split('/')[-1].replace('.exe','.pt')

config = Config()
safe = SAFE(config)

# load instruction converter and normalizer
converter = InstructionsConverter(I2V_FILENAME)
normalizer = FunctionNormalizer(max_instruction=150)

# load SAFE weights
state_dict = torch.load(SAFE_torch_model_path)
safe.load_state_dict(state_dict)
safe = safe.eval()

os.system('python embeddings_extractor.py ' + exe)

input_exe_embeddings = torch.load('/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/input_exe_embeddings.pt')
os.remove('/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/input_exe_embeddings.pt')
if not input_exe_embeddings:
    print('invalid input exe')
    sys.exit(-1)

# remove invalid entries in input exe embeddings set
from copy import deepcopy
d = deepcopy(input_exe_embeddings)
# Check if a tensor is zero: if my_tensor.float().sum().data[0] == 0:
for key in d:
        if d[key].float().sum().item() == 0:
            del input_exe_embeddings[key]

means = {}
key = ''
max = 0
for entry in tqdm(exploits_embeddings):
    count = 0
    acc = 0
    for elem in input_exe_embeddings:
        cos = max_similarity(elem,input_exe_embeddings[elem],exploits_embeddings[entry])
        #print('La max similarity tra ' + str(elem) + ' e l\'exploit ' + str(entry) + ': ' + str(cos[0]) + ' . Relativo alle funzioni ' + str(cos[1]) + ' e ' + str(cos[2]))
        acc = acc + cos[0]
        count = count + 1
    tqdm.write('Mean similarity between input exe and ' + str(entry) + ' is ' + str(acc/count))
    means[entry] = acc/count
    if means[entry] > max:
        max = means[entry]
        key = entry
print('L\'exploit con maggiore somiglianza è ' + key + ' con valore ' + str(max))

torch.save(means, '/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/' + output_name)