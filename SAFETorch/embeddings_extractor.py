import os
import torch
import sys
#da cambiare i path per il docker container
# sys.path.append('/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch')
sys.path.append('/root/poc_detection/SAFETorch/SAFEtorch')
from utils.function_normalizer import FunctionNormalizer
from utils.instructions_converter import InstructionsConverter
from utils.capstone_disassembler import disassemble
from utils.radare_analyzer import BinaryAnalyzer
from safetorch.safe_network import SAFE
from safetorch.parameters import Config
os.chdir('/root/poc_detection/SAFETorch')
# os.chdir('/home/mattia/Desktop/tesi_magistrale/poc_detection/SAFETorch')
# I2V_FILENAME = "/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/model/word2id.json"
# SAFE_torch_model_path = "/home/mattia/Desktop/tesi_magistrale/SAFEtorch/SAFEtorch/model/SAFEtorch.pt"
I2V_FILENAME = "SAFEtorch/model/word2id.json"
SAFE_torch_model_path = "SAFEtorch/model/SAFEtorch.pt"

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
input_exe_embeddings = {}
try:
    #print('inizio')
    binary = BinaryAnalyzer(exe)
    offsets = binary.get_functions()
    for offset in offsets:
        try:
            asm = binary.get_hexasm(offset)
            instructions = disassemble(asm, binary.arch, binary.bits)
            converted_instructions = converter.convert_to_ids(instructions)
            instructions, length = normalizer.normalize_functions([converted_instructions])
            tensor = torch.LongTensor(instructions[0])
            function_embedding = safe(tensor, length)
            input_exe_embeddings[hex(offset)] = function_embedding
        except:
            continue
except:
    pass

torch.save(input_exe_embeddings,'/root/poc_detection/SAFETorch/SAFEtorch/input_exe_embeddings.pt')