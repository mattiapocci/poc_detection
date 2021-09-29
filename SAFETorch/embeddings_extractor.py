import os
os.chdir('C:/Users/matti/Desktop/Magistrale/tesi/poc_detection/SAFETorch')
from SAFEtorch.utils.function_normalizer import FunctionNormalizer
from SAFEtorch.utils.instructions_converter import InstructionsConverter
from SAFEtorch.utils.capstone_disassembler import disassemble
from SAFEtorch.utils.radare_analyzer import BinaryAnalyzer
from SAFEtorch.safetorch.safe_network import SAFE
from SAFEtorch.safetorch.parameters import Config
import torch
import sys


#def disassemble(exe):
    # initialize SAFE
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
listone = []
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
            listone.append((hex(offset), function_embedding))
        except:
            continue
except:
    pass

print(listone)





