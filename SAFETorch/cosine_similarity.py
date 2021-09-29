# This script is meant to take 2 exe in input and check all the functions with cosine similarity > threshold
threshold = 0.9

from SAFEtorch.utils.function_normalizer import FunctionNormalizer
from SAFEtorch.utils.instructions_converter import InstructionsConverter
from SAFEtorch.utils.capstone_disassembler import disassemble
from SAFEtorch.utils.radare_analyzer import BinaryAnalyzer
from SAFEtorch.safetorch.safe_network import SAFE
from SAFEtorch.safetorch.parameters import Config
import torch

import sys
import os
os.chdir('SAFETorch')
first_binary_path = sys.argv[1]
second_binary_path = sys.argv[2]

# initialize SAFE
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

# analyze the first binary
binary = BinaryAnalyzer(first_binary_path)
offsets = binary.get_functions()

first_list_of_embeddings = []
# generate each function embedding
for offset in offsets:
    asm = binary.get_hexasm(offset)
    instructions = disassemble(asm, binary.arch, binary.bits)
    converted_instructions = converter.convert_to_ids(instructions)
    instructions, length = normalizer.normalize_functions(
        [converted_instructions])
    tensor = torch.LongTensor(instructions[0])
    function_embedding = safe(tensor, length)
    first_list_of_embeddings.append(hex(offset), function_embedding)

# analyze the second binary
binary = BinaryAnalyzer(second_binary_path)
offsets = binary.get_functions()
second_list_of_embeddings = []
# generate each function embedding
for offset in offsets:
    asm = binary.get_hexasm(offset)
    instructions = disassemble(asm, binary.arch, binary.bits)
    converted_instructions = converter.convert_to_ids(instructions)
    instructions, length = normalizer.normalize_functions(
        [converted_instructions])
    tensor = torch.LongTensor(instructions[0])
    function_embedding = safe(tensor, length)
    second_list_of_embeddings.append(hex(offset), function_embedding)
