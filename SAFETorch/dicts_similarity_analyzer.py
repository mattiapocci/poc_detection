import torch
import sys
from tqdm import tqdm
try:
    means_path = sys.argv[1]
except:
    print("Usage: python dicts_similarity_analyzer.py <path_to_means_file> <optional_threshold>")
    exit(-1)

try:
    threshold = float(sys.argv[2])
except:
    threshold = 0.8

means = torch.load(means_path)

for exe in tqdm(means):
    
    values = means[exe]
    for key in values:
        if values[key] > threshold:
            print(exe + ' has similarity ' + str(values[key]) + ' with poc ' + str(key) + '.')
    

