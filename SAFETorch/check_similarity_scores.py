import torch
import sys
#load input file
scores_path = sys.argv[1]
scores = torch.load(scores_path)
print(dict(sorted(scores.items(), key=lambda item: item[1], reverse=True)))