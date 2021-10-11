import torch
import sys
#load input file
scores_path = sys.argv[1]
try:
    n = sys.argv[2]
except:
    n = 10
scores = torch.load(scores_path)
scores = dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))
i = 1
print('Top ' + str(n) + ' similar exploits: ')
for elem in scores:
    if i>n:
        sys.exit(0)
    print('ID: ' + str(elem) + ' Similarity: ' + str(scores[elem]))