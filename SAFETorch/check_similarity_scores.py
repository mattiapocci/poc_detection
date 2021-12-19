import torch
import sys
#load input file
scores_path = sys.argv[1]
try:
    n = int(sys.argv[2])
except:
    n = 10
input = torch.load(scores_path)



for score in input:
    scores = input[score]
    scores = dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))
    i = 1
    print('Top ' + str(n) + ' similar exploits to ' + score + ': ')
    for elem in scores:
        if i>n:
            break
        print('('+ str(i) + ') '+ 'ID: ' + str(elem) + ' Similarity: ' + str(scores[elem]))
        i = i + 1