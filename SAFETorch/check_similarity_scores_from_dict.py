import torch
import sys
#load input file
scores_path = sys.argv[1]
print('Loading scores from: ' + scores_path)
try:
    n = int(sys.argv[2])
except:
    n = 10
scores = torch.load(scores_path)
print('Loaded scores')
print(scores.keys())
for elem in scores.keys():
    print(elem)
    i = 1
    #print('Top ' + str(n) + ' similar exploits: ')
    scoresino = dict(sorted(scores[elem].items(), key=lambda item: item[1][0]/item[1][1], reverse=True))
    for elemino in scoresino:
        if i>n:
            break
        print('('+ str(i) + ') '+ 'ID: ' + str(elemino) + ' Similarity: ' + str(scoresino[elemino]) + ' ' + str(scoresino[elemino][0]/scoresino[elemino][1]))
        i = i + 1