from itertools import chain
import torch
import os
#da levare se docker container
os.chdir('SAFETorch')

dataset = torch.load('../datasets/exploits_embeddings_complete.pt')
torch.save(dataset,'../datasets/exploits_embeddings_complete_with_duplicates.pt')
rev_dict = {}
for key, value in dataset.items():
	rev_dict.setdefault(str(value), set()).add(key)


result = filter(lambda x: len(x)>1, rev_dict.values())
res = list(result)
for s in res:
    primo = True
    for minis in s:
        if not primo:
            del dataset[minis]
        else:
            primo = False

torch.save(dataset,'../datasets/exploits_embeddings_complete.pt')
