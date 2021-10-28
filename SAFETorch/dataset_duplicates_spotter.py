from itertools import chain
import torch

dataset = torch.load('../datasets/exploits_embeddings_complete.pt')

rev_dict = {}
for key, value in dataset.items():
	rev_dict.setdefault(str(value), set()).add(key)


result = filter(lambda x: len(x)>1, rev_dict.values())
res = list(result)
for s in res:
    print(s)
    print(len(s))
    print('---')