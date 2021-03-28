#!git clone https://github.com/CVEProject/cvelist
import subprocess 
import json
folders = ['1999', '2000', '2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021']
cvelist = []
for folder in folders:
    ls = "ls " + folder
    ls = subprocess.getstatusoutput(ls)
    print(ls)
    str_list = ls[1].split('\n')
    #str_list[:] = [x for x in str_list if x]
    print(str_list)
    for f in str_list:
        ls = "ls " + folder + '/' + f
        ls = subprocess.getstatusoutput(ls)
        print(ls[1])
        jsonlist = ls[1].split('\n')
        jsonlist[:] = [x for x in jsonlist if x]
        print(jsonlist)
        for j in jsonlist:
            current_file = open(folder + '/' + f + '/' + j)
            current = json.load(current_file)
            cvelist.append(current)
            print('Inserted element ' + j)
print(len(cvelist))
print(cvelist[0])
    #cvelist.append(json.load(folder))

with open('cvelist.json', 'w') as fout:
    json.dump(cvelist, fout)
