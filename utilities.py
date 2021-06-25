'''
func ls
params:
    folder -> working directory
return:
    file_list -> (list) -> a list of strings, representing the file names of the folder
'''
def ls(folder):
    import os
    import subprocess
    os.chdir(folder)
    cc = subprocess.getstatusoutput('dir')
    j=0
    file_list = []
    for i in cc[1].split('\n'):
        if j>6:
            file_list.append(i.split(' ')[-1])
        j=j+1
    file_list = file_list[:len(file_list)-2]
    return file_list

'''
func compile_generic
params:
    df ->               pandas dataframe
    suffix ->           extension of script to be compiled
    source_dir ->       working directory
    compile_command ->  compile command for windows
                        <temp_file_name> will be substituted with
                        temp_file_name value
                        <name> will be substituted with
                        str(df.iloc[i]['exploit_db_id']) value
'''
def compile_generic(df, suffix, source_dir, compile_command):
    import subprocess
    import os
    import pandas as pd
    indexes = df.loc[df.isin([suffix]).any(axis=1)].index.tolist()
    os.chdir(source_dir)
    for n in indexes:
        i = n
        print('N: ' + str(n))
        print('dir: ' + source_dir)
        print('suffix: ' + suffix)
        print('compile_command: ' + compile_command)
        try:
            dotted_suffix = '.' + suffix
            temp_file_name = str(df.iloc[i]['exploit_db_id']) + dotted_suffix
            temp_file = open(temp_file_name, 'w')
            n = temp_file.write(df.iloc[i]['exploit'])
            # print(df.iloc[n]['exploit'])
            temp_file.close()
            cli_command = compile_command.replace('<temp_file_name>', temp_file_name)
            cli_command = cli_command.replace('<name>', str(df.iloc[i]['exploit_db_id']))
            print(cli_command)
            cc = subprocess.getstatusoutput(cli_command)
            print(cc)
            remove = 'del ' + temp_file_name
            remove = subprocess.getstatusoutput(remove)
            print(remove)
        except:
            print('Invalid file')

'''
func compile_generic_c_folder
params:
    source_dir ->       working directory
    compile_command ->  compile command for c files in windows
                        <temp_file_name> will be substituted with
                        temp_file_name value
'''
def compile_generic_c_folder(source_dir, compile_command):
    import subprocess
    import os
    os.chdir(source_dir)
    cc = subprocess.getstatusoutput('dir')
    j=0
    file_list = ls(source_dir)
    for file_name in file_list:
        if '.c' in file_name:
            try:
                cli_command = compile_command.replace('<temp_file_name>', file_name)
                cli_command = cli_command.replace('<name>', file_name.replace('.c',''))
                print(cli_command)
                cc = subprocess.getstatusoutput(cli_command)
                print(cc)
            except:
                print('Invalid file')
        else:
            print('Not a c file')