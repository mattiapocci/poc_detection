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