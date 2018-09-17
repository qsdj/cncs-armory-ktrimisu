import os
import re

def listFolderContents(dir):
    dir_before = "/".join(dir.split("/")[:-1]) + "/"
    if not os.path.isdir(dir) and dir.endswith(".py"):
        with open(dir, 'r') as pocf:
            vuluid = re.findall(r'vuln_id = \'(\s*\S*)\'\s*#', "".join(pocf.readlines()))
            if vuluid:
                filename = dir_before+vuluid[0]+".html"
                tmp = open(filename, 'w')
                tmp.close()
                os.remove(dir)
        return
    elif os.path.isdir(dir):
        for child_dir in os.listdir(dir):
            listFolderContents(dir+"/"+child_dir)

listFolderContents("./htmls")