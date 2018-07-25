# encoding: utf-8
import os
import json
import logging
from progress import progress
from CScanPoc.lib.utils.misc import vuln_to_dict, poc_to_dict, load_modules, find_vuln_poc


class INDEX_CONFIG:
    index_dir = 'index'

    if not os.path.exists(index_dir):
        os.makedirs(index_dir)

    @classmethod
    def __file(self, name, index_dir):
        d = INDEX_CONFIG.index_dir if index_dir is None else index_dir
        return os.path.join(d, name + '.index')

    @classmethod
    def get_poc_index_file(self, index_dir=None):
        return self.__file('poc', index_dir)

    @classmethod
    def get_vuln_index_file(self, index_dir=None):
        return self.__file('vuln', index_dir)

    @classmethod
    def get_poc_vuln_map_index_file(self, index_dir):
        return self.__file('poc_vuln_map', index_dir)


def load_index(index_dir=None):
    '''
    :return: Tuple<Dict<vuln_id, vuln_dict>, Dict<poc_id, poc_dict>, Dict<poc_id, vuln_id>>
    '''
    def iter_ind(f):
        for line in file(f):
            if line is None or line.strip() == '':
                continue
            yield json.loads(line)

    vuln_ind = {}
    poc_ind = {}
    poc_vuln_ind = {}

    for i in iter_ind(INDEX_CONFIG.get_vuln_index_file(index_dir)):
        vuln_ind[i['vuln_id']] = i

    for i in iter_ind(INDEX_CONFIG.get_poc_index_file(index_dir)):
        poc_ind[i['poc_id']] = i

    for i in iter_ind(INDEX_CONFIG.get_poc_vuln_map_index_file(index_dir)):
        poc_vuln_ind[i[0]] = i[1]

    return (vuln_ind, poc_ind, poc_vuln_ind)


def indexing(poc_dir, index_dir=None):
    def write_obj(f, obj):
        f.write(json.dumps(obj))
        f.write('\n')
    (vuln_ind_file, poc_ind_file, poc_vuln_map_ind_file) = (
        INDEX_CONFIG.get_vuln_index_file(index_dir),
        INDEX_CONFIG.get_poc_index_file(index_dir),
        INDEX_CONFIG.get_poc_vuln_map_index_file(index_dir))

    vuln_ids = set({})
    poc_ids = set({})
    poc_vuln_rel = set({})

    with open(poc_ind_file, 'w') as poc_ind, open(vuln_ind_file, 'w') as vuln_ind, open(poc_vuln_map_ind_file, 'w') as poc_vuln_map_ind:
        mod_count = 0
        for (mod, poc_dir, poc_file) in load_modules(poc_dir):
            poc_path = os.path.join(poc_dir, poc_file)
            progress(mod_count, mod_count, '处理模块', poc_path)
            mod_count += 1
            (vuln, poc) = find_vuln_poc(mod)
            to_write_vulns = []
            to_write_poc = None
            if vuln and vuln.vuln_id not in vuln_ids:
                to_write_vulns.append(vuln)
            if poc and poc.poc_id not in poc_ids:
                to_write_poc = poc

                poc_vuln = poc.vuln
                if poc_vuln is not None and vuln is not None:
                    to_write_vulns.append(poc_vuln)

                    if poc_vuln.vuln_id is None or poc_vuln.vuln_id.strip() == '':
                        logging.warn('Vuln Id 为空 {}'.format(poc_vuln))
                    else:
                        rel = (poc.poc_id, poc_vuln.vuln_id)
                        if rel not in poc_vuln_rel:
                            write_obj(poc_vuln_map_ind, rel)
                            poc_vuln_rel.add(rel)

            for v in to_write_vulns:
                if v.vuln_id not in vuln_ids:
                    write_obj(vuln_ind, vuln_to_dict(vuln))
                    vuln_ids.add(vuln.vuln_id)
            if to_write_poc is not None:
                if to_write_poc.poc_id not in poc_ids:
                    d_poc = poc_to_dict(to_write_poc)
                    d_poc['path'] = poc_path
                    write_obj(poc_ind, d_poc)
                    poc_ids.add(to_write_poc.poc_id)
