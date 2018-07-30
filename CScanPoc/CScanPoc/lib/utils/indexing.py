# encoding: utf-8
import os
import json
import logging
from CScanPoc.lib.api.utils import dump_poc_to_dict, dump_vuln_to_dict, load_poc_mod
from CScanPoc.lib.core.utils import load_file_as_module, iter_modules
from .progress import progress


class INDEX_CONFIG:
    '''POC 索引配置'''
    index_dir = '.index'

    if not os.path.exists(index_dir):
        os.makedirs(index_dir)

    @classmethod
    def __file(self, name, index_dir):
        dirpath = INDEX_CONFIG.index_dir if index_dir is None else index_dir
        return os.path.join(dirpath, name + '.index')

    @classmethod
    def get_poc_index_file(self, index_dir=None):
        return self.__file('poc', index_dir)

    @classmethod
    def get_vuln_index_file(self, index_dir=None):
        return self.__file('vuln', index_dir)


def _iter_json_lines(filepath):
    for line in open(filepath):
        if line is None or line.strip() == '':
            continue
        yield json.loads(line)


def load_index(index_dir=None):
    '''
    :return: Tuple<Dict<vuln_id, vuln_dict>, Dict<poc_id, poc_dict>, Dict<poc_id, vuln_id>>
    '''
    vuln_ind = {}
    poc_ind = {}

    for i in _iter_json_lines(INDEX_CONFIG.get_vuln_index_file(index_dir)):
        vuln_ind[i['vuln_id']] = i

    for i in _iter_json_lines(INDEX_CONFIG.get_poc_index_file(index_dir)):
        poc_ind[i['poc_id']] = i

    return (vuln_ind, poc_ind)


def indexing(poc_dir, index_dir=None):
    def write_obj(f, obj):
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write('\n')
    (vuln_ind_file, poc_ind_file) = (
        INDEX_CONFIG.get_vuln_index_file(index_dir),
        INDEX_CONFIG.get_poc_index_file(index_dir))

    vuln_ids = set({})
    poc_ids = set({})

    logging.info('开始查找 %s 下的 POC 信息', poc_dir)
    with open(poc_ind_file, 'w') as poc_ind, \
            open(vuln_ind_file, 'w') as vuln_ind:
        mod_count = 0
        successful_count = 0
        for (mod, poc_dir, poc_file) in iter_modules(poc_dir):
            poc_path = os.path.join(poc_dir, poc_file)
            mod_count += 1
            progress(mod_count, mod_count, '处理POC模块', poc_path)
            (vuln, pocs) = (None, None)
            try:
                (vuln, pocs) = load_poc_mod(mod)
            except Exception:
                logging.exception('模块加载出错')
            if vuln is not None and vuln.vuln_id not in vuln_ids:
                vuln_ids.add(vuln.vuln_id)
                write_obj(vuln_ind, dump_vuln_to_dict(vuln))
            for poc in pocs:
                if poc.poc_id not in poc_ids:
                    poc_ids.add(poc.poc_id)
                    poc_dict = dump_poc_to_dict(poc)
                    poc_dict['__file__'] = os.path.join(poc_dir, poc_file)
                    poc_dict['__class__'] = poc.__class__.__name__
                    write_obj(poc_ind, poc_dict)
            successful_count += 1
    logging.info('***********成功加载 %s 个模块【共计 %s 个】**********',
                 successful_count, mod_count)


def find_poc(poc_id, index_dir=None):
    '''根据 POC ID 查找 poc 实例'''
    poc_dict = None
    for i in _iter_json_lines(INDEX_CONFIG.get_poc_index_file(index_dir)):
        if i.get('poc_id') == poc_id:
            poc_dict = i
            break
    if poc_dict is None:
        raise Exception('Poc[id={}] not found'.format(poc_id))

    poc_file = poc_dict.get('__file__')
    mod = load_file_as_module(poc_file)
    return getattr(mod, poc_dict.get('__class__'))()


def iter_pocs_of_component(component_name, index_dir=None):
    for poc_dict in _iter_json_lines(INDEX_CONFIG.get_poc_index_file(index_dir)):
        try:
            poc_file = poc_dict.get('__file__')
            mod = load_file_as_module(poc_file)
            poc = getattr(mod, poc_dict.get('__class__'))()
            if poc.vuln.product == component_name:
                yield poc
        except:
            continue
