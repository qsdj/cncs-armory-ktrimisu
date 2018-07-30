# coding: utf-8

import os
import imp
import json
import uuid
import logging
from CScanPoc import ABPoc, ABVuln


def vuln_to_dict(vuln):
    if not isinstance(vuln, ABVuln):
        raise Exception('Not ABVuln')
    return {
        'vuln_id': vuln.vuln_id,
        'cnvd_id': vuln.cnvd_id,
        'cve_id': ','.join(vuln.cve_id.split()),
        'name': vuln.name,
        'type': vuln.type.value,
        'level': vuln.level.value,
        'disclosure_date': None if isinstance(vuln.disclosure_date, str) else vuln.disclosure_date,
        'desc': vuln.desc,
        'ref': vuln.ref,
        'product': vuln.product,
        'product_version': vuln.product_version
    }


def poc_to_dict(poc):
    if not isinstance(poc, ABPoc):
        raise Exception('Not ABPoc')
    return {
        'poc_id': poc.poc_id,
        'name': poc.poc_name,
        'author': poc.author,
        'create_date': poc.create_date,
        'option_schema': json.dumps(poc.option_schema)
    }


def find_vuln_poc(mod):
    '''给定加载的 module (load_poc_file_as_module 结果)

    返回其中的 ABVuln 和 ABPoc 实例

    :return: (vuln, poc)
    '''
    vuln = None
    poc = None
    for attr in dir(mod):
        try:
            val = getattr(mod, attr)()
            if isinstance(val, ABPoc):
                if val.poc_id is not None and val.poc_id.strip() != '':
                    poc = val
                else:
                    logging.warn('POC ID 为空: {} - {}'.format(val, mod))
            elif isinstance(val, ABVuln):
                if val.vuln_id is not None and val.vuln_id.strip() != '':
                    vuln = val
                else:
                    logging.warn('Vuln ID 为空: {} - {}'.format(val, mod))
        except:
            continue
    return (vuln, poc)


def load_poc_file_as_module(dir_or_file, filename=None):
    '''加载 POC 文件为 Python module

    :return: imp.load_source 的结果
    '''
    if filename is None:
        (dir, name) = (os.path.dirname(dir_or_file), os.path.basename(dir_or_file))
    else:
        (dir, name) = (dir_or_file, filename)
    mod_name = '{}-{}'.format(
        os.path.basename(name).rstrip('.py'),
        str(uuid.uuid4())
    ).replace('.', '_')
    poc_file = os.path.join(dir, name)
    try:
        logging.debug('Loading {}'.format(poc_file))
        return imp.load_source(
            'CScanPoc.{}'.format(mod_name), poc_file)
    except Exception as e:
        logging.error('Error loading {} {}'.format(poc_file, e))
        raise e


def load_modules(dir):
    for root, _, files, in os.walk(dir):
        for poc_file in files:
            if not poc_file.endswith('.py'):
                continue
            try:
                mod = load_poc_file_as_module(root, poc_file)
                yield (mod, root, poc_file)
            except:
                pass
