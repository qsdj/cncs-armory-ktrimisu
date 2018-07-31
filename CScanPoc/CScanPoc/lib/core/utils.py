# coding: utf-8

import imp
import uuid
from os import path, walk
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger


def load_file_as_module(dir_or_file, filename=None):
    '''加载 POC 文件为 Python module

    :param dir_or_file: @param{filename} 为空时，将该参数当作文件路径加载
    :param filename: 不为空时，加载 @param{dir_or_file} 目录下的该文件
    :return: imp.load_source 的结果
    '''
    if filename is None:
        (dirpath, name) = (path.dirname(dir_or_file),
                           path.basename(dir_or_file))
    else:
        (dirpath, name) = (dir_or_file, filename)
    mod_name = '{}-{}'.format(
        path.basename(name).rstrip('.py'),
        str(uuid.uuid4())
    ).replace('.', '_')
    poc_file = path.join(dirpath, name)
    try:
        logger.debug('Loading %s', poc_file)
        return imp.load_source(
            'CScanPoc.{}'.format(mod_name), poc_file)
    except Exception as err:
        logger.error('Error loading %s %s', poc_file, err)
        raise


def iter_modules(root_dirpath, ignore_dirs=['.venv']):
    '''递归加载目录下的所有除了 __init__.py 之外的 .py 文件

    对于加载失败的文件将直接忽略

    :param root_dirpath: 从该根目录开始查询加载
    :param ignore_dirs: 要忽略的目录名
    :returns: (加载的模块, 目录，文件名)
    '''
    for dirpath, dirnames, filenames, in walk(root_dirpath):
        for dirname in ignore_dirs:
            if dirname in dirnames:
                dirnames.remove(dirname)
        for filename in filenames:
            if not filename.endswith('.py') or filename == '__init__.py':
                continue
            try:
                mod = load_file_as_module(dirpath, filename)
                yield (mod, dirpath, filename)
            except Exception:
                pass
