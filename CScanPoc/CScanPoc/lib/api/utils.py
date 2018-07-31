# encoding: utf-8
import re
import json
from datetime import datetime
from .vuln import ABVuln
from .poc import ABPoc
from .strategy import ABStrategy
from ..core.log import CSCAN_LOGGER as logger


def __process_date(date, to_string=False):
    if isinstance(date, str):
        try:
            date = datetime.strptime(date, '%Y-%m-%d')
        except:
            pass
    if not isinstance(date, datetime):
        return None
    return date.strftime('%Y-%m-%d') if to_string else date


def dump_vuln_to_dict(vuln):
    '''ABVuln -> Dict'''
    if isinstance(vuln, ABVuln):
        product_versions = vuln.product_version
        if product_versions is None:
            product_versions = []
        if not isinstance(product_versions, (list, tuple)):
            product_versions = str(product_versions)
        if isinstance(product_versions, str):
            product_versions = product_versions.replace('\n', ',').split(',')
        product_versions = ','.join([v.strip() for v in product_versions])

        return {
            'vuln_id': vuln.vuln_id,
            'cnvd_id': vuln.cnvd_id,
            'cve_id': ','.join(vuln.cve_id.split()),
            'name': vuln.name,
            'type': vuln.type.value,
            'level': vuln.level.value,
            'disclosure_date': __process_date(vuln.disclosure_date, True),
            'desc': vuln.desc,
            'ref': vuln.ref,
            'product': vuln.product,
            'product_version': product_versions
        }
    raise Exception('Not ABVuln')


def dump_poc_to_dict(poc):
    '''ABPoc -> Dict'''
    if isinstance(poc, ABPoc):
        return {
            'poc_id': poc.poc_id,
            'name': poc.poc_name,
            'author': poc.author,
            'create_date': poc.create_date,
            'option_schema': json.dumps(poc.option_schema),
            'vuln_id': poc.vuln.vuln_id
        }
    raise Exception('Not ABPoc')


def dump_strategy_to_dict(strategy):
    '''ABStrategy -> Dict'''
    if isinstance(strategy, ABStrategy):
        return {
            'strategy_id': strategy.strategy_id,
            'author': strategy.author,
            'name': strategy.name,
            'poc_ids': strategy.poc_ids,
            'create_date': __process_date(strategy.create_date, True),
            'desc': strategy.description
        }
    raise Exception('Not ABStrategy')


def load_strategy_mod(mod):
    '''给定加载的 module 返回其中的 strategy

    现在默认一个模块只包含一个 strategy
    '''
    for attr in dir(mod):
        logger.debug('处理 %s', attr)
        val = None
        try:
            val = getattr(mod, attr)()
        except:
            continue
        if isinstance(val, ABStrategy):
            return val
    raise Exception('模块中未找到策略')


def load_poc_mod(mod):
    '''给定加载的 module

    一个 module 中只能有一个 ABVuln，可能存在多个 ABPoc，
    ABPoc 中引用的漏洞必须对应这个 ABVuln

    返回其中的 ABVuln 和 ABPoc 实例

    :return: Tuple<ABVuln, Tuple<ABPoc>>
    '''
    vuln = None
    pocs = []
    for attr in dir(mod):
        val = None
        try:
            val = getattr(mod, attr)()
        except:
            continue
        if isinstance(val, ABVuln):
            if vuln is not None:
                raise Exception('模块中存在多于一个的漏洞')
            vuln = val
        elif isinstance(val, ABPoc):
            pocs.append(val)
    if vuln is not None and any([poc.vuln.vuln_id != vuln.vuln_id for poc in pocs]):
        raise Exception('模块中存在引用外部漏洞的 POC')
    return (vuln, tuple(pocs))
