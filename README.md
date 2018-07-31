# CScan

- [CScanPoc](./CScanPoc): POC 编写框架
- [pocs](./pocs): POC 代码
- [vulns](./vulns): 漏洞说明
- [utility](./utility): 系统功能（资产发现，资产识别等）

## POC 开发环境说明

POC 现在放在 `pocs` 目录下，和主体框架 `CScanPoc` 代码分离，开发时还是使用 `CScanPoc` 的虚拟环境。

1. 添加环境变量 `PIPENV_VENV_IN_PROJECT=1` （比如在 `~/.bashrc` 中加 `export PIPENV_VENV_IN_PROJECT=1`），这样虚拟环境将被安装到项目根目录 `.venv` 中。
2. 重启 `shell` 或者运行 `source ~/.bashrc`
3. 进入 `CScanPoc` 下运行 `pipenv install --dev`
4. 运行 `pipenv shell`，获得的 shell 可以进行 POC 的执行测试

如果用的是 PyCharm，在开发的时候需要选择解释器为虚拟环境中的解释器 `CScanPoc/CScanPoc/.venv/bin/python`。

## 静态检查工具说明

```sh
./tools/autopep8.sh pocs # 自动检查 pocs 目录下的 py 文件，修改到满足 pep8 的格式
                         # 也可以指定修复单个文件格式
./tools/autopep8.sh pocs/cms/CmsEasy/CmsEasy0001.py
```

```sh
./tools/pylint.sh pocs # 使用 pylint 对 pocs 下的 py 文件进行静态分析找到错误
                       # 也可以指定单个文件
./tools/pylint.sh pocs/cms/CmsEasy/CmsEasy0001.py
```

## 镜像编译

```sh
./build.sh ../pocs ../strategies
```

得到 `cscan:0.1`。

策略推荐：

```sh
docker run --rm cscan:0.1 strategy_exe.py \
       --recommend \
       -u http://www.baidu.com  \
       --component-property CmsEasy.deploy_path=/tmp
```

策略执行

```sh
docker run cscan:0.1 strategy_exe.py \
       -u http://www.baidu.com \
       --strategy-id simple-component-scan-strategy \
       --component CmsEasy \
       --component-property CmsEasy.deploy_path=/tmp \
       --json-output
```
