# encoding: utf-8
import os
import shutil
import logging
import tempfile


def build_poc_image(poc, poc_file='', build_base='cscan-poc-base:0.1', cnx=None, force_rebuild=False, registry=None):
    def create_image_build_context_dir(pocfile, base_image):
        context_dir = os.path.join(tempfile.gettempdir(), 'cscan-poc-build')
        if os.path.exists(context_dir):
            shutil.rmtree(context_dir)
        os.mkdir(context_dir)
        dockerfile = os.path.join(context_dir, 'Dockerfile')
        shutil.copyfile(pocfile, os.path.join(context_dir, 'main.py'))

        with open(dockerfile, 'w') as f:
            f.write('FROM {}\n'.format(base_image))
            f.write('COPY main.py /app/main.py\n')
            f.write('ENTRYPOINT [ "pipenv",  "run", "python", "main.py" ]')

        return context_dir

    tag = build_base.split(':')
    tag = tag[1] if len(tag) == 2 else 'latest'
    if poc.poc_id is None or poc.poc_id.strip() == '':
        logging.warn('跳过 {} poc_id 不存在'.format(poc_file))

    build_context = create_image_build_context_dir(poc_file, build_base)
    poc_name = 'poc-{}:{}'.format(poc.poc_id, tag)
    cmd_image_exists = 'docker inspect --type=image {} >/dev/null 2>&1 '.format(
        poc_name)
    cmd = 'cd {} && docker build -t {} .'.format(build_context, poc_name)
    if not force_rebuild and os.system(cmd_image_exists) == 0:
        logging.debug('使用之前编译过的镜像缓存')
        return poc_name
    logging.info('Building image {}: {}'.format(poc_name, cmd))
    res = os.system(cmd)
    if registry is not None:
        img = '{}/{}'.format(registry, poc_name)
    if res == 0:
        return poc_name
    else:
        logging.warn('镜像构建失败 {}'.format(poc_file))
        return None
