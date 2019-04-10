# -*- coding: utf-8 -*-
# 依赖包 pip install pycryptodome
# 如果仍然报没有Module可以尝试将 python安装目录下site-packages的子文件夹crypto改成Crypto
from Crypto import Random
from Crypto.PublicKey import RSA
# 利用伪随机数来生成私钥和公钥
random_generator = Random.new().read

keys = RSA.generate(1024, random_generator)

private_pem = keys.exportKey()

f = open('private_key.pem', 'w')
f.write(private_pem.decode('utf-8'))
f.close()

public_pem = keys.publickey().exportKey()
f = open('public_key.pem', 'w')
f.write(public_pem.decode('utf-8'))
f.close()