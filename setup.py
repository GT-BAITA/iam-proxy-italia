"""
Modulo de setup da lib
Este é um arquivo que não está definido na biblioteca para ser baixada
como lib e portanto definimos aqui para poder instalar a lib como um pacote python dentro do container
"""

import re
from glob import glob

from setuptools import find_packages, setup

PKG_NAME = "cieoidc"

init_path = "./iam-proxy-italia-project/backends/cieoidc/__init__.py"
with open(file=init_path, encoding="utf-8") as fd:
    VERSION = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE
    ).group(1)

setup(
    name=PKG_NAME,
    version=VERSION,
    description="OpenID Connect ↔ OpenID Federation bridge for SATOSA.",
    # long_description removido
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    url="https://github.com/GT-BAITA/eudi-wallet-it-python",
    author="Giuseppe De Marco",
    author_email="demarcog83@gmail.com",
    packages=find_packages(
        where="iam-proxy-italia-project/backends",
        exclude=["*.tests", "*.tests.*", "tests.*", "tests"],
    ),
    package_dir={"": "iam-proxy-italia-project/backends"},
    package_data={
        PKG_NAME: [
            i.replace(f"{PKG_NAME}/", "")
            for i in glob(
                f"iam-proxy-italia-project/backends/{PKG_NAME}/**", recursive=True
            )
        ]
    },
    install_requires=[
        "cryptojwt>=1.9,<1.11",
        "pydantic>=2.11.9,<3.0.0",
        "pem>=23.1,<23.2",
        "cryptography>=43.0.3",
        "pyeudiw[satosa] @ git+https://github.com/italia/eudi-wallet-it-python@c9d46cc61f0c77ecec21d43c72f49a85f462bc48",
        "asyncio>=3.4.3,<4.0.0",
        "aiohttp>=3.11.11,<4.0.0",
        "pyopenssl>=24.2.1",
        "pip>=26.0",  # CVE-2026-1703: path traversal when extracting wheels; fixed in 26.0
        "setuptools>=78.1.1",  # PYSEC-2022-43012, PYSEC-2025-49, CVE-2024-6345
        "uwsgi (>=2.0.28,<3.0.0)",
    ],
)
