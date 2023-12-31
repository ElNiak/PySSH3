from setuptools import setup, find_packages

setup(
    name="py-ssh3",
    version="0.1",
    description="Python SSH3 version",
    author="ElNiak",
    author_email="elniak@email.com",
    packages=find_packages(),
    install_requires=[
        # "aiohttp",
        # "pyOpenSSL",
        "cryptography",
        # "aioquic==0.9.24",
        "pyjwt",
        # "http3",
        "authlib",
        # "PyCryptodome",
        # "sanic",
        "paramiko",
        # "h11==0.9.0",
        "wsproto",
        "jinja2",
        "starlette",
    ],
)

