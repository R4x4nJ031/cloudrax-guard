from setuptools import setup, find_packages

setup(
    name="cloudrax-guard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "rich",
        "pyyaml",
        "python-hcl2",
    ],
    entry_points={
        "console_scripts": [
            "cloudrax-guard=cloudrax_guard.main:cli",
        ],
    },
)