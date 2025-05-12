from setuptools import setup, find_packages

setup(
    name="sentry-aliyun-sls-plugin-example",
    version="0.1.0",
    author="Your Name", 
    author_email="your.email@example.com", 
    packages=find_packages(),
    install_requires=[
        "aliyun-log-python-sdk", 
    ],
    entry_points={
        "sentry.plugins": [
            "aliyunsls = sentry_plugins.aliyunsls.plugin:AliyunSLSPlugin",
        ]
    },
    include_package_data=True,
)