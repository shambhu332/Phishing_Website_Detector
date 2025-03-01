from setuptools import setup, find_packages

setup(
    name="phishing_detector",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'python-whois',
        'tldextract',
        'mysql-connector-python'
    ],
)
