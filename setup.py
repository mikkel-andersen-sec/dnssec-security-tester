from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='dnssec-security-tester',
    version='0.1.0',
    description='Comprehensive DNSSEC security testing and validation tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Mikkel Andersen',
    author_email='mikkel.andersen@sentinelcybersecurity.com',
    url='https://github.com/mikkel-andersen-sec/dnssec-security-tester',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'dnspython>=2.4.0',
        'cryptography>=40.0.0',
        'click>=8.0.0',
        'tabulate>=0.9.0',
        'colorama>=0.4.4',
        'pydantic>=2.0.0',
        'python-dateutil>=2.8.2',
        'requests>=2.28.0',
        'jinja2>=3.1.0',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'dnssec-tester=dnssec_tester.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: System :: Networking',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
