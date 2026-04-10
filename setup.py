from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name             = 'decod3x',
    version          = '1.0.0',
    author           = 'Rohit',
    description      = 'Smart Data Triage Engine for '
                       'Cybersecurity Professionals & CTF Players',
    long_description          = long_description,
    long_description_content_type = "text/markdown",
    python_requires  = '>=3.7',
    packages         = find_packages(
        exclude=['tests*', 'db_init*']
    
    ),
    py_modules=['decod3x'],
    install_requires = [
        'colorama>=0.4.6',
    ],
    entry_points     = {
        'console_scripts': [
            'decod3x=decod3x:main',
        ],
    },
    classifiers      = [
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
    ],
    keywords         = [
        'cybersecurity', 'soc', 'ctf',
        'encoding', 'hash', 'encryption',
        'forensics', 'triage', 'cli'
    ],
)