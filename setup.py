# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from setuptools import setup, find_namespace_packages
import setuptools_scm

setup(
    name='apkscan',
    version='0.2.2',
    use_scm_version=True,
    setup_requires=['setuptools_scm>=8'],
    description='Scan for secrets, endpoints, and other sensitive data after decompiling and deobfuscating Android files. (.apk, .xapk, .dex, .jar, .class, .smali, .zip, .aar, .arsc, .aab, .jadx.kts)',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Lucas Faudman',
    author_email='lucasfaudman@gmail.com',
    url='https://github.com/LucasFaudman/apkscan',
    packages=find_namespace_packages(where='src', exclude=['tests*']),
    package_dir={'': 'src'},
    package_data={
        '': ['LICENSE'],
        'apkscan.secret_locators': ['*.json', '*.yaml', '*.yml', '*.toml'],
    },
    include_package_data=True,
    exclude_package_data={'': ['.gitignore', '.pre-commit-config.yaml']},
    install_requires=[
        'enjarify-adapter',
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'apkscan = apkscan.main:main',
        ],
    },
    python_requires='>=3.11',
    license='LICENSE',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    keywords='secret scanner jadx decompile android java security mobile decompiler concurrency penetration-testing apktool security-tools fernflower cfr jadx procyon enjarify krakatau secret-scanning decompiler-java secret-scanner apk dex jar class smali zip aar arsc aab xapk jadx.kts ',
    project_urls={
        'Homepage': 'https://github.com/LucasFaudman/apkscan',
        'Repository': 'https://github.com/LucasFaudman/apkscan',
    },
)
