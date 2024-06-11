from setuptools import setup, find_packages
import setuptools_scm

setup(
    name='apkscan',
    version='0.1.0',
    use_scm_version=True,
    setup_requires=['setuptools_scm>=8'],
    description='Decompile and scan for secrets in .apk, .xapk, .jar, .dex, .class, .smali, .zip, .aar, .arsc, .aab, .jadx.kts files',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Lucas Faudman',
    author_email='lucasfaudman@gmail.com',
    url='https://github.com/LucasFaudman/apk-secret-scanner.git',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=[
        'enjarify-adapter',
        'pyyaml',
    ],
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
    keywords='secret scanner jadx decompile apk dex jar class smali zip aar arsc aab xapk jadx.kts',
    project_urls={
        'Homepage': 'https://github.com/LucasFaudman/apk-secret-scanner.git',
        'Repository': 'https://github.com/LucasFaudman/apk-secret-scanner.git',
    },
    entry_points={
        'console_scripts': [
            'apkscan = apkscan.main:main',
        ],
    },
)
