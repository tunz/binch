from setuptools import setup, find_packages

py_modules = [
'pyelftools',
'capstone',
'keystone-engine',
'urwid',
'blinker',
'progressbar2'
]

setup (
        name = 'binch',
        version = '0.3.1',
        description = 'a light ELF binary patch tool',
        author = 'Choongwoo Han',
        author_email = 'cwhan.tunz@gmail.com',
        url = 'https://github.com/tunz/binch',
        license = 'MIT',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Topic :: Security',
            'Topic :: Software Development',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'License :: OSI Approved :: MIT License',
            'Environment :: Console',
            'Environment :: Console :: Curses',
            'Operating System :: MacOS',
            'Operating System :: POSIX :: Linux'
            ],
        keywords = 'disassemble binary patch',
        packages = find_packages(),
        install_requires = py_modules,
        entry_points = {
            'console_scripts': ['binch = binchlib.main:binch']
            }
)
