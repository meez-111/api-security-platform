from setuptools import setup, find_packages

setup(
    name="horsesec-scanner",
    version="1.0.0",
    description="A comprehensive API security scanning tool",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/horsesec-scanner",
    package_dir={"": "src"},  # Tell setuptools packages are under src
    packages=find_packages(where="src"),  # Find packages in src directory
    install_requires=[
        "aiohttp>=3.8.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "horsesec=security_scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="security api scanner vulnerability detection",
    include_package_data=True,
)
