from distutils.core import setup
from setuptools_rust import Binding, RustExtension

import os

setup(
    name="native_blockifier",
    version=os.environ.get("GIT_REF", "0.1.0"),
    rust_extensions=[RustExtension("native_blockifier.native_blockifier", binding=Binding.PyO3)],
    author="Starkware",
    author_email="info@starkware.co",
    description="Rust binding for python",
)
