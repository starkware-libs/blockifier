from distutils.core import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="native_blockifier",
    version="0.16.5",
    rust_extensions=[RustExtension("native_blockifier.native_blockifier", binding=Binding.PyO3)],
    author="Starkware",
    author_email="info@starkware.co",
    description="Rust binding for python",
)
