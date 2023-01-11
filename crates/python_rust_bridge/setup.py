from distutils.core import setup
from setuptools_rust import Binding, RustExtension

setup(
    name='python-rust-bridge',
    version='1.0',
    rust_extensions=[RustExtension("python_rust_bridge.python_rust_bridge", binding=Binding.PyO3)],
    author="Starkware",
    author_email="info@starkware.co",
    description="Rust binding for python",
)
