from distutils.core import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="native-blockifier",
    version="1.0",
    rust_extensions=[RustExtension("native-blockifier.native-blockifier", binding=Binding.PyO3)],
    author="Starkware",
    author_email="info@starkware.co",
    description="Rust binding for python",
)
