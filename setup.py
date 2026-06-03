from setuptools import setup, find_packages

setup(
    name="slither-eip7702",
    version="0.0.1",
    description="Slither detector pack for EIP-7702 delegate-contract security footguns",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["slither-analyzer>=0.10.0"],
    entry_points={
        "slither_analyzer.plugin": [
            "slither-eip7702 = slither_eip7702:make_plugin",
        ],
    },
)
