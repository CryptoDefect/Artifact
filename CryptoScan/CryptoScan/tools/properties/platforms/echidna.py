from pathlib import Path

from CryptoScan.tools.properties.addresses.address import Addresses
from CryptoScan.tools.properties.utils import write_file


def generate_echidna_config(output_dir: Path, addresses: Addresses) -> str:
    """
    Generate the echidna configuration file
    :param output_dir:
    :param addresses:
    :return:
    """
    content = "prefix: crytic_\n"
    content += f'deployer: "{addresses.owner}"\n'
    content += f'sender: ["{addresses.user}", "{addresses.attacker}"]\n'
    content += f'psender: "{addresses.user}"\n'
    content += "coverage: true\n"
    filename = "echidna_config.yaml"
    write_file(output_dir, filename, content)
    return filename
