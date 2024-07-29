# Auto SSH Exploit Script

This script is designed to automatically exploit SSH vulnerabilities by scanning a block of IP addresses. Once a vulnerable IP is found, it will automatically be exploited.

## Features

- **Automated IP Scanning**: Scans a block of IP addresses for SSH vulnerabilities.
- **Auto Exploitation**: Automatically exploits the found vulnerabilities.
- **Easy to Use**: Execute the script with a single command.

## Requirements

- **Operating System**: Linux-based
- **Dependencies**: Ensure you have the following tools installed:
  - `nmap`
  - `sshpass`
  - `expect`

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/Sincan2/regreSSHion.git
cd regreSSHion
chmod +x sodok.sh
```

## Usage

To execute the script, simply run:

```bash
./sodok.sh
```

The script will start scanning the specified IP block and automatically exploit any vulnerable SSH services it encounters.

## Script Breakdown

1. **IP Scanning**: Uses `nmap` to scan a block of IP addresses for open SSH ports.
2. **Vulnerability Detection**: Identifies SSH services with default or weak credentials.
3. **Exploitation**: Uses `sshpass` and `expect` to automate the exploitation process.

## Disclaimer

This script is intended for educational purposes only. Unauthorized use of this script is illegal and unethical. Always obtain proper authorization before scanning or exploiting any network.

## Contributing

We welcome contributions! If you have any improvements or suggestions, feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or support, www.mergosono.my.id.

---

By following this structure, your README will be informative, easy to read, and provide all the necessary details for users to understand and use your script effectively.
