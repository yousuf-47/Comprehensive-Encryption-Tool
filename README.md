
# Comprehensive Encryption Tool

The Comprehensive Encryption Tool is a versatile encryption and decryption application that supports multiple algorithms including AES-GCM, AES-CBC, and ChaCha20. It features a graphical user interface (GUI) built with Tkinter and provides functionalities for both file and text input/output. Additionally, it includes RSA-based digital signature verification to ensure data integrity.




## Features

- **Encryption Algorithms**: Supports AES-GCM, AES-CBC, and ChaCha20.
- **Digital Signature**: Uses RSA to sign and verify data, ensuring data authenticity.
- **Input/Output Modes**: Can handle both file and text inputs and outputs.
- **User-Friendly Interface**: Easy-to-use GUI built with Tkinter.
- **Key Management**: Automatically generates and saves RSA keys.

## Installation

To get started with the Comprehensive Encryption Tool, follow these steps:

- **Clone the repository**:

  ```bash
  git clone https://github.com/yousuf-47/Comprehensive-Encryption-Tool.git
  cd Comprehensive-Encryption-Tool
  ```
- **Ensure you have Python 3.x installed. Then, install the required Python packages**:


  ```bash
  pip install -r requirements.txt
  ```

- **Run the application**:
  ```bash
  python encryption_tool.py
  ```


## Usage/Examples

The Comprehensive Encryption Tool offers a simple interface for encrypting, decrypting, and verifying signatures.

### Encrypting Data

- **Select Encryption**: Choose between AES-GCM, AES-CBC, or ChaCha20.
- **Choose Input Mode**: Select whether to encrypt text or a file.
- **Enter Data**: If encrypting text, enter it in the input field. If encrypting a file, use the file dialog to select the file.
- **Encrypt**: Click the "Encrypt" button to encrypt the data. The output will be displayed or saved based on your chosen output mode.

### Decrypting Data

- **Choose Input Mode**: Select whether to decrypt text or a file.
- **Enter Encrypted Data**: If decrypting text, paste the encrypted data in the input field. If decrypting a file, use the file dialog to select the file.
- **Decrypt**: Click the "Decrypt" button to decrypt the data. The output will be displayed or saved based on your chosen output mode.

### Verifying Signature

- **Choose Input Mode**: Select whether to verify the signature of text or a file.
- **Enter Encrypted Data**: If verifying text, paste the encrypted data in the input field. If verifying a file, use the file dialog to select the file.
- **Verify Signature**: Click the "Verify Signature" button to verify the data’s signature.

### Example 1: Encrypting a Text

- Select AES-GCM as the algorithm.
- Choose Text as the input mode.
- Enter "Hello, World!" in the input field.
- Click Encrypt.
- The encrypted text will appear in the output field.

### Example 2: Decrypting a File

- Choose File as the input mode.
- Select the encrypted file using the file dialog.
- Click Decrypt.
- The decrypted content will be saved or displayed based on the output mode.



## License

This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License


## Acknowledgements

 - Thanks to the authors of the **pycryptodome** library for providing the cryptographic primitives.
- Inspiration from various encryption tools and GUI applications.

