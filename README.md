# File Manager Application

This Python application provides a graphical user interface (GUI) for managing files and folders, along with features for compression, decompression, encryption, and decryption. It's designed for ease of use and runs with administrator privileges for accessing system-level functionalities.

## Features:

* **Browse and Navigate:** Easily browse and navigate through directories using the file list and directory input.
* **File Operations:**
    * **Open:** Open files using their default applications.
    * **Delete:** Delete files and folders, with an option for secure deletion.
    * **Copy:** Copy files and folders to a chosen destination, with options for hash verification and deleting the source after copying.
* **Compression and Decompression:**
    * **Compress:** Compress selected files and folders into a ZIP archive.
    * **Decompress:** Extract files from a selected ZIP archive.
* **Encryption and Decryption:**
    * **Encrypt:** Encrypt selected files using the Fernet library, providing strong encryption with a user-provided password.
    * **Decrypt:** Decrypt encrypted files using the correct password.
* **Search:**  Quickly search for files and folders by name within the current directory.
* **Share over Wi-Fi:** Share files wirelessly using the `qrcp` command-line utility.
* **Secure Delete:**  Optionally overwrite deleted files with random data for enhanced privacy.
* **Hash Verification:** Verify the integrity of copied files by comparing their SHA256 hash values.

## Requirements:

* Python 3.x
* PyQt5 library
* cryptography library
* qrcp (optional, for Wi-Fi sharing - place the `qrcp.exe` in a "bin" folder in the same directory as the script)
* Download qrcp from here : https://github.com/claudiodangelis/qrcp/releases/latest

## Usage:

1. **Run the script:**  Ensure you are running the script with administrator privileges (right-click and select "Run as administrator").
2. **Browse for directory:** Use the "Browse" button to select the directory you want to work with.
3. **Navigate and manage files:** Use the file list to navigate, open, delete, copy, compress, decompress, encrypt, or decrypt files and folders. 
4. **Search:** Use the search bar to find specific files or folders.
5. **Share (Optional):**  Use the "Share" button to share a single selected file over Wi-Fi using `qrcp`.

## Code Structure:

* **`run_as_admin()`:**  Attempts to relaunch the script with administrator privileges.
* **`secure_delete(file_path)`:** Overwrites the given file with random data before deleting it.
* **`calculate_hash(file_path, algorithm='sha256')`:** Calculates the hash of a file using the specified algorithm.
* **`is_connected_to_wifi()`:** Checks if the computer is connected to a Wi-Fi network.
* **`WorkerThread` Class:**
    * Handles file operations (compression, decompression, encryption, decryption) in a separate thread to prevent the GUI from freezing.
* **`FileManager` Class:**
    * Creates the main application window and user interface elements.
    * Handles user interactions, such as button clicks and file list selections.
    * Implements logic for file and folder operations, search, sharing, encryption, and decryption.

## Security Notes:

* **Windows Directory Protection:** The application prevents access to the `C:\Windows` directory to protect system files.
* **Secure Deletion:** The "Secure Delete" option provides an additional layer of privacy by overwriting file data before deletion.
* **Encryption:** The encryption feature uses the Fernet library for strong, symmetric encryption, but users are responsible for managing their passwords securely. 

## Further Development:

* **Drag and Drop:** Implement drag-and-drop support for files and folders from the operating system's file explorer. This will require a custom model or delegate for the `QListWidget` and handling of MIME data.
* **WebDAV Server:**  Add functionality to start and stop a WebDAV server, allowing users to access their files remotely.

## License:

This project is open source and available under the MIT License. Feel free to use, modify, and distribute it as needed.
