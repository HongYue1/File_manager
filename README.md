# File Manager Application

This is a Python application that provides a graphical user interface (GUI) for managing files and directories. It offers the following features:

- **Browsing:** Easily navigate through directories and view files.
- **File Operations:** 
    - Open files.
    - Copy files and directories.
    - Delete files and directories (with an option for secure deletion).
- **Compression/Decompression:** 
    - Compress files and folders into ZIP archives.
    - Decompress ZIP archives.
- **Search:** Search for files and folders within the current directory.
- **Wi-Fi File Sharing:** Share files over Wi-Fi using the `qrcp` command-line utility. 
- **Security:** Includes a secure delete option that overwrites data before deleting files for better privacy.
- **User Interface:** Features a dark theme  for a more visually appealing user experience.

## Requirements

- Python 3.x
- PyQt5 library (`pip install PyQt5`)
- `qrcp` command-line utility (place `qrcp.exe` in a folder named `bin` in the same directory as the script).

## Usage

1. Run the `main.py` script.
2. The File Manager window will open, displaying the contents of the current working directory.
3. Use the buttons and interface elements to perform file operations.

## Interface Elements

- **Directory Input:** Enter or browse to the desired directory path.
- **Browse Button:** Opens a dialog for selecting a directory.
- **Search Bar:** Enter text to search for files and folders.
- **File List:** Displays the files and directories in the current directory.
- **Delete Button:** Deletes the selected files or directories.
- **Copy Button:** Copies the selected files or directories to a chosen location.
- **Compress Button:** Creates a ZIP archive of the selected files or folders.
- **Decompress Button:** Extracts the contents of a selected ZIP archive.
- **Share Button:** Uses `qrcp` to share the selected file over Wi-Fi.

## Important Notes

- Ensure that the `qrcp.exe` file is placed in a folder named `bin` in the same directory as the `main.py` script for file sharing to work correctly.
- For secure deletion, the application overwrites the file's data multiple times before deleting it to make recovery more difficult, but it's more time consuming and reduces disk life due to multiple write operations.

