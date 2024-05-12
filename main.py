import os
import sys
import zipfile
import shutil
import ctypes, sys
import hashlib
import subprocess  # For running external commands
import socket  # For checking internet connection

from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QListWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFileDialog,
    QMessageBox,
    QCheckBox,
    QProgressDialog,
)
from PyQt5.QtGui import QIcon, QPalette, QColor
from PyQt5.QtCore import Qt, QUrl, QThread, pyqtSignal


def run_as_admin():
    """Tries to relaunch the script with administrator privileges."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()


def secure_delete(file_path):
    """Overwrites the file with random data before deleting."""
    file_size = os.path.getsize(file_path)
    with open(file_path, "wb") as file:
        for _ in range(10):
            file.seek(0)
            file.write(os.urandom(file_size))
    os.remove(file_path)


def calculate_hash(file_path, algorithm="sha256"):
    """Calculate the hash of a file using the specified algorithm."""
    hash_obj = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):  # Read file in chunks
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def is_connected_to_wifi():
    """Checks if the computer is connected to a Wi-Fi network."""
    try:
        # Try to resolve a known hostname (e.g., Cloudflare's DNS server)
        socket.gethostbyname("one.one.one.one")
        return True
    except socket.gaierror:
        return False


class WorkerThread(QThread):
    """Worker thread for performing file operations in the background."""

    progress_updated = pyqtSignal(int)  # Signal to update progress bar
    task_finished = pyqtSignal(bool)  # Signal whether task was successful

    def __init__(
        self, operation, source_directory, destination=None, selected_items=None
    ):
        super().__init__()
        self.operation = operation  # "compress" or "decompress"
        self.source_directory = source_directory
        self.destination = destination
        self.selected_items = selected_items
        self.cancelled = False

    def run(self):
        """Start the thread's operation."""
        if self.operation == "compress":
            self.compress_files()
        elif self.operation == "decompress":
            self.decompress_files()

    def compress_files(self):
        """Compresses the selected files into a ZIP archive."""
        if self.cancelled:
            self.task_finished.emit(False)
            return

        if self.source_directory.endswith((".zip")):
            QMessageBox.warning(None, "Error", "Cannot compress an archive file.")
            self.task_finished.emit(False)
            return

        if self.destination is None:
            QMessageBox.warning(None, "Error", "No destination file selected.")
            self.task_finished.emit(False)
            return

        if os.path.exists(self.destination):
            if self.cancelled:
                self.task_finished.emit(False)
                return

            result = QMessageBox.question(
                None,
                "File Exists",
                "The destination file already exists. Do you want to overwrite it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result == QMessageBox.No:
                self.task_finished.emit(False)
                return

        if self.destination.endswith(".zip"):
            with zipfile.ZipFile(self.destination, "w", zipfile.ZIP_DEFLATED) as zipf:
                for item in self.selected_items:
                    if self.cancelled:
                        self.task_finished.emit(False)
                        return

                    item_path = os.path.join(self.source_directory, item.text())
                    if os.path.isdir(item_path):
                        for foldername, _, filenames in os.walk(item_path):
                            for filename in filenames:
                                if self.cancelled:
                                    self.task_finished.emit(False)
                                    return

                                file_path = os.path.join(foldername, filename)
                                zipf.write(
                                    file_path,
                                    os.path.relpath(file_path, self.source_directory),
                                )
                    else:
                        zipf.write(
                            item_path,
                            os.path.relpath(item_path, self.source_directory),
                        )
        else:
            QMessageBox.warning(None, "Error", "Invalid archive format.")
            self.task_finished.emit(False)
            return

        if self.cancelled:
            self.task_finished.emit(False)
            return

        self.task_finished.emit(True)

    def decompress_files(self):
        """Decompresses the selected ZIP archive."""
        if self.cancelled:
            self.task_finished.emit(False)
            return

        if not self.source_directory.endswith((".zip")):
            QMessageBox.warning(None, "Error", "Not a valid archive file.")
            self.task_finished.emit(False)
            return

        if self.destination is None:
            self.destination = os.path.splitext(self.source_directory)[0]

        if os.path.exists(self.destination):
            if self.cancelled:
                self.task_finished.emit(False)
                return

            result = QMessageBox.question(
                None,
                "Folder Exists",
                "The destination folder already exists. Do you want to overwrite it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result == QMessageBox.No:
                self.task_finished.emit(False)
                return

        if self.source_directory.endswith(".zip"):
            with zipfile.ZipFile(self.source_directory, "r") as zip_ref:
                zip_ref.extractall(self.destination)
        else:
            QMessageBox.warning(None, "Error", "Invalid archive format.")
            self.task_finished.emit(False)
            return

        if self.cancelled:
            self.task_finished.emit(False)
            return

        self.task_finished.emit(True)


class FileManager(QWidget):
    """Main application window for the File Manager."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Manager")
        self.setGeometry(100, 100, 800, 600)
        self.set_theme()
        self.init_ui()
        self.check_admin()

    def set_theme(self):
        """Sets the application's color theme."""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(15, 15, 15))
        palette.setColor(QPalette.WindowText, QColor(248, 248, 242))
        palette.setColor(QPalette.Base, QColor(24, 24, 24))
        palette.setColor(QPalette.AlternateBase, QColor(40, 42, 46))
        palette.setColor(QPalette.Highlight, QColor(108, 118, 135))
        palette.setColor(QPalette.HighlightedText, QColor(248, 248, 242))
        palette.setColor(QPalette.Button, QColor(40, 42, 46))
        palette.setColor(QPalette.ButtonText, QColor(248, 248, 242))
        QApplication.setPalette(palette)

        # Style for buttons and message box
        app.setStyleSheet(
            "QPushButton { border: 1px solid #58657e; padding: 5px; }"
            "QPushButton:hover { background-color: #323437; }"
            "QListWidget { color: white; }"
            "QMessageBox QLabel { color: #248; }"
            "QMessageBox QPushButton { border: 1px solid #58657e; padding: 5px; color: #248; }"
            "QMessageBox QPushButton:hover { background-color: #323437; }"
            "QMessageBox QCheckBox { color: black; }"
            "QProgressBar { text-align: center; color: white; }"
            "QProgressBar::chunk { background-color: #0078D7; }"
        )

    def init_ui(self):
        """Initializes the user interface, creating widgets and layouts."""
        # Layout
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        bottom_layout = QHBoxLayout()
        search_layout = QHBoxLayout()

        # Directory Input
        self.directory_input = QLineEdit()
        self.directory_input.setPlaceholderText("Enter directory path")
        top_layout.addWidget(self.directory_input)

        # Browse Button
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_directory)
        top_layout.addWidget(self.browse_button)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search files...")
        self.search_input.textChanged.connect(self.search_files)
        search_layout.addWidget(self.search_input)

        # File List
        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self.open_file)
        main_layout.addWidget(self.file_list)

        # Delete Button
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_selected)
        bottom_layout.addWidget(self.delete_button)

        # Copy Button
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_file)
        bottom_layout.addWidget(self.copy_button)

        # Compress Button
        self.compress_button = QPushButton("Compress")
        self.compress_button.clicked.connect(self.compress_files)
        bottom_layout.addWidget(self.compress_button)

        # Decompress Button
        self.decompress_button = QPushButton("Decompress")
        self.decompress_button.clicked.connect(self.decompress_files)
        bottom_layout.addWidget(self.decompress_button)

        # Share Button
        self.share_button = QPushButton("Share")
        self.share_button.clicked.connect(self.share_file)
        bottom_layout.addWidget(self.share_button)

        # Add layouts
        main_layout.addLayout(top_layout)
        main_layout.addLayout(search_layout)
        main_layout.addLayout(bottom_layout)
        self.setLayout(main_layout)

        # Show Initial Directory
        self.update_file_list(os.getcwd())

    def check_admin(self):
        """Checks if the application has administrator privileges and prompts
        for elevation if needed.
        """
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False

        if not is_admin:
            result = QMessageBox.question(
                self,
                "Admin Rights Required",
                "This application requires administrator privileges. "
                "Do you want to run it as administrator?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if result == QMessageBox.Yes:
                run_as_admin()
            else:
                sys.exit()

    def browse_directory(self):
        """Opens a dialog to select a directory and updates the file list."""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            # Prevent entering C:\Windows
            if os.path.abspath(directory).startswith(os.path.abspath(r"C:\Windows")):
                QMessageBox.warning(
                    self,
                    "Restricted Access",
                    "Access to the Windows directory is prohibited.",
                )
            else:
                self.directory_input.setText(directory)
                self.update_file_list(directory)

    def update_file_list(self, directory):
        """Updates the file list widget with the contents of the given directory."""
        self.file_list.clear()
        if self.directory_input.text() != "C:\\":
            self.file_list.addItem("Go Up")  # Special item for navigating up
        try:
            for item in os.listdir(directory):
                self.file_list.addItem(item)
        except PermissionError:
            QMessageBox.warning(
                self,
                "Access Denied",
                f"You do not have permission to access '{directory}'",
            )

    def open_file(self, item):
        """Opens the selected file or navigates into the selected directory."""
        if item.text() == "Go Up":
            self.go_up_directory()
        else:
            file_path = os.path.join(self.directory_input.text(), item.text())
            # Prevent entering C:\Windows
            if os.path.abspath(file_path).startswith(os.path.abspath(r"C:\Windows")):
                QMessageBox.warning(
                    self,
                    "Restricted Access",
                    "Access to the Windows directory is prohibited.",
                )
            else:
                if os.path.isdir(file_path):
                    self.directory_input.setText(file_path)
                    self.update_file_list(file_path)
                elif os.path.isfile(file_path):
                    QUrl.fromLocalFile(file_path).toString()
                else:
                    QMessageBox.warning(self, "Error", f"Path not found: {file_path}")

    def go_up_directory(self):
        """Navigates to the parent directory."""
        current_path = self.directory_input.text()
        if not current_path:
            current_path = os.getcwd()
        parent_path = os.path.dirname(current_path)
        if os.path.exists(parent_path):
            self.directory_input.setText(parent_path)
            self.update_file_list(parent_path)

    def delete_selected(self):
        """Deletes the selected files or directories, with an option for secure delete."""
        selected_items = self.file_list.selectedItems()
        if selected_items:
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Question)
            msg_box.setWindowTitle("Confirm Delete")
            msg_box.setText("Are you sure you want to delete the selected item(s)?")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

            # Add Secure Delete Checkbox
            secure_delete_checkbox = QCheckBox("Secure Delete", msg_box)
            msg_box.layout().addWidget(
                secure_delete_checkbox, 1, 0, 1, msg_box.layout().columnCount()
            )

            result = msg_box.exec_()

            if result == QMessageBox.Yes:
                for item in selected_items:
                    # Prevent deletion of "Go Up"
                    if item.text() == "Go Up":
                        continue
                    file_path = os.path.join(self.directory_input.text(), item.text())
                    if os.path.exists(file_path):
                        if secure_delete_checkbox.isChecked():
                            secure_delete(file_path)
                        else:
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                            else:
                                shutil.rmtree(file_path)
                        self.file_list.takeItem(self.file_list.row(item))

                self.update_file_list(self.directory_input.text())

    def copy_file(self):
        """Copies selected files or directories to a chosen destination."""
        selected_items = self.file_list.selectedItems()
        if selected_items:
            dest_dir = QFileDialog.getExistingDirectory(
                self, "Select Destination Directory"
            )
            if dest_dir:
                # Create a dialog with checkboxes for copy options
                msg_box = QMessageBox(self)
                msg_box.setIcon(QMessageBox.Question)
                msg_box.setWindowTitle("Copy Options")
                msg_box.setText("Select copy options:")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)

                # Add checkboxes
                verify_hash_checkbox = QCheckBox(
                    "Verify file hash after copying", msg_box
                )
                delete_source_checkbox = QCheckBox(
                    "Delete source after copying", msg_box
                )
                msg_box.layout().addWidget(verify_hash_checkbox, 1, 0, 1, 2)
                msg_box.layout().addWidget(delete_source_checkbox, 2, 0, 1, 2)

                result = msg_box.exec_()
                if result == QMessageBox.Ok:
                    for item in selected_items:
                        if item.text() == "Go Up":
                            continue
                        src_path = os.path.join(
                            self.directory_input.text(), item.text()
                        )
                        dest_path = os.path.join(dest_dir, item.text())
                        if os.path.exists(src_path):
                            if os.path.isfile(src_path):
                                shutil.copy2(src_path, dest_path)
                                if verify_hash_checkbox.isChecked():
                                    src_hash = calculate_hash(src_path)
                                    dest_hash = calculate_hash(dest_path)
                                    if src_hash == dest_hash:
                                        QMessageBox.information(
                                            self,
                                            "Hash Verification",
                                            f"File copied and verified successfully: {item.text()}",
                                        )
                                    else:
                                        QMessageBox.warning(
                                            self,
                                            "Hash Mismatch",
                                            f"File copy verification failed for {item.text()}",
                                        )
                                if delete_source_checkbox.isChecked():
                                    os.remove(src_path)
                            else:  # It's a directory
                                shutil.copytree(src_path, dest_path)
                                verify_hash_checkbox.setChecked(False)
                                verify_hash_checkbox.setEnabled(False)
                                if delete_source_checkbox.isChecked():
                                    shutil.rmtree(src_path)

    def search_files(self, search_text):
        """Searches for files and folders matching the search text in the current directory."""
        self.file_list.clear()
        current_directory = self.directory_input.text()
        if current_directory != "C:\\":
            self.file_list.addItem("Go Up")
        try:
            for item in os.listdir(current_directory):
                if search_text.lower() in item.lower():
                    self.file_list.addItem(item)
        except PermissionError:
            QMessageBox.warning(
                self,
                "Access Denied",
                f"You do not have permission to access '{current_directory}'",
            )

    def compress_files(self):
        """Compresses the selected files into a ZIP archive in a background thread."""
        selected_items = self.file_list.selectedItems()
        if not selected_items or (
            len(selected_items) == 1 and selected_items[0].text() == "Go Up"
        ):
            QMessageBox.warning(
                self,
                "Invalid Selection",
                "Please select valid file(s) or folder(s) to compress.",
            )
            return

        source_directory = self.directory_input.text()

        if len(selected_items) == 1:
            default_filename = os.path.splitext(selected_items[0].text())[0] + ".zip"
        else:
            default_filename = "compressed_files.zip"

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Compressed File",
            os.path.join(source_directory, default_filename),
            "ZIP Files (*.zip)",
            options=options,
        )
        if file_name:
            self.compress_thread = WorkerThread(
                "compress", source_directory, file_name, selected_items
            )
            self.compress_thread.task_finished.connect(self.compression_finished)
            self.progress_dialog = QProgressDialog(
                "Compressing...", "Cancel", 0, 100, self
            )
            self.progress_dialog.setWindowTitle("Compression Progress")
            self.progress_dialog.setWindowModality(Qt.WindowModal)
            self.progress_dialog.canceled.connect(self.cancel_compression)
            self.compress_thread.start()
            self.progress_dialog.exec_()

    def decompress_files(self):
        """Decompresses the selected ZIP archive in a background thread."""
        selected_items = self.file_list.selectedItems()
        if selected_items:
            if len(selected_items) == 1 and selected_items[0].text() == "Go Up":
                QMessageBox.warning(
                    self, "Invalid Selection", "Cannot decompress 'Go Up'."
                )
                return

            source_file = os.path.join(
                self.directory_input.text(), selected_items[0].text()
            )
            if not source_file.endswith((".zip")):
                QMessageBox.warning(
                    self, "Invalid File", "Selected file is not a compressed archive."
                )
                return

            dest_dir = QFileDialog.getExistingDirectory(
                self, "Select Destination Directory"
            )
            if dest_dir:
                self.decompress_thread = WorkerThread(
                    "decompress", source_file, dest_dir
                )
                self.decompress_thread.task_finished.connect(
                    self.decompression_finished
                )
                self.progress_dialog = QProgressDialog(
                    "Decompressing...", "Cancel", 0, 100, self
                )
                self.progress_dialog.setWindowTitle("Decompression Progress")
                self.progress_dialog.setWindowModality(Qt.WindowModal)
                self.progress_dialog.canceled.connect(self.cancel_decompression)
                self.decompress_thread.start()
                self.progress_dialog.exec_()

    def compression_finished(self, successful):
        """Handles the completion of the compression thread."""
        self.progress_dialog.setValue(100)
        self.progress_dialog.close()
        if successful:
            QMessageBox.information(
                self, "Compression Complete", "Files compressed successfully."
            )
            self.update_file_list(self.directory_input.text())

    def decompression_finished(self, successful):
        """Handles the completion of the decompression thread."""
        self.progress_dialog.setValue(100)
        self.progress_dialog.close()
        if successful:
            QMessageBox.information(
                self, "Decompression Complete", "Files decompressed successfully."
            )
            self.update_file_list(self.directory_input.text())

    def cancel_compression(self):
        """Cancels the compression operation."""
        self.compress_thread.cancelled = True
        self.progress_dialog.close()

    def cancel_decompression(self):
        """Cancels the decompression operation."""
        self.decompress_thread.cancelled = True
        self.progress_dialog.close()

    def share_file(self):
        """Shares a file over Wi-Fi using qrcp.exe."""
        if not is_connected_to_wifi():
            QMessageBox.warning(
                self,
                "No Wi-Fi Connection",
                "Please connect to a Wi-Fi network to share files.",
            )
            return

        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self, "No File Selected", "Please select a file to share."
            )
            return
        elif len(selected_items) > 1:
            QMessageBox.warning(
                self, "Multiple Files Selected", "Please select only one file to share."
            )
            return

        file_path = os.path.join(self.directory_input.text(), selected_items[0].text())
        qrcp_path = os.path.join("bin", "qrcp.exe")

        try:
            subprocess.Popen([qrcp_path, file_path])
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", f"qrcp.exe not found at '{qrcp_path}'")
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"An error occurred while sharing the file: {e}"
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    file_manager = FileManager()
    file_manager.show()
    sys.exit(app.exec_())
