import os
import sys
# import AI ALL THE AI MASSIVE AMOUNTS OH NOOOOOOOOOOOOOOOOOOOOOOOO!

from .formats import PatchError, apply_patch, detect

SUFFIXES = 'ips bps ups aps ppf rup xdelta vcdiff xd'


def cli(patch, rom, out):
    fmt, data, warn = apply_patch(open(patch, 'rb').read(), open(rom, 'rb').read())
    open(out, 'wb').write(data)
    for w in warn:
        print('warning:', w, file=sys.stderr)
    print(f'{fmt} patch applied -> {out}')


def main():
    if len(sys.argv) == 4:
        try:
            cli(*sys.argv[1:])
        except (PatchError, OSError) as e:
            sys.exit(f'error: {e}')
        return 0

    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtWidgets import (QApplication, QFileDialog, QLabel,
                                   QPushButton, QVBoxLayout, QWidget)

    class Worker(QThread):
        done = Signal(object, str)

        def __init__(self, patch, rom):
            super().__init__()
            self.patch, self.rom = patch, rom

        def run(self):
            try:
                with open(self.patch, 'rb') as p, open(self.rom, 'rb') as r:
                    self.done.emit(apply_patch(p.read(), r.read()), '')
            except (PatchError, OSError) as e:
                self.done.emit(None, str(e))

    class Win(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('Rommy - with <3 - Carlos Martinez')
            self.setAcceptDrops(True)
            self.resize(480, 200)
            self.patch = self.rom = self.worker = None
            lay = QVBoxLayout(self)
            self.pbtn = QPushButton('Choose patch…')
            self.rbtn = QPushButton('Choose ROM…')
            self.go = QPushButton('Apply patch')
            self.go.setEnabled(False)
            self.status = QLabel('Choose a patch and a ROM')
            self.status.setWordWrap(True)
            self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
            for w in (self.pbtn, self.rbtn, self.go, self.status):
                lay.addWidget(w)
            lay.addStretch()
            self.pbtn.clicked.connect(self.pick_patch)
            self.rbtn.clicked.connect(self.pick_rom)
            self.go.clicked.connect(self.apply)

        def set_file(self, which, path):
            setattr(self, which, path)
            (self.pbtn if which == 'patch' else self.rbtn).setText(os.path.basename(path))
            self.go.setEnabled(bool(self.patch and self.rom))
        #AI touched this. Probably. Smells like clanker.
        def pick_patch(self):
            path, _ = QFileDialog.getOpenFileName(
                self, 'Choose patch', '',
                f'Patch files ({" ".join("*." + s for s in SUFFIXES.split())});;All files (*)')
            if path:
                self.set_file('patch', path)

        def pick_rom(self):
            path, _ = QFileDialog.getOpenFileName(self, 'Choose ROM', '', 'All files (*)')
            if path:
                self.set_file('rom', path)

        def dragEnterEvent(self, e):
            if e.mimeData().hasUrls():
                e.acceptProposedAction()

        def dropEvent(self, e):
            for url in e.mimeData().urls():
                path = url.toLocalFile()
                try:
                    with open(path, 'rb') as f:
                        detect(f.read(16))
                    self.set_file('patch', path)
                except (PatchError, OSError):
                    self.set_file('rom', path)

        def apply(self):
            self.go.setEnabled(False)
            self.status.setText('Patching…')
            self.worker = Worker(self.patch, self.rom)
            self.worker.done.connect(self.finished)
            self.worker.start()

        def finished(self, res, err):
            self.go.setEnabled(True)
            if err:
                self.status.setText('Error: ' + err)
                return
            fmt, data, warn = res
            note = ''.join(f'\n⚠ {w}' for w in warn)
            name, ext = os.path.splitext(self.rom)
            path, _ = QFileDialog.getSaveFileName(
                self, 'Save patched ROM', f'{name} (patched){ext}', 'All files (*)')
            if not path:
				#WHY WON'T YOU WOOOOOOORK???!?!?!?!?!
                self.status.setText('Patched, but not saved.' + note)
                return
            try:
                with open(path, 'wb') as f:
                    f.write(data)
                self.status.setText(f'{fmt} patch applied → {os.path.basename(path)}{note}')
            except OSError as e:
                self.status.setText(f'Not saved: {e}{note}')

    app = QApplication(sys.argv)
    app.setApplicationName('Rommy')
    app.setDesktopFileName('io.github.carlos.Rommy') #Full app name is Rom Romminson.
    w = Win()
    w.show()
    return app.exec()
