from PyQt5 import QtCore, QtGui, QtWidgets

class SplashScreen(QtWidgets.QSplashScreen):
    def __init__(self, filepath, flags=0):
        super().__init__(flags=QtCore.Qt.WindowFlags(flags))
        self.movie = QtGui.QMovie(filepath, parent=self)
        self.movie.frameChanged.connect(self.handleFrameChange)
        self.movie.start()

    def updateProgress(self, count=0):
        if count == 0:
            message = 'Starting...'
        elif count > 0:
            message = f'Processing... {count}'
        else:
            message = 'Finished!'
        self.showMessage(
            message, QtCore.Qt.AlignHCenter | QtCore.Qt.AlignBottom, QtCore.Qt.white)

    def handleFrameChange(self):
        pixmap = self.movie.currentPixmap()
        pixmap = pixmap.scaled(200, 100, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
        self.setPixmap(pixmap)
        self.setMask(pixmap.mask())
