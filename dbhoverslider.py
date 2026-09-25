from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import QApplication, QSlider, QStyle, QStyleOptionSlider, QVBoxLayout, QWidget, QLabel, QFrame
from PySide6.QtCore import  QRect
from PySide6.QtGui import   QFont

class DbHoverSlider(QSlider):
    
    handleHovered = Signal(bool)
    isOverHandle = False
    
    #offset = 112
    #factor = 1.34
    
    offset = 112
    factor = 1.34
    length = 62
    
    def __init__(self, orientation=Qt.Orientation.Horizontal, parent=None):
        super().__init__(orientation, parent)
        # Mouse-Tracking aktivieren, damit mouseMoveEvent ohne Klick triggert
        self.setMouseTracking(True)
        self._is_hovered = False
        
        #self.slider.handleHovered.connect(self.on_handle_hover)
 
        self.handleHovered.connect(self.on_handle_hover)
        self.valueChanged.connect(self.handleslidermoved)
        self.sliderReleased.connect(self.sliderreleaed)
        self.sliderPressed.connect(self.sliderpressed)
        
        self.label = QLabel(self)
        
         
        #self.setMinimum(-90)
        #self.setMaximum(90)
        
        
        

    def mouseMoveEvent(self, event):
        # Bereite die Style-Optionen vor, um die aktuelle Geometrie des Sliders zu ermitteln
        opt = QStyleOptionSlider()
        self.initStyleOption(opt)
        
        # Prüfen, welches Unterelement (SubControl) sich unter der Mausposition befindet
        sub_control = self.style().hitTestComplexControl(
            QStyle.ComplexControl.CC_Slider, 
            opt, 
            event.position().toPoint(), 
            self
        )
        
        # Befindet sich die Maus über dem Handle (Knopf)?
        is_over_handle = (sub_control == QStyle.SubControl.SC_SliderHandle)
        
        self.isOverHandle = is_over_handle
                    
        # Signal nur senden, wenn sich der Zustand geändert hat (Performance-Schonung)
        if is_over_handle != self._is_hovered:
            self._is_hovered = is_over_handle
            self.handleHovered.emit(is_over_handle)

            
        # Standardverhalten des Sliders beibehalten
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        # Wenn die Maus das Widget komplett verlässt, Zustand zurücksetzen
        if self._is_hovered:
            self._is_hovered = False
            self.handleHovered.emit(False)
        super().leaveEvent(event)

    #####################
    
    def setup(self):
        #self.label.setEnabled(0)
        self.label.setHidden(1)
        #self.label.setGeometry(QRect(30, 860, 75, 41))
        self.label.setGeometry(QRect(30, 860, self.length, 35))
        self.label.setAutoFillBackground(False)
        self.label.setStyleSheet(u"background-color: rgb(0, 53, 0);" u"color: rgb(255, 255, 255);"u"border-radius:10;")
        self.label.setFrameShape(QFrame.Shape.StyledPanel)
        self.label.setFrameShadow(QFrame.Shadow.Sunken)
        self.label.setLineWidth(3)
        self.label.setMidLineWidth(3)
        font1 = QFont()
        font1.setPointSize(10)
        font1.setBold(True)
        self.label.setFont(font1)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
    
    def print_string(self):
        
        if self.value() > 0:
            prefix = "+"
        else:
            prefix = ""
        if self.value() == 0:    
            prefix = " "
        
        string =  prefix+ str(self.value()/10) + "dB"
    
        return string
    
    def sliderpressed(self):
        self.label.setText(self.print_string())
        self.label.setHidden(0)
       
    def sliderreleaed(self):
        self.label.setText(self.print_string())
        #print(self.ui.verticalSlider_hovertest.isOverHandle)
        if self.isOverHandle == True:
            self.label.setHidden(0)
        else:
            self.label.setHidden(1)
    
    def handleslidermoved(self):
        self.label.setText(self.print_string())
        self.label.setHidden(0)
        #self.ui.label_s2.move(self.ui.verticalSlider_hovertest.x() + 20, self.ui.verticalSlider_hovertest.y()+108  - 1.34*self.ui.verticalSlider_hovertest.value())
        self.label.move(self.x() + 25, self.y() + self.offset  - self.factor * self.value())
        
    def on_handle_hover(self, hovered):
        self.handleslidermoved()
        if hovered:
            self.label.setText(self.print_string())
            self.label.setHidden(0)
        else:
            self.label.setText(self.print_string())
            if self.isSliderDown() == False:
                self.label.setHidden(1)



