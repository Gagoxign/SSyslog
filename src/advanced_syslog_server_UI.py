"""
Entry point: wires the Model, View, and Controller together (MVC).
"""
import tkinter as tk

from syslog_model import SyslogServerModel
from syslog_view import SyslogView
from syslog_controller import SyslogController

if __name__ == "__main__":
    root = tk.Tk()
    model = SyslogServerModel()
    controller = SyslogController(model)
    view = SyslogView(root, controller)
    controller.set_view(view)
    root.mainloop()
