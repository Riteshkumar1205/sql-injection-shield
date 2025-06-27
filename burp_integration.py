from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
from java.awt import BorderLayout
from javax.swing import (JPanel, JScrollPane, JTable, JTabbedPane, JButton,
                         JLabel, JCheckBox, JOptionPane)
import os
from sql_injection_detector import HybridSQLiDetector

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("Linux SQLi Shield")

        self.home_dir = os.path.expanduser("~")
        self.model_path = os.path.join(self.home_dir, ".sqli_shield/models")

        self.detector = HybridSQLiDetector(self.model_path)
        self.detector.load_models()

        self._panel = JPanel(BorderLayout())
        tabs = JTabbedPane()

        detection_panel = JPanel(BorderLayout())
        self.table_model = TableModel(["URL", "Parameter", "Payload", "Severity"])
        self.result_table = JTable(self.table_model)
        detection_panel.add(JScrollPane(self.result_table), BorderLayout.CENTER)

        btn_panel = JPanel()
        self.export_btn = JButton("Export CSV", actionPerformed=self.export_csv)
        self.clear_btn = JButton("Clear Results", actionPerformed=self.clear_results)
        self.prev_btn = JButton("Prevention Tips", actionPerformed=self.show_prevention)
        btn_panel.add(self.export_btn)
        btn_panel.add(self.clear_btn)
        btn_panel.add(self.prev_btn)
        detection_panel.add(btn_panel, BorderLayout.SOUTH)

        settings_panel = JPanel()
        settings_panel.add(JLabel("AI Detection:"))
        self.ai_toggle = JCheckBox("Enabled", True)
        settings_panel.add(self.ai_toggle)

        tabs.addTab("Detection", detection_panel)
        tabs.addTab("Settings", settings_panel)
        self._panel.add(tabs, BorderLayout.CENTER)

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._stdout.println("[+] Linux SQLi Shield initialized")

    def processHttpMessage(self, tool, isRequest, message):
        if not isRequest or not self.ai_toggle.isSelected():
            return

        request = message.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        url = analyzed.getUrl().toString()

        for param in analyzed.getParameters():
            payload = param.getValue()
            if self.detector.detect(payload):
                self.table_model.addRow([url, param.getName(), payload[:50] + "...", "High"])
                self._report_finding(message, param.getName(), payload)

    def _report_finding(self, message, param, payload):
        markers = [self._callbacks.createMarker(payload, payload)]
        self._callbacks.addScanIssue(
            self._callbacks.applyMarkers(message, None, markers)
        )

    def show_prevention(self, event):
        tips = "\n".join(self.detector.generate_prevention())
        JOptionPane.showMessageDialog(self._panel, tips, "Prevention Tips", JOptionPane.INFORMATION_MESSAGE)

    def export_csv(self, event):
        from javax.swing import JFileChooser
        chooser = JFileChooser()
        chooser.setCurrentDirectory(os.path.expanduser("~"))
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            with open(chooser.getSelectedFile().getPath(), 'w') as f:
                f.write("URL,Parameter,Payload,Severity\n")
                for row in self.table_model.data:
                    f.write(','.join(row) + '\n')

    def clear_results(self, event):
        self.table_model.clear()

    def getTabCaption(self):
        return "SQLi Shield"

    def getUiComponent(self):
        return self._panel

class TableModel:
    def __init__(self, columns):
        self.columns = columns
        self.data = []

    def getRowCount(self):
        return len(self.data)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, col):
        return self.columns[col]

    def getValueAt(self, row, col):
        return self.data[row][col]

    def addRow(self, row):
        self.data.append(row)

    def clear(self):
        self.data = []
