"""
Parse Postman collection and environment files and generate Repeater tabs

History:
1.0.0: First version
1.1.0: Handled requests with the same name
1.2.0: Added list of requests to a table and made them selectable and allowed name changes. Save the last file path. Logs are coloured.
1.3.0: Fixed issue with checking body and added HTTP Method to table
1.4.0: Added "Select all/none/invert" buttons for Luca
"""

__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "1.4.0"

from burp import IBurpExtender
from burp import ITab

import base64
import datetime
import json
import os
import re
import sys
import traceback
from urlparse import urlparse

# Java imports
from java.awt import BorderLayout, FlowLayout, Color, Font
from java.awt.event import MouseAdapter
from java.io import File
from java.lang import Class
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from javax.swing.text import  SimpleAttributeSet, StyleConstants


NAME = "Postman Pat"

SETTING_LAST_PATH = "LAST_PATH"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            self._callbacks.printError("\n\n*** PYTHON EXCEPTION")
            self._callbacks.printError(traceback.format_exc(e))
            self._callbacks.printError("*** END\n")
    return wrapper


class BurpExtender(IBurpExtender, ITab):

    _callbacks = None
    _helpers = None
    _envCols = ('Name', 'Value')
    _reqCols = ('Generate?', 'name', 'Method')
    _requests = {}
    _hasScript = False

    def __init__(self):
        self._collectionFile = None
        self._envs = {}

    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        jsonFilter = FileNameExtensionFilter("JSON files", ['json'])

        basePath = self._callbacks.loadExtensionSetting(SETTING_LAST_PATH)
        # print("got last path {}".format(basePath))

        self._collectionChooser = swing.JFileChooser(basePath)
        self._collectionChooser.setFileFilter(jsonFilter)

        self._environmentChooser = swing.JFileChooser(basePath)
        self._environmentChooser.setFileFilter(jsonFilter)

        # ### Top "buttons" pane
        controlPane = swing.JPanel()
        controlPane.setBorder(EmptyBorder(10, 20, 0, 10))
        controlPane.setLayout(swing.BoxLayout(controlPane, swing.BoxLayout.PAGE_AXIS))
        controlPane.setAlignmentX(swing.Box.LEFT_ALIGNMENT)

        box1 = swing.Box.createHorizontalBox()
        box1.setAlignmentX(swing.Box.LEFT_ALIGNMENT)
        box1.add(swing.JButton('Load Collection', actionPerformed=self.loadCollection))  
        self._collectionLabel = swing.JLabel("Choose a collection file")
        box1.add(self._collectionLabel)  
        controlPane.add(box1)

        box2 = swing.Box.createHorizontalBox()
        box2.setAlignmentX(swing.Box.LEFT_ALIGNMENT)
        box2.add(swing.JButton('Load Environment', actionPerformed=self.loadEnvironment))  
        self._environmentLabel = swing.JLabel("Choose an environment file")
        box2.add(self._environmentLabel)  
        controlPane.add(box2)

        # ### end Top "controls" pane
        
        # ### instructions
        instructionsPane = swing.JPanel(BorderLayout())
        instructions = swing.JLabel()
        instructions.setText("""<html><body>
<h3>Usage:</h3>
<ol>
<li>Select the Collection Postman JSON file. This should extract all discovered environment variables.</li>
<li>(Optional) Select an Environment Postman JSON file. This can be the same as the Collection file.</li>
<li>Set environment variables below.</li>
<li>Choose 'Create Requests' to create Repeater tabs.</li>
</ol>
</body></html>""")
        instructionsPane.add(instructions, BorderLayout.NORTH)
        # ### end instructions

        # ### environment variables
        envTablePane = swing.JPanel(BorderLayout())
        envLabel = swing.JLabel("Environment Variables")
        envLabel.setBorder(EmptyBorder(5, 5, 5, 5))
        envLabel.setFont(Font(envLabel.getFont().getName(), Font.BOLD, envLabel.getFont().getSize() + 2))
        envTablePane.add(envLabel, BorderLayout.NORTH)
       
        self._envTable = swing.JTable(DefaultTableModel([], self._envCols))
        self._envTable.setAutoCreateRowSorter(True);
        self._envTable.getTableHeader().setReorderingAllowed(False)
        tableMenu = swing.JPopupMenu()
        tableMenu.add(swing.JMenuItem("Add New", actionPerformed=self._addEnv))
        tableMenu.add(swing.JMenuItem("Clear All", actionPerformed=self._clearEnv))
        deleteMenuItem = swing.JMenuItem("Delete Row", actionPerformed=self._deleteEnv)
        deleteMenuItem.setEnabled(False)
        tableMenu.add(deleteMenuItem)
        self._envTable.setComponentPopupMenu(tableMenu)
        listener = self._envTableListener(self)
        self._envTable.addMouseListener(listener)
        renderer = self._envTableRenderer()
        self._envTable.setDefaultRenderer(Class.forName('java.lang.Object'), renderer)

        envTablePaneMenu = swing.JPopupMenu()
        envTablePaneMenu.add(swing.JMenuItem("Add New", actionPerformed=self._addEnv))
        envTablePaneMenu.add(swing.JMenuItem("Clear All", actionPerformed=self._clearEnv))
        scrl = swing.JScrollPane(self._envTable)
        scrl.setComponentPopupMenu(envTablePaneMenu)
        envTablePane.add(scrl)
        # ### end environment variables

        # ### requests
        reqTablePane = swing.JPanel(BorderLayout())
        reqLabel = swing.JLabel("Requests")
        reqLabel.setBorder(EmptyBorder(5, 5, 5, 5))
        reqLabel.setFont(envLabel.getFont())
        reqTablePane.add(reqLabel, BorderLayout.NORTH)
       
        self._reqTable = self._reqTableClass(DefaultTableModel([], self._reqCols))
        self._reqTable.setAutoCreateRowSorter(True);
        self._reqTable.getTableHeader().setReorderingAllowed(False)
        self._reqTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_LAST_COLUMN)
        self._reqTable.getTableHeader().setReorderingAllowed(False)
        self._reqTable.getColumnModel().getColumn(0).setMaxWidth(150)
        self._reqTable.getColumnModel().getColumn(0).setMinWidth(150)
        self._reqTable.getColumnModel().getColumn(2).setMaxWidth(150)
        self._reqTable.getColumnModel().getColumn(2).setMinWidth(150)
        scrl2 = swing.JScrollPane(self._reqTable)
        reqTablePane.add(scrl2)
        # ### end requests

        # ### Logs
        logPane = swing.JPanel(BorderLayout())

        buttonBox = swing.JPanel(FlowLayout(FlowLayout.LEFT, 20, 0))
        requestButtonBox = swing.Box.createHorizontalBox()
        self._selectButtons = [
            swing.JButton('Select All', actionPerformed=self.selectAll),
            swing.JButton('Select None', actionPerformed=self.selectNone),
            swing.JButton('Invert Selection', actionPerformed=self.selectInvert)
        ]
        for btn in self._selectButtons:
            requestButtonBox.add(btn)  
            btn.setEnabled(False)

        buttonBox.add(requestButtonBox)

        self._createRequestsButton = swing.JButton('Create Requests', actionPerformed=self.createRequests)
        self._createRequestsButton.setEnabled(False)
        requestButtonBox.add(self._createRequestsButton)

        buttonBox.add(self._createRequestsButton)

        self._logButton = swing.JButton('Clear Log', actionPerformed=self.clearLog)
        self._logButton.setEnabled(False)
        buttonBox.add(self._logButton)

        logPane.add(buttonBox, BorderLayout.NORTH)

        self._log = swing.JTextPane()
        self._log.setEditable(False)
        self._log.setFont(Font("monospaced", Font.PLAIN, 12))
        logPane.add(swing.JScrollPane(self._log))
        # ### end Logs

        # ### add panels
        self._topControlsPane = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT, controlPane, instructionsPane)
        p1 = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, self._topControlsPane, envTablePane)
        p2 = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, p1, reqTablePane)
        p2.setResizeWeight(0.5)
        self._panel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, p2, logPane)
        self._panel.setResizeWeight(0.6)
        # ### end add panels

        callbacks.setExtensionName(NAME)
        callbacks.addSuiteTab(self)

    class _reqTableClass(swing.JTable):

        def getColumnClass(self, col):
            if col == 0:
                return Class.forName('java.lang.Boolean')
            else:
                return Class.forName('java.lang.String')
            

    class _envTableRenderer(DefaultTableCellRenderer):

        def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
            if col == 1 and value.startswith("{{") and value.endswith("}}"):
                c.setForeground(Color.RED)
            elif col == 1 and value.startswith("** ") and value.endswith(" **"):
                c.setForeground(Color.ORANGE)
            else:
                c.setForeground(table.getForeground())
            return self

    class _envTableListener(MouseAdapter):

        def __init__(self, parent):
            self._parent = parent

        def mouseReleased(self, event):
            table = self._parent._envTable
            r = table.rowAtPoint(event.getPoint())
            if 0 <= r < table.getRowCount():
                table.setRowSelectionInterval(r, r)
                self._parent._deleteMenuItem.setEnabled(True)
            else:
                table.clearSelection()
                self._parent._deleteMenuItem.setEnabled(False)

    def _clearEnv(self, event):
        self._envTable.setModel(DefaultTableModel([], self._envCols))

    def _deleteEnv(self, event):
        if len(self._envTable.getSelectedRows()) != 1:
            swing.JOptionPane.showMessageDialog(None, "Select a single row to delete")
            return
        self._envTable.getModel().removeRow(self._envTable.getSelectedRow())

    def _addEnv(self, event):
        n = datetime.datetime.now()
        self._envTable.getModel().addRow([str(n.date()), str(n.time())])

    def _dictToTable(self, obj):
        return [[k, v] for k,v in obj.items()]

    def clearLog(self, event):
        self._log.setText('')
        self._logButton.setEnabled(False)

    def selectAll(self, event):
        model = self._reqTable.getModel()
        for row in range(model.getRowCount()):
            model.setValueAt(True, row, 0)

    def selectNone(self, event):
        model = self._reqTable.getModel()
        for row in range(model.getRowCount()):
            model.setValueAt(False, row, 0)

    def selectInvert(self, event):
        model = self._reqTable.getModel()
        for row in range(model.getRowCount()):
            model.setValueAt(not model.getValueAt(row, 0), row, 0)

    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self._panel

    def log(self, msg, color=None, bold=False, end='\n'):
        msg = str(msg).replace("\n", "\n    ") + end
        doc = self._log.getStyledDocument();
        aset = SimpleAttributeSet()
        if color:
            StyleConstants.setForeground(aset, color)
        if bold:
            StyleConstants.setBold(aset, True);

        doc.insertString(self._log.getDocument().getLength(), msg, aset)
        self._logButton.setEnabled(True)

    def info(self, msg):
        self.log("[*] ", bold=True, end='')
        self.log(msg)

    def error(self, msg):
        self.log("[!] ", color=Color.RED, bold=True, end='')
        self.log(msg)

    def ok(self, msg):
        self.log("[+] ", Color.GREEN, bold=True, end='')
        self.log(msg)

    def warn(self, msg):
        self.log("[~] ", Color.ORANGE, bold=True, end='')
        self.log(msg)

    def _getEnvTableIndex(self):
        model = self._envTable.getModel()
        for i in range(model.getRowCount()):
            self._envs[model.getValueAt(i, 0)] = model.getValueAt(i, 1)


    def loadCollection(self, event):
        result = self._collectionChooser.showOpenDialog(self._panel)
        if result == swing.JFileChooser.APPROVE_OPTION:
            file = self._collectionChooser.getSelectedFile().getPath()
            if os.path.isfile(file):
                self._callbacks.saveExtensionSetting(SETTING_LAST_PATH, file)
                self._collectionChooser.setCurrentDirectory(File(file))
                self._requests = []
                self._requestNames = []
                self._reqTable.getModel().setRowCount(0)
                self.info("Processing " + file)
                self._collectionFile = file
                self._collectionLabel.setText("Using " + file)

                try:
                    with open(self._collectionFile, 'r') as f:
                        obj = json.load(f)

                    if obj:
                        self.log("""
Name/Group                          Method  Details
==========                          ======  =======""")
                        self._parse_item(obj)

                        if self._hasScript:
                            self.warn("Collection uses scripts - check these manually.")

                        for btn in self._selectButtons:
                            btn.setEnabled(True)
                        self._createRequestsButton.setEnabled(True)
                        self._topControlsPane.resetToPreferredSizes()
                
                except Exception as e:
                    self.error("Unable to parse JSON file. Did you try and load an environment file?")
                    print(traceback.format_exc(e))

            else:
                self.error("File '" + file + "' does not exist")

    def loadEnvironment(self, event):
        result = self._environmentChooser.showOpenDialog(self._panel)
        if result == swing.JFileChooser.APPROVE_OPTION:
            file = self._environmentChooser.getSelectedFile().getPath()
            if os.path.isfile(file):
                self._callbacks.saveExtensionSetting(SETTING_LAST_PATH, file)
                self._collectionChooser.setCurrentDirectory(File(file))
                with open(file, 'r') as f:
                    obj = json.load(f)

                if obj:
                    if obj.get('values'):
                        for value in obj.get('values'):
                            if value.get('enabled', True):
                                key = value.get('key')
                                val = value.get('value')
                                if key and val:
                                    try:
                                        self._addOrUpdateEnv(key, str(val))
                                    except UnicodeError:
                                        self._addOrUpdateEnv(key, "** {} **".format(val.encode('utf-8').strip()))
                                        self.warn(
                                            "Environment variable value for '{}' contains unparseable unicode characters\n"
                                            "This entry is highlighted in '** ORANGE **'".format(key)
                                        )

                                    except Exception as e:
                                        self._addOrUpdateEnv(key, "{{UNABLE TO PARSE}}")
                                        self.error("Unable to parse environment variable value for '{}'".format(key))
                                        print(traceback.format_exc(e))

                        self._environmentLabel.setText("Using " + file)
                        self._topControlsPane.resetToPreferredSizes()

                else:
                    self.error("Unable to parse Environment file")
            else:
                self.error("No valid file specified")

    def _replace_envs(self, in_str):
        if re.search(r"{{(\w+)}}", in_str):
            for env in re.finditer(r"{{(\w+)}}", in_str):
                new = self._envs.get(env.group(1))
                if new:
                    in_str = in_str.replace("{{{{{}}}}}".format(env.group(1)), new)

        return in_str


    def _rebuildEnvs(self):
        self._envs.clear()
        model = self._envTable.getModel()
        for i in range(model.getRowCount()):
            self._envs[model.getValueAt(i, 0)] = model.getValueAt(i, 1)

    def _findEnvInString(self, in_str):
        """make sure to call _rebuildEnvs() at least once first"""
        if re.search(r"{{(\w+)}}", in_str):
            for env in re.finditer(r"{{(\w+)}}", in_str):
                model = self._envTable.getModel()
                hasEnv = False
                for i in range(model.getRowCount()):
                    key = model.getValueAt(i, 0).lower()
                    if key == env.group(1).lower():
                        hasEnv = True
                        continue

                if not hasEnv:
                    self._envTable.getModel().addRow([env.group(1), env.group(0)])

    def _addOrUpdateEnv(self, env, value):
        model = self._envTable.getModel()
        hasEnv = False
        for i in range(model.getRowCount()):
            key = model.getValueAt(i, 0).lower()
            if key == env.lower():
                model.setValueAt(value, i, 1)
                return
        model.addRow([env, value])
    
    def createRequests(self, event):
        self._rebuildEnvs()
        model = self._reqTable.getModel()
        for row in range(model.getRowCount()):
            if bool(model.getValueAt(row, 0)):

                name = model.getValueAt(row, 1)
                obj = self._requests[row]

                url = self._replace_envs(obj.get('url'))
                o_url = urlparse(url)

                if not o_url.scheme or not o_url.netloc:
                    self.error("Skipping request with invalid URL '{}'. Did you set all environment variables?".format(url))
                    continue

                https = o_url.scheme.lower() == "https"
                netloc = o_url.netloc.split(':')
                host = netloc[0]
                try:
                    port = int(host[1])
                except (ValueError, IndexError):
                    port = 443 if https else 80

                path = o_url.path
                if o_url.query:
                    path = path + "?" + o_url.query

                new_headers = [
                    "Host: " + host,
                    "User-Agent: Burp Repeater"
                ]

                for k, v in obj.get('headers').items():
                    new_headers.append("{}: {}".format(k, self._replace_envs(v)))

                full_request = (
                    obj.get('method') + " " + path + " HTTP/1.1\n" + 
                    "\n".join(new_headers) +
                    "\n\n" + 
                    self._replace_envs(obj.get('body'))
                )
                # print(host, port, https, name)
                try:
                    self._callbacks.sendToRepeater(host, port, https, full_request, name)
                    self.ok("Request '{}' created".format(name))
                except Exception as e:
                    self.error("Unable to create Repeater tab - check all environment variables?")
                    self.error(e)

    def _parse_item(self, node, level=0):
        for item in node.get('item'):
            req = item.get('request')
            name = item.get('name')
            if req:

                if req.get('method', "").upper() == "OPTIONS":
                    # ignore OTIONS requests
                    continue

                url = req.get('url')
                if type(url) == dict:
                    url = url.get('raw')

                if not url:
                    self.warn("Endpoint '{}' has no URL".format(name))
                
                else:

                    self._findEnvInString(url)

                    w = 34 - (level*2)
                    self.log("    {}- {}  {:<6}  {}".format('  '*(level-1), (name + ' '*w)[:w], req.get('method'), url))

                    headers = {}

                    event = item.get('event')
                    if event:
                        if type(event) is list:
                            for o in event:
                                if o.get('script'):
                                    self._hasScript = True
                                    break
                        else:
                            if event.get('script'):
                                self._hasScript = True

                    indent = 48

                    auth = req.get('auth')
                    if auth:
                        typ = auth.get('type', '')
                        val = None
                        o = auth.get(typ, {})
                        try:
                            if typ.lower() == "bearer":
                                if type(o) is list:
                                    o = o[0]
                                val = o.get('token', o.get('value', ''))
                                self._findEnvInString(val)

                            elif typ.lower() == "basic":
                                val = base64.b64encode("{}:{}".format(
                                    auth.get(typ, {}).get('username'),
                                    auth.get(typ, {}).get('password')
                                ))
                                self._findEnvInString(auth.get(typ, {}).get('username'))
                                self._findEnvInString(auth.get(typ, {}).get('password'))
                        except Exception as e:
                            print(e)
                            val = 'ERROR'

                        if val:
                            self.log("{}Authorization: {} {}".format(' '*indent, typ, val))
                            headers['Authorization'] = "{} {}".format(
                                typ, 
                                val
                            )
                    
                    if req.get('header'):
                        self.log("{}Headers:".format(' '*indent))
                        for header in req.get('header'):
                            key = header.get('key')
                            val = header.get('value')
                            if key and val:
                                self.log("{}{} = {}".format(' '*(indent+2), key, val))
                                headers[header.get('key')] = val
                                self._findEnvInString(val)

                    body = ''
                    if req.get('body'):
                        self.log("{}Body:".format(' '*indent))
                        # TODO what if it's not raw?
                        body = req.get('body').get('raw', '')
                        self.log(' '*(indent+2) + body.replace("\n", "\n" + ' '*(indent+2)) )
                        self._findEnvInString(body)

                    if not name:
                        name = "Undefined"

                    if name in self._requestNames:
                        cnt = 1
                        base_name = name
                        while name in self._requestNames:
                            name = "{} ({})".format(base_name, cnt)
                            cnt += 1
                        print("Renamed '{}' to '{}'".format(base_name, name))

                    self._requestNames.append(name)
                    self._requests.append({
                        'method': req.get('method'),
                        'url': url,
                        'body': body,
                        'headers': headers
                    })
                    self._reqTable.getModel().addRow([True, name, req.get('method').upper()])
                    self.log('')

            # recur
            if item.get('item'):
                if level:
                    self.log("    {}> {}:".format('  '*(level-1), item.get('name')))
                else:
                    self.log("    {}:".format(item.get('name')))

                self._parse_item(item, level+1)

