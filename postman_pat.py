__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "1.1"

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import ITextEditor
from burp import ITab

# Java imports
from java.lang import Class
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import DefaultTableModel, AbstractTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Color, Font
from java.awt.event import MouseAdapter

import base64
import datetime
import json
import os
import re
import sys
import textwrap
import traceback
from urlparse import urlparse


NAME = "Postman Pat"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            sys.stderr.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stderr)
            raise
    return wrapper


class BurpExtender(IBurpExtender, ITab):

    _callbacks = None
    _helpers = None
    _cols = ('Name', 'Value')
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

        self._collectionChooser = swing.JFileChooser()
        self._collectionChooser.setFileFilter(jsonFilter)

        self._environmentChooser = swing.JFileChooser()
        self._environmentChooser.setFileFilter(jsonFilter)

        self._controlPane = swing.JPanel()
        self._controlPane.setLayout(swing.BoxLayout(self._controlPane, swing.BoxLayout.PAGE_AXIS))
        self._controlPane.setAlignmentX(swing.Box.LEFT_ALIGNMENT)

        box1 = swing.Box.createHorizontalBox()
        box1.setAlignmentX(swing.Box.LEFT_ALIGNMENT)
        box1.add(swing.JButton('Load Collection', actionPerformed=self.loadCollection))  
        self._collectionLabel = swing.JLabel("Choose a collection file")
        box1.add(self._collectionLabel)  
        self._controlPane.add(box1)

        box2 = swing.Box.createHorizontalBox()
        box2.setAlignmentX(swing.Box.LEFT_ALIGNMENT)
        box2.add(swing.JButton('Load Environment', actionPerformed=self.loadEnvironment))  
        self._environmentLabel = swing.JLabel("Choose an environment file")
        box2.add(self._environmentLabel)  
        self._controlPane.add(box2)

        self._controlPane.add(swing.JButton('Create Requests', actionPerformed=self.createRequests))  
        
        logPane = swing.JPanel(BorderLayout())

        box3 = swing.Box.createHorizontalBox()
        box3.add(swing.JButton('Clear Log', actionPerformed=self.clearLog))  
        logPane.add(box3, BorderLayout.NORTH)

        self._log = swing.JTextArea('')
        self._log.setEditable(False)
        self._log.setFont(Font("monospaced", Font.PLAIN, 12))
        logPane.add(swing.JScrollPane(self._log))

        tablePane = swing.JPanel(BorderLayout())
        envLabel = swing.JLabel("Environment Variables")
        envLabel.setBorder(EmptyBorder(5, 5, 5, 5))
        envLabel.setFont(Font(envLabel.getFont().getName(), Font.BOLD, envLabel.getFont().getSize() + 2))
        tablePane.add(envLabel, BorderLayout.NORTH)
       
        self._envTable = swing.JTable(DefaultTableModel([], self._cols))
        self._envTable.getTableHeader().setReorderingAllowed(False)
        tableMenu = swing.JPopupMenu()
        tableMenu.add(swing.JMenuItem("Add New", actionPerformed=self._addEnv))
        tableMenu.add(swing.JMenuItem("Clear All", actionPerformed=self._clearEnv))
        self._deleteMenuItem = swing.JMenuItem("Delete Row", actionPerformed=self._deleteEnv)
        self._deleteMenuItem.setEnabled(False)
        tableMenu.add(self._deleteMenuItem)
        self._envTable.setComponentPopupMenu(tableMenu)
        listener = self._envTableListener(self)
        self._envTable.addMouseListener(listener)
        renderer = self._envTableRenderer()
        self._envTable.setDefaultRenderer(Class.forName("java.lang.Object"), renderer)

        tablePaneMenu = swing.JPopupMenu()
        tablePaneMenu.add(swing.JMenuItem("Add New", actionPerformed=self._addEnv))
        tablePaneMenu.add(swing.JMenuItem("Clear All", actionPerformed=self._clearEnv))
        scrl = swing.JScrollPane(self._envTable)
        scrl.setComponentPopupMenu(tablePaneMenu)
        tablePane.add(scrl)

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

        topInnerPane = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT, self._controlPane, instructionsPane)
        topOuterPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, topInnerPane, tablePane)
        self._panel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, topOuterPane, logPane)

        callbacks.setExtensionName(NAME)
        callbacks.addSuiteTab(self)

    class _envTableRenderer(DefaultTableCellRenderer):

        def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
            if col == 1 and value.startswith("{{") and value.endswith("}}"):
                c.setForeground(Color.RED)
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
        self._envTable.setModel(DefaultTableModel([], self._cols))

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

    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self._panel

    def log(self, msg):
        self._log.append(str(msg) + "\n")

    def info(self, msg):
        self.log("INFO    " + msg.replace("\n", "\n    "))

    def error(self, msg):
        self.log("ERROR   " + msg.replace("\n", "\n    "))

    def ok(self, msg):
        self.log("OK" + " "*6 + msg.replace("\n", "\n    "))

    def warn(self, msg):
        self.log("WARNING " + msg.replace("\n", "\n    "))

    def _getEnvTableIndex(self):
        model = self._envTable.getModel()
        for i in range(model.getRowCount()):
            self._envs[model.getValueAt(i, 0)] = model.getValueAt(i, 1)


    def loadCollection(self, event):
        result = self._collectionChooser.showOpenDialog(self._panel)
        if result == swing.JFileChooser.APPROVE_OPTION:
            file = self._collectionChooser.getSelectedFile().getPath()
            if os.path.isfile(file):
                self._requests = {}
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
                
                except Exception as e:
                    self.error("Unable to parse JSON file: {}".format(e))

            else:
                self.error("File '" + file + "' does not exist")

    def loadEnvironment(self, event):
        result = self._environmentChooser.showOpenDialog(self._panel)
        if result == swing.JFileChooser.APPROVE_OPTION:
            file = self._environmentChooser.getSelectedFile().getPath()
            if os.path.isfile(file):
                with open(file, 'r') as f:
                    obj = json.load(f)

                if obj:
                    if obj.get('values'):
                        for value in obj.get('values'):
                            if value.get('enabled', True):
                                key = value.get('key')
                                val = value.get('value')
                                if key and val:
                                    # self._envTable.getModel().addRow([key, str(val)])
                                    self._addOrUpdateEnv(key, str(val))
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

        # self.log(self._envs)

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
                # if env.group(1) not in self._envs:
                    self._envTable.getModel().addRow([env.group(1), env.group(0)])
                    # self._envs[env.group(1)] = env.group(0)

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
        for name, obj in self._requests.items():

            o_url = urlparse(self._replace_envs(obj.get('url')))
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
            print(host, port, https, name)
            try:
                self._callbacks.sendToRepeater(host, port, https, full_request, name)
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
                    
                    indent = 48
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
                        self._findEnvInString(val)

                    # if len(name) > 25:
                    #     name = name[:25] + "..."

                    if not name:
                        name = "Undefined"

                    if name in self._requests:
                        # print("name is not unique")
                        cnt = 1
                        base_name = name
                        while name in self._requests:
                            name = "{} ({})".format(base_name, cnt)
                            cnt += 1
                        print("Renamed '{}' to '{}'".format(base_name, name))

                    self._requests[name] = {
                        'method': req.get('method'),
                        'url': url,
                        'body': body,
                        'headers': headers
                    }

                    self.log('')

            # recur
            if item.get('item'):
                if level:
                    self.log("    {}> {}:".format('  '*(level-1), item.get('name')))
                else:
                    self.log("    {}:".format(item.get('name')))

                self._parse_item(item, level+1)

