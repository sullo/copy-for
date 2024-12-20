# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import JPanel, JLabel, JTextField, JButton, BoxLayout, JMenuItem, JScrollPane, JEditorPane, JTextArea, Box
from java.awt import GridBagConstraints, GridBagLayout, Insets, Dimension, Color, BorderLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.io import PrintWriter
from java.lang import Integer
from javax.swing.text.html import HTMLEditorKit
from javax.swing.event import DocumentListener
from javax.swing.text.html import HTMLEditorKit
import json
import re

help = """
Burp extension: Copy For
Copyright (c) 2024 Chris Sullo, All Rights Reserved.
https://github.com/sullo/copy-for
License: GNU Affero General Public License v3.0
"""

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    print(help)

    # Modify defaults here if desired
    default_flag_values = {
        "jwt_tool": "python3 jwt_tool.py -t '{url}' {headers} -M at",
        "nikto": "nikto.pl -F htm -S . -o . -h '{url}'",
        "nmap": "nmap {hostname} -oA '{filename}' -Pn -p- -sCV",
        "nuclei": "nuclei -u '{baseurl}' -me '{directory}' -H 'User-Agent: {ua}'",
        "ffuf": "ffuf -u '{baseurl}/FUZZ' {headers}",
        "curl": "curl -X '{method}' {headers} '{url}'",
        "wget": "wget '{url}' {headers}",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
    }

    def setup_ui(self):
        self.panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(1, 1, 0, 1)  # Minimize padding
        constraints.anchor = GridBagConstraints.WEST

        # Explanation text
        explanation_text = """Variable substitution:
        {baseurl} - Base URL (protocol and domain)
        {body} - Request body (if present)
        {directory} - Safe directory name based on base URL
        {url} - Full URL
        {filename} - Safe filename based on hostname
        {headers} - Request headers
        {hostname} - Hostname
        {method} - HTTP method
        {port} - Port number
        {uaff} - FireFox User Agent
        """

        explanation_area = JTextArea(explanation_text)
        explanation_area.setEditable(False)
        explanation_area.setLineWrap(True)
        explanation_area.setWrapStyleWord(True)
        explanation_area.setPreferredSize(Dimension(1000, 220))

        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        constraints.weightx = 1.0
        constraints.weighty = 0.0
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(1, 1, 0, 1)  # Top, Left, Bottom, Right
        self.panel.add(explanation_area, constraints)

        # Flag fields for each tool
        self.flag_fields = {}
        for i, (tool, flags) in enumerate(sorted(self.flag_values.items())):
            constraints.gridy = i + 1  # Start immediately after the explanation area
            constraints.gridx = 0
            constraints.gridwidth = 1
            constraints.weightx = 0.0
            constraints.weighty = 0.0
            constraints.fill = GridBagConstraints.NONE
            constraints.insets = Insets(1, 1, 1, 1)  # Reset insets for other components
            self.panel.add(JLabel("{} Flags:".format(tool.capitalize())), constraints)

            constraints.gridx = 1
            constraints.weightx = 1.0
            constraints.fill = GridBagConstraints.HORIZONTAL
            field = JTextField(flags, 20)
            field.setPreferredSize(Dimension(250, 20))
            self.flag_fields[tool] = field
            self.panel.add(field, constraints)

        # Dynamic command panel
        self.dynamic_command_panel = JPanel()
        self.dynamic_command_panel.setLayout(BoxLayout(self.dynamic_command_panel, BoxLayout.Y_AXIS))
        self.dynamic_fields = []

        # Add 'Add Command' button
        add_command_button = JButton("Add Command", actionPerformed=self.add_dynamic_command)
        constraints.gridy += 1
        constraints.gridx = 0
        constraints.gridwidth = 2
        constraints.weightx = 0.0
        constraints.fill = GridBagConstraints.NONE
        self.panel.add(add_command_button, constraints)

        # Add 'Save' button
        save_button = JButton("Save", actionPerformed=self.save_flags)
        constraints.gridy += 1
        constraints.gridx = 0
        constraints.gridwidth = 2
        constraints.weightx = 0.0
        constraints.fill = GridBagConstraints.NONE
        self.panel.add(save_button, constraints)

        # Add dynamic command scroll pane
        constraints.gridy += 1  # Move below all flag fields
        constraints.gridx = 0
        constraints.gridwidth = 2  # Span across both columns
        constraints.weightx = 1.0
        constraints.weighty = 1.0  # Allow this component to take remaining vertical space
        constraints.fill = GridBagConstraints.BOTH
        self.panel.add(JScrollPane(self.dynamic_command_panel), constraints)

        # Add scroll pane to main panel
        self.scroll_pane = JScrollPane(self.panel)
        self.panel.revalidate()
        self.panel.repaint()

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("Copy For...")
        callbacks.registerExtensionStateListener(self)
        self.flag_values = self.default_flag_values.copy()
        self.dynamic_commands = []
        self.setup_ui()
        self.loadSettings()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        self.copy_options = sorted([
            {"name": "Copy for curl", "formatter": self.format_curl},
            {"name": "Copy for ffuf", "formatter": self.format},
            {"name": "Copy for jwt_tool.py", "formatter": self.format_jwt_tool},
            {"name": "Copy for Nikto", "formatter": self.format},
            {"name": "Copy for Nmap", "formatter": self.format},
            {"name": "Copy for Nuclei", "formatter": self.format},
            {"name": "Copy for wget", "formatter": self.format}
        ], key=lambda x: x["name"])

    # Hanmdler to remove arbitrary menu items
    def remove_dynamic_command(self, row):
        self.dynamic_command_panel.remove(row)
        self.dynamic_fields = [(label, command) for label, command in self.dynamic_fields 
                            if label not in row.getComponents() and command not in row.getComponents()]
        self.dynamic_command_panel.revalidate()
        self.dynamic_command_panel.repaint()
        self.save_dynamic_commands(None)  # Save changes immediately after deletion

    # Store values
    def save_flags(self, event):
        for tool, field in self.flag_fields.items():
            self.flag_values[tool] = field.getText()
        self.saveSettings()
        self.save_dynamic_commands(event)
        self.changes_made = False

    # Populate the menu
    def createMenuItems(self, invocation):
        menu_list = []
        for option in self.copy_options:
            menu_item = JMenuItem(option["name"])
            menu_item.addActionListener(lambda event, opt=option: self.copy_command(invocation, opt))
            menu_list.append(menu_item)
        for dynamic in self.dynamic_commands:
            menu_item = JMenuItem(dynamic["label"])
            menu_item.addActionListener(lambda event, dyn=dynamic: self.copy_dynamic_command(invocation, dyn))
            menu_list.append(menu_item)
        return menu_list if menu_list else None

    # Copy to clipboard
    def copy_dynamic_command(self, invocation, dynamic):
        # Get the selected HTTP request
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages or len(selected_messages) == 0:
            return

        http_traffic = selected_messages[0]
        request_info = self._helpers.analyzeRequest(http_traffic)
        url = request_info.getUrl()
        headers = request_info.getHeaders()
        method = request_info.getMethod()
        body_offset = request_info.getBodyOffset()
        request_bytes = http_traffic.getRequest()
        body = None
        if body_offset < len(request_bytes):
            body = self._helpers.bytesToString(request_bytes[body_offset:])

        # Generate the command dynamically
        variables = self.get_common_variables(url, headers, method, body)
        command = self.format_command(dynamic["command"], variables)

        # Copy the command to the clipboard
        string_selection = StringSelection(command)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(string_selection, None)
        if not selected_messages or len(selected_messages) == 0:
            self._stdout.println("Error: No HTTP messages selected.")
            return
        else:
            self._stdout.println("Failed to generate dynamic command.")

    def add_dynamic_command(self, event=None):
        row = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(2, 2, 2, 2)  # Minimal padding
        constraints.anchor = GridBagConstraints.WEST

        # Label field
        label_field = JTextField("", 10)
        label_field.setPreferredSize(Dimension(125, 25))  # Shrink label field

        # Command field
        command_field = JTextField("", 20)
        command_field.setPreferredSize(Dimension(150, 25))  # Shrink command field
        command_field.setMinimumSize(Dimension(150, 25))  # Enforce minimum size
        command_field.setMaximumSize(Dimension(150, 25))  # Enforce maximum size

        # Delete button
        delete_button = JButton("Delete", actionPerformed=lambda evt, row=row: self.remove_dynamic_command(row))

        # Add "Label:" text
        constraints.gridx = 0
        constraints.weightx = 0.0
        constraints.fill = GridBagConstraints.NONE  # No stretching
        row.add(JLabel("Label:"), constraints)

        # Add label field
        constraints.gridx = 1
        constraints.weightx = 0.3  # Allocate minimal space for the label field
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.anchor = GridBagConstraints.WEST  # Align field to the left
        row.add(label_field, constraints)

        # Add "Command:" text
        constraints.gridx = 2
        constraints.weightx = 0.0
        constraints.fill = GridBagConstraints.NONE
        row.add(JLabel("Command:"), constraints)

        # Add command field
        constraints.gridx = 3
        constraints.weightx = 0.5  # Reduced space allocation
        constraints.fill = GridBagConstraints.HORIZONTAL
        row.add(command_field, constraints)

        # Add delete button
        constraints.gridx = 4
        constraints.weightx = 0.0
        constraints.fill = GridBagConstraints.NONE
        row.add(delete_button, constraints)

        # Add row to the dynamic command panel
        self.dynamic_command_panel.add(row, 0)  # Add at index 0
        row.setMaximumSize(Dimension(Integer.MAX_VALUE, 35))
        self.dynamic_fields.insert(0, (label_field, command_field))  # Insert at the beginning of the list
        self.dynamic_command_panel.revalidate()
        self.dynamic_command_panel.repaint()

    def remove_dynamic_command(self, row):
        self.dynamic_command_panel.remove(row)
        self.dynamic_fields = [
            (label, command)
            for label, command in self.dynamic_fields
            if label not in row.getComponents() and command not in row.getComponents()
        ]
        self.dynamic_command_panel.revalidate()
        self.dynamic_command_panel.repaint()

    # Store settings
    def saveSettings(self):
        settings = {tool: value for tool, value in self.flag_values.items()}
        self._callbacks.saveExtensionSetting("settings", json.dumps(settings))
        self._callbacks.saveExtensionSetting("dynamic_commands", json.dumps(self.dynamic_commands))

    # Load settings
    def loadSettings(self):
        settings_json = self._callbacks.loadExtensionSetting("settings")
        if settings_json:
            settings = json.loads(settings_json)
            for tool, value in settings.items():
                if tool in self.flag_values:
                    self.flag_values[tool] = value
                    if tool in self.flag_fields:
                        self.flag_fields[tool].setText(value)

        dynamic_commands_json = self._callbacks.loadExtensionSetting("dynamic_commands")
        if dynamic_commands_json:
            self.dynamic_commands = json.loads(dynamic_commands_json)
            for dynamic in self.dynamic_commands:
                self.add_dynamic_command()
                self.dynamic_fields[-1][0].setText(dynamic["label"])
                self.dynamic_fields[-1][1].setText(dynamic["command"])

    # Format command options
    def format(self, tool_name, url, headers, method, body, header_prefix="-H"):
        variables = self.get_common_variables(url, headers, method, body, header_prefix)
        command = self.format_command(self.flag_values[tool_name], variables)
        return command

    # Custom formatting for JWT Tool
    def format_jwt_tool(self, url, headers, method, body):
        variables = self.get_common_variables(url, headers, method, body, header_prefix="-rh")
        command = self.format_command(self.flag_values["jwt_tool"], variables)
        if body:
            command += " -pd '{}'".format(variables['body'])
        return command

    # Custom formatting for curl
    def format_curl(self, url, headers, method, body):
        variables = self.get_common_variables(url, headers, method, body)
        command = self.format_command(self.flag_values["curl"], variables)
        if "{headers}" in self.flag_values["curl"] and variables['headers']:
            command += " {}".format(variables['headers'])
        if body:
            command += " --data '{}'".format(variables['body'])
        return command

    # Define variables
    def get_common_variables(self, url, headers, method, body, header_prefix="-H"):
        hostname = self.get_hostname(url)
        base_url = self.get_baseurl(url)
        port = self.get_port(url)
        filename = self.get_path_safe_name(hostname)
        directory = self.get_path_safe_name(base_url)
        headers_str = ' '.join(["{} '{}'".format(header_prefix, self.escape(header)) for header in headers[1:]])
        return {
            'url': self.escape(str(url)),
            'baseurl': base_url,
            'hostname': hostname,
            'filename': filename,
            'directory': directory,
            'port': port,
            'method': method,
            'body': self.escape(body) if body else '',
            'headers': headers_str,
            'ua': self.flag_values.get("ua", ""),
        }
    
    # Handle generic command formatting
    def format_command(self, command_template, variables):
        if not command_template:
            return ""
        placeholders = re.findall(r'\{(\w+)\}', command_template)
        for placeholder in placeholders:
            if placeholder in variables:
                command_template = command_template.replace('{' + placeholder + '}', str(variables[placeholder]))
        return command_template

    def getTabCaption(self):
        return "Copy For"

    def getUiComponent(self):
        return self.scroll_pane

    def get_path_safe_name(self, host):
        safe_name = re.sub(r'[^a-zA-Z0-9_\.\-]', '_', host)
        safe_name = re.sub(r'___', '_', safe_name)
        safe_name = safe_name.strip('.- ')
        return safe_name

    def escape(self, s):
        return s.replace("'", "\\'")

    def get_baseurl(self, url):
        return re.match(r'(https?://(?:[^:@]+(?::[^@]+)?@)?[^:/]+)', str(url)).group(1)

    def get_hostname(self, url):
        return re.match(r'https?://(?:[^:@]+(?::[^@]+)?@)?([^/:]+)', str(url)).group(1)

    def extensionUnloaded(self):
        self.saveSettings()

    def get_port(self, url):
        match = re.match(r'https?://(?:[^:@]+(?::[^@]+)?@)?([^:/]+)(?::(\d+))?', str(url))
        if match:
            return match.group(2) if match.group(2) else ("443" if url.startswith("https") else "80")
        return "80"
    
    # Save custom items
    def save_dynamic_commands(self, event):
        self.dynamic_commands = []
        for label_field, command_field in self.dynamic_fields:
            label = label_field.getText().strip()
            command = command_field.getText().strip()
            if label and command:
                self.dynamic_commands.append({"label": label, "command": command})
        self.saveSettings()
    
    def copy_command(self, invocation, option):
        # Get the selected HTTP request
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages or len(selected_messages) == 0:
            self._stdout.println("Error: No HTTP messages selected.")
            return

        http_traffic = selected_messages[0]
        request_info = self._helpers.analyzeRequest(http_traffic)
        url = request_info.getUrl()
        headers = request_info.getHeaders()
        method = request_info.getMethod()
        body_offset = request_info.getBodyOffset()
        request_bytes = http_traffic.getRequest()
        body = None
        if body_offset < len(request_bytes):
            body = self._helpers.bytesToString(request_bytes[body_offset:])

        # Generate the command using the specified formatter
        if option["name"] == "Copy for curl":
            command = option["formatter"](url, headers, method, body)
        else:
            tool_name = option["name"].split(" ")[-1].lower()
            command = option["formatter"](tool_name, url, headers, method, body)

        # Copy the command to the clipboard
        # if command:
        string_selection = StringSelection(command)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(string_selection, None)
        # self._stdout.println("Command copied to clipboard: %s" % command)
        # else:
            # self._stdout.println("Failed to generate command.")

class ChangeListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def changedUpdate(self, e):
        self.callback(None)

    def removeUpdate(self, e):
        self.callback(None)

    def insertUpdate(self, e):
        self.callback(None)
