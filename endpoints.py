# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab
from java.util import ArrayList
from java.net import URL
import re

from javax.swing import JPanel, JLabel, JButton, JScrollPane, BoxLayout, JTree, JOptionPane
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel
from java.awt import Font, Dimension, event

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab):
    saved_endpoints = set()
    method_based_urls = set()
    tree_nodes = {}

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Hudhud")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self.main_panel = JPanel()
        self.main_panel.setLayout(BoxLayout(self.main_panel, BoxLayout.Y_AXIS))

        self.label = JLabel("JS Endpoint Extractor Dashboard")
        self.label.setFont(Font("Arial", Font.BOLD, 16))
        self.main_panel.add(self.label)

        self.counter_label = JLabel("Extracted: 0 endpoints")
        self.main_panel.add(self.counter_label)

        self.root_node = DefaultMutableTreeNode("JS Files")
        self.tree_model = DefaultTreeModel(self.root_node)
        self.endpoint_tree = JTree(self.tree_model)
        self.endpoint_tree.addMouseListener(self.MouseClickListener(self))

        self.tree_scroll = JScrollPane(self.endpoint_tree)
        self.tree_scroll.setPreferredSize(Dimension(900, 400))
        self.main_panel.add(self.tree_scroll)

        self.button_extract = JButton("Extract from Site Map + HTTP History", actionPerformed=self.extract_from_history)
        self.button_clear = JButton("Clear Everything", actionPerformed=self.clear_all_memory_and_log)
        self.button_export = JButton("Export Endpoints to TXT", actionPerformed=self.export_to_txt)
        self.main_panel.add(self.button_export)
        self.main_panel.add(self.button_extract)
        self.main_panel.add(self.button_clear)

        callbacks.addSuiteTab(self)

    def export_to_txt(self, event):
        try:
            filepath = "extracted_endpoints.txt"
            with open(filepath, "w") as f:
                for (line, _) in sorted(self.saved_endpoints, key=lambda x: re.sub(r'^\[(GET|POST|PUT|DELETE|PATCH|Path|Full)\]\s+', '', x[0]).lower()):
                    endpoint = re.sub(r'^\[(GET|POST|PUT|DELETE|PATCH|Path|Full)\]\s+', '', line)
                    f.write(endpoint + "\n")
            JOptionPane.showMessageDialog(self.main_panel, "Endpoints exported to: " + filepath)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error: " + str(e))

    def getTabCaption(self):
        return "JS Extractor"

    def getUiComponent(self):
        return self.main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        url_obj = self._helpers.analyzeRequest(messageInfo).getUrl()
        url = url_obj.toString()
        if not self._callbacks.isInScope(url_obj):
            return

        response = messageInfo.getResponse()
        if not response:
            return

        analyzed = self._helpers.analyzeResponse(response)
        headers = analyzed.getHeaders()
        body_offset = analyzed.getBodyOffset()
        body = response[body_offset:].tostring()

        content_type = ""
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.lower()
                break

        if content_type.find("javascript") == -1 and not url.endswith(".js"):
            return

        self.extract_and_save(body, url)

    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = self._callbacks.createMenuItem("Extract from Site Map + HTTP History", self.extract_from_history)
        menu.add(item)
        return menu

    def extract_from_history(self, event):
        items = list(self._callbacks.getSiteMap(None)) + list(self._callbacks.getProxyHistory())
        for item in items:
            response = item.getResponse()
            if not response:
                continue
            url = self._helpers.analyzeRequest(item).getUrl()
            if not self._callbacks.isInScope(url):
                continue
            url_str = url.toString()
            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()
            body_offset = analyzed.getBodyOffset()
            body = response[body_offset:].tostring()
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.lower()
                    break
            if content_type.find("javascript") == -1 and not url_str.endswith(".js"):
                continue
            self.extract_and_save(body, url_str)

    def extract_and_save(self, body, source_url):
        STATIC_FILE_EXTENSIONS = ('.png', '.svg', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.css', '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.otf')
        STATIC_PATH_BLACKLIST = (
            '/fonts/', '/icons/', '/images/', '/bootstrap/', '/vendor/', '/locales/', '/i18n/', 
            'dd/MM/yyyy', 'MM/dd/yyyy', 'application/pdf', 'application/json', 'application/javascript', 'text/css', 'text/plain', 'application/ecmascript', 'M/d/yy', '//', "dd/MM/yyyy", 'image/png'
        )
        STATIC_PATH_BLACKLIST = tuple(b.lower() for b in STATIC_PATH_BLACKLIST)

        method_patterns = [
            r'fetch\s*\(\s*["\'](?P<url>[^"\']+)["\']\s*,\s*{[^}]*?method\s*:\s*["\'](?P<method>GET|POST|PUT|DELETE|PATCH)["\']',
            r'axios\.(?P<method>get|post|put|delete|patch)\s*\(\s*["\'](?P<url>[^"\']+)["\']',
            r'\$\.ajax\s*\(\s*{[^}]*?url\s*:\s*["\'](?P<url>[^"\']+)["\'][^}]*?type\s*:\s*["\'](?P<method>GET|POST|PUT|DELETE|PATCH)["\']',
            r'xhr\.open\s*\(\s*["\'](?P<method>GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\'](?P<url>[^"\']+)["\']',
            r'\brequest\.(?P<method>get|post|put|delete|patch)\s*\(\s*["\'](?P<url>[^"\']+)["\']',
            r'this\.\$?http\.(?P<method>get|post|put|delete)\s*\(\s*["\'](?P<url>[^"\']+)["\']',
            r'makeRequest\s*\(\s*["\'](?P<method>GET|POST|PUT|DELETE)["\']\s*,\s*["\'](?P<url>[^"\']+)["\']',
        ]

        found = []
        self.method_based_urls = set()

        for pattern in method_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                method = match.group("method").upper()
                url = match.group("url")
                if url and not url.lower().endswith(STATIC_FILE_EXTENSIONS) and not self.is_noise_path(url) and not any(bad in url.lower() for bad in STATIC_PATH_BLACKLIST):
                    self.method_based_urls.add(url)
                    line = "[{}] {}".format(method, url)
                    if (line, source_url) not in self.saved_endpoints:
                        found.append(line)
                        self.saved_endpoints.add((line, source_url))

        raw_paths = re.findall(r'[\[\\"\']([a-zA-Z0-9_\-/\.]*\/[a-zA-Z0-9_\-/\.]+)[\\"\']', body)
        for p in raw_paths:
            if p in self.method_based_urls:
                continue
            if not p.lower().endswith(STATIC_FILE_EXTENSIONS) and not self.is_noise_path(p) and not any(bad in p.lower() for bad in STATIC_PATH_BLACKLIST):
                line = "[Path] " + p
                if (line, source_url) not in self.saved_endpoints:
                    found.append(line)
                    self.saved_endpoints.add((line, source_url))

        if found:
            self.add_to_tree(source_url, found)
            self.update_counter()

    def add_to_tree(self, js_url, endpoint_list):
        if js_url not in self.tree_nodes:
            label = "{} ({})".format(js_url, len(endpoint_list))
            js_node = DefaultMutableTreeNode(label)
            self.tree_nodes[js_url] = js_node
            self.tree_model.insertNodeInto(js_node, self.root_node, self.root_node.getChildCount())
        else:
            js_node = self.tree_nodes[js_url]
            label = "{} ({})".format(js_url, js_node.getChildCount() + len(endpoint_list))
            js_node.setUserObject(label)

    #  Sort alphabetically before adding
        for ep in sorted(endpoint_list, key=lambda x: re.sub(r'^\[(GET|POST|PUT|DELETE|PATCH|Path|Full)\]\s+', '', x).lower()):
            ep_node = DefaultMutableTreeNode(ep.strip())
            js_node.add(ep_node)

        self.tree_model.reload()

    def update_counter(self):
        self.counter_label.setText("Extracted: {} endpoints".format(len(self.saved_endpoints)))

    def clear_all_memory_and_log(self, event):
        self.saved_endpoints.clear()
        self.method_based_urls.clear()
        self.tree_nodes.clear()
        self.root_node.removeAllChildren()
        self.tree_model.reload()
        self.counter_label.setText("Extracted: 0 endpoints")

    def is_noise_path(self, path):
        path_lower = path.lower()
        lang_codes = ['ar', 'en', 'fr', 'ur', 'zh', 'vi', 'uz', 'tr', 'yo', 'lt', 'ru', 'ja', 'de', 'es', 'fa', 'ps']
        if path_lower.startswith('.../') or path_lower.startswith('../'):
            return True
        if any(path_lower.startswith(code + '/') for code in lang_codes):
            return True
        if any(path_lower.endswith(code + '.js') for code in lang_codes):
            return True
        if len(path_lower.strip('/').split('/')) == 1 and path_lower.strip('/') in lang_codes:
            return True
        if "assets/images" in path_lower or "icons/" in path_lower:
            return True
        return False

    class MouseClickListener(event.MouseAdapter):
        def __init__(self, outer):
            self.outer = outer

        def mouseClicked(self, e):
            tree = e.getSource()
            path = tree.getPathForLocation(e.getX(), e.getY())
            if path and path.getPathCount() > 1:
                node = path.getLastPathComponent()
                if node.isLeaf() and e.getClickCount() == 1:
                    raw_text = node.toString()
                    endpoint = re.sub(r'^\[(GET|POST|PUT|DELETE|PATCH|Path|Full)\]\s+', '', raw_text)
                    self.copy_to_clipboard(endpoint)

        def copy_to_clipboard(self, text):
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            selection = StringSelection(text)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, None)
