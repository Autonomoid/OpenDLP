import http.server
import urllib.request
import logging
import regex
regex.DEFAULT_VERSION = regex.VERSION1

### understand your background signal first - this will help to set your thresholds.

# In project folder:  python3 -m http.server 8888
# In web browser: http://localhost:8000/http://localhost:8888/test_form.html
# In web browser: http://localhost:8000/http://www.reddit.com
# In web browser: http://localhost:8000/http://dlptest.com/http-post/

PORT = 8000


def decode_multipart_content(data, delimiter):
    blocks = data.split(delimiter)
    fields = {}
    for block in blocks:
        comps = block.split("\r")# causes breaks in field values to break the parsing
        if len(comps) == 5:
            fields[comps[1].split("\"")[1].strip()] = comps[3].strip()
    return fields


class MyProxy(http.server.SimpleHTTPRequestHandler):
    deny_list = [
        "reddit.com"
    ]

    def allow(self):
        url = self.path[1:]
        self.send_response(200)
        self.end_headers()
        self.copyfile(urllib.request.urlopen(url), self.wfile)

    def deny(self, message=""):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(bytes("<b>DLP Policy Violation</b><br>" + message, "utf-8"))

    def inspect_POST(self, data):
        clean = True
        message = ""

        # load from conf file
        patterns = {
            'Credit Card Number (Visa)': '4(\d{12}|\d{15})(?=\D)',
            'Credit Card Number (Mastercard)': '5\d{15}(?=\D)',
            'Sensitivity Marker (Confidential)': 'confidential',
            'NINO': '[[A-Z]--[DFIQUV]][[A-Z]--[O]]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]',
            'Test Pattern 1': 'post'
        }

        for pattern_id in patterns:
            logging.info("Trying '" + pattern_id + "'.")
            pattern = patterns[pattern_id]
            compiled_pattern = regex.compile(pattern, regex.IGNORECASE)
            if regex.search(compiled_pattern, data) is not None:
                clean = False
                matches = regex.finditer(compiled_pattern, data)
                message += "<br>Pattern = '" + pattern_id + "'"
                message += "<br>Matches:"

                first_match = next(matches)
                text_before = first_match.string[:first_match.start()]
                text_after = first_match.string[first_match.end():]
                highlights = text_before + "<font color=red>" + first_match.group() + "</font>"
                prev_end = first_match.end()

                logging.info("Matches = {")
                logging.info("\t" + first_match.group())

                for match in matches:
                    logging.info("\t" + match.group() + ",")
                    text_before = match.string[prev_end:match.start()]
                    highlights += text_before + "<font color=red>" + match.group() + "</font>"
                    text_after = match.string[match.end():]
                    prev_end = match.end()

                logging.info("}")

                highlights += text_after
                message += "<br>" + highlights + "<br>"

        return clean, message

    def site_is_denied(self):
        url = self.path[1:]
        for domain in self.deny_list:
            if domain in url:
                return True
        return False

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        url=self.path[1:]

        if self.site_is_denied():
            message = "This domain is on the deny list."
            self.deny(message)
        else:
            self.allow()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        # Get all the fields from the multipart form data
        content_type = self.headers['Content-Type'].split(';')[0]
        logging.info("Content type = '" + content_type + "'.")

        if content_type == "multipart/form-data":
            delimiter = self.headers['Content-Type'].split(';')[1].strip().split('=')[1]
            logging.info("Delimiter = '" + delimiter + "'.")

            fields = decode_multipart_content(post_data.decode('utf-8'), "--" + delimiter)
            logging.info("Fields = {")
            for field in fields:
                logging.info("\t" + field + ",")
            logging.info("}")

        # Loop over all fields in the POST message.
        is_clean = True
        hit_count = 0
        final_message = ""
        for key in fields:
            logging.info("Inspecting field '" + key + "'.")
            is_clean, message = self.inspect_POST(fields[key])
            if not is_clean:
                hit_count += 1
                final_message += "<hr>HTTP POST Field = '" + key + "'" + message

        if hit_count == 0:
            self.allow()
        else:
            self.deny(final_message)



FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)
logging.info('Starting httpd...\n')
server = http.server.ThreadingHTTPServer(('', PORT), MyProxy)
server.serve_forever()
