import re
from gruyere_code.sanitize import SanitizeHtml

html_snippet = '<p <script>alert(1)</script>hello'

print(SanitizeHtml(html_snippet))