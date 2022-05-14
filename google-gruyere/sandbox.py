import re
from gruyere_code.sanitize import SanitizeHtml

html_snippet = '<input <script>alert()</script>'

print(SanitizeHtml(html_snippet))