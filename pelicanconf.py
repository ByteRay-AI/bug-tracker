AUTHOR = "Argus"
SITENAME = "Argus Proof of Possession"
SITESUBTITLE = "Public Security Advisories"
SITEURL = ""

PATH = "content"

# Each Markdown file under content/advisories/ becomes one advisory.
ARTICLE_PATHS = ["advisories"]

TIMEZONE = "America/Los_Angeles"

DEFAULT_LANG = "en"

# --- Custom theme ---------------------------------------------------------
THEME = "themes/argus"

# Clean, dated URLs for each advisory, e.g. /advisory/2026-06-05-some-bug.html
ARTICLE_URL = "advisory/{slug}.html"
ARTICLE_SAVE_AS = "advisory/{slug}.html"

# Newest advisories first (this is Pelican's default, set explicitly for clarity).
ARTICLE_ORDER_BY = "reversed-date"

DEFAULT_DATE_FORMAT = "%Y-%m-%d"

# --- Feeds ----------------------------------------------------------------
# Disabled during development; enable in publishconf.py for production.
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# --- Navigation -----------------------------------------------------------
LINKS = (
    ("Home", "/"),
)

SOCIAL = ()

DEFAULT_PAGINATION = 25

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True
