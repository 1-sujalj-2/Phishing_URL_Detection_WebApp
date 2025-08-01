# import re
# from urllib.parse import urlparse
# import numpy as np
#
#
# def extract_features(url):
#     """
#     Extracts 30 features from a given URL to match the phishing.csv dataset.
#     Features that cannot be derived from the URL string alone (like 'AgeofDomain')
#     are set to a neutral '0' value.
#     """
#
#     # Helper function to convert 1/-1 values to 1/0
#     def to_binary(val):
#         return 1 if val == 1 else 0
#
#     # Ensure URL has a scheme (like http://) for proper parsing
#     if not re.match(r'^https?://', url):
#         url = 'http://' + url
#
#     parsed_url = urlparse(url)
#     domain = parsed_url.netloc
#     path = parsed_url.path
#
#     # --- Feature Extraction (Order matches phishing.csv) ---
#
#     # 1. UsingIP
#     using_ip = to_binary(1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else -1)
#
#     # 2. LongURL
#     long_url = to_binary(1 if len(url) > 75 else -1)
#
#     # 3. ShortURL
#     shortening_services = ['bit.ly', 't.co', 'tinyurl', 'is.gd', 'goo.gl', 'ow.ly']
#     short_url = to_binary(1 if any(service in domain for service in shortening_services) else -1)
#
#     # 4. Symbol@
#     symbol_at = to_binary(1 if '@' in url else -1)
#
#     # 5. Redirecting//
#     redirecting = to_binary(1 if '//' in path else -1)
#
#     # 6. PrefixSuffix-
#     prefix_suffix = to_binary(1 if '-' in domain else -1)
#
#     # 7. SubDomains
#     sub_domains_count = len(domain.split('.'))
#     sub_domains = to_binary(1 if sub_domains_count > 3 else (-1 if sub_domains_count > 2 else 0))
#
#     # 8. HTTPS
#     https = to_binary(1 if parsed_url.scheme == 'https' else -1)
#
#     # 9. DomainRegLen (Cannot be computed from URL alone)
#     domain_reg_len = 0
#
#     # 10. Favicon (Cannot be computed accurately from URL alone)
#     favicon = 0
#
#     # 11. NonStdPort
#     non_std_port = to_binary(1 if parsed_url.port not in [None, 80, 443] else -1)
#
#     # 12. HTTPSDomainURL
#     https_domain_url = to_binary(1 if 'https' in domain else -1)
#
#     # The following features require parsing page content or external lookups.
#     # We will return 0 as a neutral value.
#     request_url = 0
#     anchor_url = 0
#     links_in_script_tags = 0
#     server_form_handler = 0
#
#     # 17. InfoEmail
#     info_email = to_binary(1 if 'mailto:' in url else -1)
#
#     # 18. AbnormalURL
#     abnormal_url = to_binary(1 if domain not in url else -1)
#
#     website_forwarding = 0
#     status_bar_cust = 0
#     disable_right_click = 0
#     using_popup_window = 0
#     iframe_redirection = 0
#     age_of_domain = 0
#     dns_recording = 0
#     website_traffic = 0
#     page_rank = 0
#     google_index = 0
#     links_pointing_to_page = 0
#     stats_report = 0
#
#     # --- Assemble the final feature vector in the correct order ---
#     features = [
#         using_ip, long_url, short_url, symbol_at, redirecting, prefix_suffix,
#         sub_domains, https, domain_reg_len, favicon, non_std_port,
#         https_domain_url, request_url, anchor_url, links_in_script_tags,
#         server_form_handler, info_email, abnormal_url, website_forwarding,
#         status_bar_cust, disable_right_click, using_popup_window,
#         iframe_redirection, age_of_domain, dns_recording, website_traffic,
#         page_rank, google_index, links_pointing_to_page, stats_report
#     ]
#
#     return np.array(features).reshape(1, -1)


import re
from urllib.parse import urlparse
import numpy as np


def extract_features(url):
    """
    Extracts 30 features from a given URL, matching the user's specific
    training data preparation.
    """
    if not re.match(r'^https?://', url):
        url = 'http://' + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # --- Ternary Features (1, 0, -1) ---
    # These columns were NOT in the user's list for -1 to 0 conversion.

    # LongURL
    if len(url) > 75:
        long_url = 1
    elif len(url) >= 54:
        long_url = 0
    else:
        long_url = -1

    # SubDomains
    sub_domains_count = len(domain.split('.'))
    if sub_domains_count > 3:
        sub_domains = 1
    elif sub_domains_count == 3:
        sub_domains = 0
    else:
        sub_domains = -1

    # HTTPS
    https = -1 if parsed_url.scheme == 'https' else 1

    # Non-computable ternary features default to -1 (safe).
    anchor_url = -1
    links_in_script_tags = -1
    server_form_handler = -1
    website_traffic = -1
    links_pointing_to_page = -1

    # --- Binary Features (1, 0) ---
    # These columns WERE in the user's list for -1 to 0 conversion.

    using_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
    short_url = 1 if any(service in domain for service in ['bit.ly', 't.co', 'tinyurl.com']) else 0
    symbol_at = 1 if '@' in url else 0
    redirecting = 1 if '//' in parsed_url.path else 0
    prefix_suffix = 1 if '-' in domain else 0
    non_std_port = 1 if parsed_url.port not in [None, 80, 443] else 0
    https_domain_url = 1 if 'https' in domain else 0
    info_email = 1 if 'mailto:' in url else 0
    abnormal_url = 1 if parsed_url.hostname not in url else 0

    # Non-computable binary features default to 0 (safe).
    domain_reg_len = 0
    favicon = 0
    request_url = 0
    website_forwarding = 0
    status_bar_cust = 0
    disable_right_click = 0
    using_popup_window = 0
    iframe_redirection = 0
    age_of_domain = 0
    dns_recording = 0
    page_rank = 0
    google_index = 0
    stats_report = 0

    # --- Assemble the final feature vector in the correct order ---
    features = [
        using_ip, long_url, short_url, symbol_at, redirecting, prefix_suffix,
        sub_domains, https, domain_reg_len, favicon, non_std_port,
        https_domain_url, request_url, anchor_url, links_in_script_tags,
        server_form_handler, info_email, abnormal_url, website_forwarding,
        status_bar_cust, disable_right_click, using_popup_window,
        iframe_redirection, age_of_domain, dns_recording, website_traffic,
        page_rank, google_index, links_pointing_to_page, stats_report
    ]

    return np.array(features).reshape(1, -1)