import re


def classify_severity(title):
    t = title.lower()
    if any(x in t for x in [
        'rce', 'remote code execution', 'unauthenticated sql injection',
        'file upload', 'php file upload', 'deserialization', 'admin+ php',
        'arbitrary file upload', 'phar'
    ]):
        return "critical"
    elif any(x in t for x in [
        'sql injection', 'sqli', 'sql in ', 'ssrf', 'arbitrary file read',
        'arbitrary file delet', 'blind ssrf', 'price manipulation',
        'unauthenticated shortcode', 'arbitrary shortcode execution',
        'unauthenticated arbitrary'
    ]):
        return "high"
    elif any(x in t for x in [
        'xss', 'csrf', 'cross-site', 'open redirect', 'disclosure',
        'exposure', 'traversal', 'missing authorization', 'injection',
        'content injection', 'information exposure', 'broken access'
    ]):
        return "medium"
    else:
        return "low"


def extract_cves(references):
    """Extract CVE IDs and map them to their URLs from references list."""
    cve_map = {}
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    poc_keywords = ['exploit', 'poc', 'proof', 'github.com', 'exploit-db', 'packetstorm', 'rapid7']

    for ref in references:
        # Check if the URL itself contains a CVE identifier
        cve_in_url = cve_pattern.search(ref)
        if cve_in_url:
            cve_id = cve_in_url.group(0).upper()
            if cve_id not in cve_map:
                cve_map[cve_id] = {"cve_url": ref, "poc_url": None}
            elif not cve_map[cve_id]["cve_url"]:
                cve_map[cve_id]["cve_url"] = ref
        # Check if this is a PoC link
        ref_lower = ref.lower()
        if any(kw in ref_lower for kw in poc_keywords):
            # Associate with most recently seen CVE if any
            for cve_id in reversed(list(cve_map.keys())):
                if not cve_map[cve_id]["poc_url"]:
                    cve_map[cve_id]["poc_url"] = ref
                    break

    return [
        {"id": cid, "cve_url": data["cve_url"], "poc_url": data["poc_url"]}
        for cid, data in cve_map.items()
    ]


def parse_wpscan(raw):
    result = {
        "target": "",
        "wordpress_version": "",
        "plugins": [],
        "users": [],
        "interesting_findings": [],
        "vulnerabilities": [],
        "summary": {
            "total_vulns": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "plugins_found": 0
        }
    }

    lines = raw.splitlines()
    i = 0
    current_plugin = None

    while i < len(lines):
        line = lines[i]

        # Target URL
        if re.search(r'\[\+\] URL:', line):
            m = re.search(r'https?://[^\s\]]+', line)
            if m:
                result["target"] = m.group(0).rstrip('/')

        # WordPress version
        if 'WordPress version' in line:
            m = re.search(r'(\d+\.\d+[\.\d]*)', line)
            if m:
                result["wordpress_version"] = m.group(1)

        # Plugin block: line like "[+] plugin-slug"
        pm = re.match(r'^\[\+\]\s+([\w\-]+)\s*$', line)
        if pm:
            pname = pm.group(1)
            current_plugin = {"name": pname, "version": "", "vulns": []}
            result["plugins"].append(current_plugin)
            result["summary"]["plugins_found"] += 1

        # Plugin version detection
        if current_plugin:
            vm = re.search(r'\|\s+Version:\s+([\d.]+)', line)
            if vm and not current_plugin["version"]:
                current_plugin["version"] = vm.group(1)
            vm2 = re.search(r'\?ver=([\d.]+)', line)
            if vm2 and not current_plugin["version"]:
                current_plugin["version"] = vm2.group(1)

        # Vulnerability title line
        if re.search(r'\[!\] Title:', line):
            title_m = re.search(r'\[!\] Title:\s*(.+)', line)
            if title_m:
                title = title_m.group(1).strip()
                vuln = {
                    "title": title,
                    "severity": classify_severity(title),
                    "fixed_in": "",
                    "references": [],
                    "cves": [],
                    "plugin": current_plugin["name"] if current_plugin else "WordPress Core"
                }

                j = i + 1
                while j < len(lines) and j < i + 30:
                    sub = lines[j]
                    if re.search(r'\[!\] Title:', sub):
                        break
                    if re.match(r'^\[\+\]', sub) and not re.search(r'^\s*\|', sub):
                        break
                    fi = re.search(r'Fixed in:\s*([\d.]+)', sub)
                    if fi:
                        vuln["fixed_in"] = fi.group(1)
                    ref = re.search(r'-\s*(https?://\S+)', sub)
                    if ref:
                        vuln["references"].append(ref.group(1))
                    j += 1

                # Extract CVEs from references
                vuln["cves"] = extract_cves(vuln["references"])

                result["vulnerabilities"].append(vuln)
                sev = vuln["severity"]
                result["summary"][sev] = result["summary"].get(sev, 0) + 1
                if current_plugin:
                    current_plugin["vulns"].append(vuln)

        # Users
        if 'Login:' in line:
            um = re.search(r'Login:\s*(\S+)', line)
            if um:
                result["users"].append(um.group(1))

        # Interesting top-level findings
        if re.match(r'^\[\+\]', line):
            skip_words = [
                'URL:', 'Started:', 'Enumerating', 'Checking', 'Finished',
                'WPScan DB', 'Requests', 'Data ', 'Memory', 'Elapsed'
            ]
            if not any(s in line for s in skip_words):
                if not re.match(r'^\[\+\]\s+[\w\-]+\s*$', line):
                    finding = re.sub(r'^\[\+\]\s*', '', line).strip()
                    if finding and len(finding) < 300:
                        result["interesting_findings"].append(finding)

        i += 1

    result["summary"]["total_vulns"] = len(result["vulnerabilities"])
    return result
