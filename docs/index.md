---
layout: default
title: OSINT Monitor
---

# OSINT Monitor  
Public OSINT references to exploitation, proof‑of‑concept activity, or zero‑day claims.  
Items listed here are automatically filtered to exclude vulnerabilities already present in the Known Exploited Vulnerabilities (KEV) Catalog.

_Last updated: **{{ site.data.latest.generated_at }}**_

---

## Results

<table>
  <thead>
    <tr>
      <th>Source</th>
      <th>Title</th>
      <th>Claim</th>
      <th>CVEs</th>
      <th>Link</th>
      <th>Published</th>
    </tr>
  </thead>
  <tbody>
    {% for item in site.data.latest.items %}
      <tr>
        <td>{{ item.source }}</td>
        <td>{{ item.title }}</td>
        <td>{{ item.claim }}</td>
        <td>
          {% if item.cves and item.cves.size > 0 %}
            {% for cve in item.cves %}
              https://www.cve.org/CVERecord?id={{ cve }}{{ cve }}</a>{% unless forloop.last %}, {% endunless %}
            {% endfor %}
          {% else %}
            N/A
          {% endif %}
        </td>
        <td>
          {% if item.url %}
          {{ item.url }}open</a>
          {% endif %}
        </td>
        <td>{{ item.published }}</td>
      </tr>
    {% endfor %}
  </tbody>
</table>

---

**Note:** This page is auto‑generated from public sources. Respect each source’s terms of service.
