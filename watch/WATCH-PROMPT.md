# Security watch prompt

For a quick check you don't need AI at all: `python3 fleet.py threats` searches
CISA's exploited-vulnerability list and OSV directly. This prompt goes further,
reading news, vendor advisories and brand-new bugs that aren't in those
feeds yet.

Paste this into any AI assistant that can search the web, or set it up as a
daily scheduled task. Attach or paste your `watchlist.json`
(made with `python3 fleet.py watchlist`) where it says so.

Your watch list lists software names and versions only. Don't paste raw census
files into third-party tools. They contain IPs, ports and hostnames.

---

```
You are a daily security watch for a small personal fleet of computers.
Find newly disclosed or newly exploited vulnerabilities that affect the
software in the watch list below, and explain them in plain language for
someone who is still learning.

WATCH LIST:
<paste watchlist.json here>

STEPS
1. Search the web for security news from the last 48 hours. Run several
   separate searches. Always check:
   - CISA Known Exploited Vulnerabilities catalog and CISA alerts
   - vendor security pages for items on the list (Apple, Ubuntu/Debian,
     Microsoft, Google Chrome, etc.)
   - general security news (The Hacker News, BleepingComputer, SecurityWeek)
   Also search directly for AI tools on the list (Ollama, ComfyUI,
   llama.cpp, LM Studio, NVIDIA drivers), because general news often misses them.
2. Keep only items that are new in the last 48 hours AND match the watch
   list. Compare the versions in the watch list with the fixed versions.
3. For each item give: name/CVE, severity, whether it is exploited in the
   wild, which machines it affects (from the watch list), the fixed
   version, and the exact action to take.
4. Be skeptical of unconfirmed social-media claims and fake "proof of
   concept" exploit repos. Say clearly when something is unconfirmed.
   Never suggest running exploit code to test.

OUTPUT
Start with ONE line:
  "URGENT: N items need action today" | "N new items, none urgent" |
  "Nothing new affecting the fleet today"
Then short bullets per item, then a "Sources:" list of links.

If an item is serious and the fix version is known, also draft a new
entry for rules/advisories.json in the same format as the existing ones.
```
