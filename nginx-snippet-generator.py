import re
from pathlib import Path
import httpx

USER_AGENTS_SOURCES = [
    "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/refs/heads/main/haproxy-block-ai-bots.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list",
    "https://raw.githubusercontent.com/coreruleset/coreruleset/refs/heads/main/rules/scanners-user-agents.data",
]

WHITELIST_USER_AGENTS = {
    "python",
    "requests",
    "httpx",
    "urllib",
    "aiohttp",
    "tornado",
    "pip",
    "node",
    "axios",
    "undici",
    "got",
    "node-fetch",
    "npm",
    "php",
    "guzzlehttp",
    "guzzle",
    "composer",
    "java",
    "okhttp",
    "apache-httpclient",
    "spring-web",
    "dotnet",
    "clr",
    "go-http-client",
    "reqwest",
    "hyper",
    "curl",
    "wget",
    "mozilla",
    "chrome",
    "safari",
    "firefox",
    "edge",
    "opera",
    "chromium",
    "applewebkit",
    "gecko",
    "khtml",
    "uabrowser",
    "yabrowser",
    "android",
    "iphone",
    "ipad",
    "cfnetwork",
    "dalvik",
    "googlebot",
    "yandexbot",
    "bingbot",
    "applebot",
    "baiduspider",
    "duckduckbot",
    "yandeximages",
    "google-keyword-suggestion",
    "adsbot-google",
    "telegrambot",
    "vkshare",
    "facebookexternalhit",
    "whatsapp",
    "twitterbot",
    "pinterestbot",
    "linkedinbot",
    "slackbot",
    "discordbot",
    "uptime",
    "monitoring",
    "pingdom",
    "gtmetrix",
    "leto",
}


def fetch_user_agents(client: httpx.Client, url: str) -> set[str]:
    response = client.get(url)
    response.raise_for_status()

    user_agents = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        clean_ua = line.replace("\\ ", " ").split("/")[0].strip().lower()
        if clean_ua:
            user_agents.add(clean_ua)

    return user_agents


def extract_roots(user_agents: set[str]) -> set[str]:
    split_pattern = re.compile(r"[\s\-_]")
    sub_pattern = re.compile(r"v?\d+(\.\d+)*$")
    raw_roots = set()

    for ua in user_agents:
        base_root = split_pattern.split(ua)[0].strip()

        if len(base_root) < 6 or base_root.isdigit():
            raw_roots.add(ua)
            continue

        cleaned_root = sub_pattern.sub("", base_root).strip(" .-_\t")

        if len(cleaned_root) >= 5:
            raw_roots.add(cleaned_root)
        else:
            raw_roots.add(ua)

    return raw_roots


def filter_and_minimize(raw_roots: set[str], whitelist: set[str]) -> list[str]:
    minimized = []
    for current in sorted(raw_roots, key=len):
        if current in whitelist:
            continue
        if any(current.startswith(saved) for saved in minimized):
            continue

        minimized.append(current)
    return minimized


def make_nginx_map(user_agents: list[str]) -> list[str]:
    nginx_lines = []
    for ua in user_agents:
        escaped_ua = re.escape(ua)

        if len(ua) < 6:
            nginx_lines.append(rf"~*\b{escaped_ua} 1;")
        else:
            nginx_lines.append(rf"~*{escaped_ua} 1;")

    return nginx_lines


def main():
    user_agents = set()

    with httpx.Client() as client:
        for url in USER_AGENTS_SOURCES:
            user_agents.update(fetch_user_agents(url=url, client=client))

    raw_roots = extract_roots(user_agents)
    filtered_ua = filter_and_minimize(raw_roots, WHITELIST_USER_AGENTS)

    nginx_map_rules = make_nginx_map(sorted(filtered_ua))

    output_path = Path("bad_user_agents.map")
    output_path.write_text("\n".join(nginx_map_rules), encoding="utf-8")


if __name__ == "__main__":
    main()
