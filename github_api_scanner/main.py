from tqdm import tqdm
from collections import defaultdict
import aiohttp
import asyncio


limit = asyncio.Semaphore(20)  # Чтобы не словить secondary rate limit
time_sleep = 0.01


async def get_json_from_url(session: aiohttp.ClientSession,
                            url: str, auth: tuple):
    async with limit:
        if limit.locked():
            await asyncio.sleep(time_sleep)
        async with session.get(url, auth=aiohttp.BasicAuth(auth[0], auth[1])) as response:
            return await response.json()


async def get_count_commits_pages(session: aiohttp.ClientSession,
                                  commits_url: str, auth: tuple) -> int:
    url = f"{commits_url}?per_page=1"
    async with limit:
        if limit.locked():
            await asyncio.sleep(time_sleep)
        async with session.get(url, auth=aiohttp.BasicAuth(auth[0], auth[1])) as response:

            if len(response.links) == 0:
                return 0
            last_url = str(response.links.get("last").get("url"))
            page = last_url[last_url.rindex('=') + 1:]

            return int(page) // 100 + 1


async def update_counter_by_commit_page(session: aiohttp.ClientSession,
                                        counter: defaultdict, commits_url: str,
                                        page: int, auth: tuple) -> None:
    commits_json = await get_json_from_url(session, f'{commits_url}?per_page=100&page={page}', auth)
    for commit_json in commits_json:
        if 'commit' not in commit_json \
                or 'Merge pull request #' in commit_json['commit']['message']:
            continue

        author = commit_json['commit']['author']['email']

        if author != '':
            counter[author] += 1


async def update_counter_by_repos(session: aiohttp.ClientSession,
                                  counter: defaultdict, commits_url: str,
                                  auth: tuple, progress_update_func) -> None:
    count_pages = await get_count_commits_pages(session, commits_url, auth)

    futures = []
    for page in range(1, count_pages + 1):
        futures.append(update_counter_by_commit_page(session, counter, commits_url, page, auth))

    for future in asyncio.as_completed(futures):
        await future

    progress_update_func()


async def update_counter_by_repos_page(session: aiohttp.ClientSession,
                                       counter: defaultdict, url: str,
                                       page: int, auth: tuple, progress_update_func) -> None:
    repositories_jsons = await get_json_from_url(session, f'{url}/repos?per_page=100&page={page}', auth)

    futures = []
    for repos_json in repositories_jsons:
        commits_url = repos_json['commits_url'].replace('{/sha}', '')
        futures.append(update_counter_by_repos(session, counter, commits_url, auth, progress_update_func))

    for future in asyncio.as_completed(futures):
        await future


async def get_top_authors(session: aiohttp.ClientSession,
                          url: str, auth: tuple, n=100) -> dict:
    counter = defaultdict(int)

    main_json = await get_json_from_url(session, url, auth)
    count_repositories = main_json['public_repos']
    progress_bar = tqdm(total=count_repositories)

    futures = [
        update_counter_by_repos_page(session, counter, url, i // 100 + 1, auth, lambda: progress_bar.update())
        for i in range(0, count_repositories, 100)
    ]

    for future in asyncio.as_completed(futures):
        await future

    sorted_counter = {author: value for author, value in
                      sorted(counter.items(), key=lambda item: item[1], reverse=True)}

    result = {}
    for i, author in enumerate(sorted_counter):
        if i >= n:
            break
        result[author] = sorted_counter[author]

    return result


def print_top(collection: dict) -> None:
    for i, author in enumerate(collection):
        print(f'{i + 1}. {author} -- {collection[author]}')


async def main():
    async with aiohttp.ClientSession() as session:
        user_name = input('Введи имя своего аккаунта GitHub\n')
        token = input('Введи токен\n')
        auth = (user_name, token)
        organisation = input('Какую организацию исследуем?\n')

        url = f'https://api.github.com/orgs/{organisation}'
        print('Прогресс: ')
        top_dict = await get_top_authors(session, url, auth)
        print(f'Топ активных авторов в {organisation}: ')
        print_top(top_dict)
        input('Введи что угодно для выхода\n')
        return


if __name__ == '__main__':
    ioloop = asyncio.new_event_loop()
    top_dict = ioloop.run_until_complete(main())
    ioloop.close()
