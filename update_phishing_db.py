from urllib.request import urlopen
from urllib.error import URLError, HTTPError

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
LOCAL_DB_PATH = "data/phishing_db.txt"


def load_local_urls(file_path):
    urls = set()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                url = line.strip()
                if url:
                    urls.add(url)
    except FileNotFoundError:
        print("Lokal baza topilmadi. Yangi baza yaratiladi.")

    return urls


def load_remote_urls(feed_url):
    urls = set()

    try:
        with urlopen(feed_url) as response:
            content = response.read().decode("utf-8")

            for line in content.splitlines():
                url = line.strip()
                if url:
                    urls.add(url)

    except HTTPError as e:
        print(f"HTTP xatolik yuz berdi: {e}")
    except URLError as e:
        print(f"Internet ulanishida muammo: {e}")
    except Exception as e:
        print(f"Noma'lum xatolik: {e}")

    return urls


def save_urls(file_path, urls):
    sorted_urls = sorted(urls)

    with open(file_path, "w", encoding="utf-8") as file:
        for url in sorted_urls:
            file.write(url + "\n")


def update_database():
    print("Lokal baza yuklanmoqda...")
    local_urls = load_local_urls(LOCAL_DB_PATH)
    print(f"Lokal bazadagi URL soni: {len(local_urls)}")

    print("OpenPhish bazasi yuklanmoqda...")
    remote_urls = load_remote_urls(OPENPHISH_FEED_URL)
    print(f"OpenPhish'dan olingan URL soni: {len(remote_urls)}")

    if not remote_urls:
        print("Yangi baza olinmadi. Lokal baza o'zgartirilmadi.")
        return

    merged_urls = local_urls.union(remote_urls)

    new_count = len(merged_urls) - len(local_urls)

    save_urls(LOCAL_DB_PATH, merged_urls)

    print("Baza muvaffaqiyatli yangilandi.")
    print(f"Jami URL soni: {len(merged_urls)}")
    print(f"Qo'shilgan yangi URL lar soni: {new_count}")


if __name__ == "__main__":
    update_database()