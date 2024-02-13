import requests
import hashlib
import sys


# K-ANONYMITY HASHES PASSWORD, THEN SELECTS ONLY 1ST 5 CHARS/INTS, FOR SECURITY


#
def request_api_data(query_char):
    url = ('https://api.pwnedpasswords.com/range/' + query_char)
    res = requests.get(url)
    # print(res)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwn_api_check(password):
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # print(first5_char)
    # print(tail)
    # print(sha1password)
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(f'{password} was found {count} time... Password change recommended')
        else:
            print(f'{password} was NOT found. All good!')
    return 'all done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
