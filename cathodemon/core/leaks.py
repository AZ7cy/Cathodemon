"""Offline leaked-password check.

Compares a password against Cathodemon's own list of the passwords that show up
most often in leaks, and against the patterns that fill leaked-password lists
(a common word plus digits, dates, keyboard runs, short numbers). Nothing is
sent anywhere.

Being offline, it cannot prove a password has never leaked. It catches the
passwords and habits attackers try first. The list was written for Cathodemon
from widely reported "most common password" statistics. Standard library only.
"""
from __future__ import annotations

import re

LEAKED = {
    # numbers
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890", "1234",
    "111111", "000000", "123123", "654321", "666666", "121212", "112233", "123321",
    "7777777", "777777", "555555", "11111111", "88888888", "987654321", "159753",
    "131313", "222222", "333333", "999999", "888888", "11111", "0000", "1111",
    "123654", "987654", "232323", "87654321", "12344321", "8675309", "102030",
    "123654789", "147258369", "147258", "159357", "456789", "789456", "741852963",
    "963852741", "1029384756", "0987654321", "696969", "2580", "1212", "5555",
    "123123123", "1q2w3e", "11223344", "123456a", "a123456", "aa123456",
    # keyboard patterns
    "qwerty", "qwerty123", "qwertyuiop", "qwertyui", "qwerty1", "qwer1234",
    "asdfgh", "asdfghjkl", "asdf1234", "asdfasdf", "zxcvbn", "zxcvbnm", "qazwsx",
    "1qaz2wsx", "1qazxsw2", "zaq12wsx", "1q2w3e4r", "1q2w3e4r5t", "q1w2e3r4",
    "q1w2e3r4t5", "1qaz2wsx3edc", "123qwe", "qweasd", "qweqwe", "abc123", "abcd1234",
    "abc12345", "123abc", "1a2b3c", "abcdef", "abcdefg", "1234qwer", "1234abcd",
    # words and phrases
    "password", "password1", "password12", "password123", "1password", "passw0rd",
    "p@ssw0rd", "p@ssword", "pass", "passwort", "iloveyou", "iloveu", "loveyou",
    "letmein", "letmein1", "welcome", "welcome1", "admin", "admin123", "root",
    "toor", "guest", "test", "changeme", "secret", "login", "master", "hello",
    "whatever", "trustno1", "access", "freedom", "monkey", "monkey1", "dragon",
    "dragon1", "shadow", "shadow1", "sunshine", "sunshine1", "princess",
    "princess1", "superman", "superman1", "batman", "batman1", "starwars",
    "football", "baseball", "soccer", "hockey", "basketball", "mustang",
    "michael", "jennifer", "jordan", "jordan23", "hunter", "buster", "harley",
    "andrew", "tigger", "charlie", "robert", "thomas", "ranger", "daniel",
    "george", "computer", "michelle", "jessica", "pepper", "maggie", "ginger",
    "joshua", "cheese", "amanda", "summer", "winter", "love", "ashley", "nicole",
    "chelsea", "matthew", "yankees", "dallas", "austin", "thunder", "taylor",
    "matrix", "william", "corvette", "martin", "heather", "merlin", "diamond",
    "hammer", "silver", "anthony", "justin", "bailey", "patrick", "internet",
    "scooter", "orange", "golfer", "cookie", "richard", "samantha", "bigdog",
    "guitar", "jackson", "mickey", "chicken", "sparky", "snoopy", "maverick",
    "phoenix", "camaro", "peanut", "morgan", "falcon", "cowboy", "ferrari",
    "samsung", "andrea", "smokey", "steelers", "joseph", "mercedes", "dakota",
    "arsenal", "eagles", "melissa", "boomer", "booboo", "spider", "nascar",
    "monster", "tigers", "yellow", "xxxxxx", "gateway", "marina", "diablo",
    "bulldog", "compaq", "purple", "banana", "junior", "hannah", "porsche",
    "lakers", "iceman", "money", "cowboys", "london", "tennis", "coffee",
    "scooby", "miller", "boston", "brandon", "yamaha", "chester", "mother",
    "forever", "johnny", "edward", "oliver", "redsox", "player", "nikita",
    "knight", "fender", "barney", "midnight", "please", "brandy", "chicago",
    "badboy", "slayer", "rangers", "charles", "angel", "flower", "rabbit",
    "wizard", "jasper", "enter", "rachel", "chris", "steven", "winner", "adidas",
    "victoria", "natasha", "jasmine", "prince", "marine", "fishing", "cocacola",
    "casper", "james", "raiders", "gandalf", "crystal", "golf", "apple",
    "babygirl", "lovely", "liverpool", "pokemon", "killer", "zxcvbnm123",
    "oompaloompa", "india123", "qwerty12", "aaaaaa", "123qweasd", "gfhjkm",
    "ghbdtn", "qwertz", "azerty", "solo", "flower1", "sunflower", "butterfly",
    # famous examples from the xkcd "password strength" comic, now widely reused
    "correct horse battery staple", "correcthorsebatterystaple", "tr0ub4dor&3",
}

# Base words that leaked passwords are most often built from ("Summer2024!").
COMMON_WORDS = {
    "love", "baby", "angel", "summer", "winter", "spring", "autumn", "dragon",
    "monkey", "master", "shadow", "sunshine", "princess", "football", "baseball",
    "soccer", "hockey", "cricket", "jordan", "michael", "jessica", "ashley",
    "charlie", "daniel", "hello", "welcome", "password", "passwort", "qwerty",
    "admin", "letmein", "iloveyou", "secret", "freedom", "flower", "cookie",
    "chocolate", "butterfly", "purple", "orange", "yellow", "banana", "apple",
    "pepper", "ginger", "tiger", "lion", "eagle", "falcon", "killer", "hunter",
    "ranger", "music", "money", "lucky", "happy", "family", "forever", "jesus",
    "india", "london", "paris", "america", "canada", "chicago", "boston",
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "monday", "friday",
    "sunday", "pass", "login", "user", "guest", "test", "root", "superman",
    "batman", "starwars", "pokemon", "computer", "internet", "samsung",
    "matrix", "thunder", "silver", "diamond", "crystal", "angel", "rainbow",
}

_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl",
              "zxcvbnm", "1qaz2wsx3edc4rfv", "qazwsxedc")
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s",
                       "7": "t", "!": "i", "|": "l", "8": "b"})


def _bases(low: str):
    """Possible base words once digits/symbols around the edges are removed and
    look-alike characters are undone (p@ssw0rd123! -> password)."""
    core = re.sub(r"^[\d\W_]+|[\d\W_]+$", "", low)
    if not core:
        return set()
    out = {core, core.translate(_LEET)}
    out |= {core.replace("1", "i").translate(_LEET), core.replace("1", "l").translate(_LEET)}
    return {b for b in out if len(b) >= 3}


def _is_sequence(low: str) -> bool:
    s = re.sub(r"[\W_]", "", low)
    if len(s) < 4:
        return False
    return any(s in seq or s in seq[::-1] for seq in _SEQUENCES)


def _is_date(pw: str) -> bool:
    if re.fullmatch(r"(19[5-9]\d|20[0-4]\d)", pw):
        return True
    m = re.fullmatch(r"(\d{1,2})[./-](\d{1,2})[./-](\d{2}|\d{4})", pw)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        return (1 <= a <= 31 and 1 <= b <= 12) or (1 <= a <= 12 and 1 <= b <= 31)
    m = re.fullmatch(r"(19|20)\d{2}[./-](\d{1,2})[./-](\d{1,2})", pw)
    return bool(m and 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31)


def check(password: str) -> dict:
    """Return {"status": "leaked"|"pattern"|"clear", "title": ..., "detail": ...}."""
    if not password:
        return {"status": "clear", "title": "", "detail": ""}
    low = password.lower()
    if low in LEAKED:
        return {"status": "leaked",
                "title": "Found on Cathodemon's list of the most commonly leaked passwords",
                "detail": "Attackers try this list first, so this password is guessed in "
                          "seconds. Don't use it for any account."}
    if re.fullmatch(r"\d{1,8}", password):
        return {"status": "pattern", "title": "A short number",
                "detail": "Short all-number passwords are among the most leaked and are "
                          "guessed in seconds."}
    if _is_date(password):
        return {"status": "pattern", "title": "Looks like a date",
                "detail": "Birthdays and years appear in every leaked-password list and are "
                          "easy to guess from social media."}
    if len(set(low)) <= 2:
        return {"status": "pattern", "title": "Repeated characters",
                "detail": "Repeats like 'aaaaaa' or 'abab' are among the first guesses."}
    if _is_sequence(low):
        return {"status": "pattern", "title": "A keyboard pattern or sequence",
                "detail": "Runs like 'qwerty', 'asdf' or 'abcd' appear in every leaked-password list."}
    for base in _bases(low):
        if base in LEAKED or base in COMMON_WORDS:
            return {"status": "pattern",
                    "title": f"A common word ('{base}') with extra characters",
                    "detail": "Leaked-password lists are full of variations like this one "
                              "(capital letter, digits, a symbol, @ for a). Cracking tools "
                              "try them right after the plain words."}
    return {"status": "clear",
            "title": "Not on Cathodemon's offline list, and no common leak pattern",
            "detail": "This check runs offline, so it can't prove this exact password has "
                      "never leaked. Use a different password for every account."}
