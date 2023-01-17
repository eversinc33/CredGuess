#!/usr/bin/python3
import ldap, argparse, sys, datetime
from typing import List

class LdapUser:
    def __init__(dn, samAccountName, pwdLastSet):
        self.dn = dn
        self.samAccountName = samAccountName
        self.pwdLastSet = pwdLastSet

def ad_timestamp_to_unix(timestamp):
    if timestamp != 0:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
    return np.nan

def get_users(con, user_dn, password, domain) -> List[LdapUser]:
    results = []

    attributes = ['samAccountName', 'pwdLastSet']
    domain_cn = "".join([f"DC={x}," for x in domain.split('.')])[:-1]

    try:
        con.simple_bind_s(user_dn, password)
        res = con.search_s(f"{domain_cn}", ldap.SCOPE_SUBTREE, '(&(objectClass=User)(objectCategory=Person))', attributes)
        for dn, entry in res:
            results.append(Ldapuser(dn, entry.get("samAccountName"), entry.get("pwdLastSet")))
    except Exception as error:
        print(error)
        
    return results

def main():
    parser = argparse.ArgumentParser(
            prog = "Brute",
            description = "Generates a list of passwords according to users pwdLastSet-date"
    )

    # TODO: anonymous bind
    parser.add_argument('-u', '--username', metavar="username@domain.local", type=str, required=True)
    parser.add_argument('-p', '--password', metavar="<Password>", type=str, required=True)
    parser.add_argument('--ssl', action="store_true", default=False)
    parser.add_argument('--dc-ip', metavar="<DC IP or FQDN>", type=str, required=True)

    args = parser.parse_args()

    user_dn = args.username
    password = args.password
    domain = user_dn.split('@')[1:]
    protocol = "ldaps" if args.ssl else "ldap"
    con = ldap.initialize(f'{protocol}://{args.dc_ip}')

    users = get_users(con, user_dn, password, domain)

    # TODO: get pw according to pw last set
    
if __name__ == "__main__":
    main()
