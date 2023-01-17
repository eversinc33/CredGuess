#!/usr/bin/python3
import ldap, argparse, sys

def get_users(con, user_dn, password, domain):

    attributes = ['samAccountName', 'pwdLastSet']
    domain_cn = [f"DC={x}," for x in domain.split('.')][:-1]

    try:
        con.simple_bind_s(user_dn, password)
        res = con.search_s(f"CN=Users,{domain_cn}", ldap.SCOPE_SUBTREE, '(objectClass=User)', attributes)
        for dn, entry in res:
            print(dn)
    except Exception as error:
        print(error)

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
    con = ldap.initialize(f'{protocol}://{dc}')

    get_users(con, user_dn, password, domain)

if __name__ == "__main__":
    main()
