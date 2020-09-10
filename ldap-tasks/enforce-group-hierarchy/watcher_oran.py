COMP_ID: int = 4409
COMP_NAME: str = 'Watcher Oran'
VERSION: int = 1000

import argparse
import coloredlogs
import getpass
import logging
import os
import ldap
import ldap.modlist
import sys

log: logging.Logger = logging.getLogger()



def preprocessLDAPGroups(lConnection: ldap.ldapobject.LDAPObject, unsortedGroups):
    ''' Take the unsorted and potentially-incomplete list of LDAP groups and use
      ' the `supergroup` attribute to:
      ' 
      '   * pull in any top-level groups (that aren't `extendedGroup`s and thus
      '     weren't pulled in by the initial query); and
      ' 
      '   * sort the list of groups in order of inheritance, so that any
      '     subgroup will always appear later in the list than its supergroup.
      ' 
      ' This ensures that users will always propagate all the way down the
      ' inheritance tree, even to subgroups of subgroups.
    '''
    log.debug('Sorting LDAP group inheritance tree...')
    knownDNs = []
    for group in unsortedGroups:
        knownDNs.append(group[0])
    
    log.debug(' > Retrieving any non-extendedGroup supergroups.')
    extraGroups = []
    for group in unsortedGroups:
        if 'supergroup' in group[1].keys():
            for sgDn_b in group[1]['supergroup']:
                sgDn: str = sgDn_b.decode('utf-8')
                if sgDn not in knownDNs:

                    log.debug(f'   > Retrieving {sgDn}')
                    newSg = ldapConnection.search_s(
                        sgDn,
                        ldap.SCOPE_BASE
                    )

                    if not newSg:
                        log.critical(
                            f'Group {group[0]} has supergroup ' \
                            + f'{group[1]["supergroup"]}, but ' \
                            + f'{group[1]["supergroup"]} does not exist! This' \
                            + f' could be a sign of a serious problem with ' \
                            + f'the DIT!'
                        )
                        continue

                    extraGroups.append(newSg[0])
                    knownDNs.append(newSg[0][0])
    
    if extraGroups:
        unsortedGroups += extraGroups
    
    log.debug(f' > Attempting group inheritance-order sort for ' \
        + f'{len(unsortedGroups)} ' \
        + f'{"group" if len(unsortedGroups) == 1 else "groups"}'
    )
    sortedGroups = []
    sortedDNs = []
    passNo: int = 1
    while len(unsortedGroups) > 0:
        initNumUnsorted: int = len(unsortedGroups)
        remainingGroups = []

        for group in unsortedGroups:
            if 'supergroup' not in group[1].keys():
                log.debug(f'      [Pass {passNo}]: Sorted {group[0]}')
                sortedGroups.append(group)
                sortedDNs.append(group[0])
            else:
                allSgsHaveBeenSorted: bool = True
                for elem_b in group[1]['supergroup']:
                    elem: str = elem_b.decode('utf-8')
                    if elem not in sortedDNs:
                        allSgsHaveBeenSorted = False
                        break
                
                if allSgsHaveBeenSorted:
                    log.debug(f'      [Pass {passNo}]: Sorted {group[0]}')
                    sortedGroups.append(group)
                    sortedDNs.append(group[0])
                else:
                    remainingGroups.append(group)

        finalNumUnsorted: int = len(remainingGroups)
        unsortedGroups = remainingGroups
        log.debug(f'  > {finalNumUnsorted} {"group remains" if finalNumUnsorted == 1 else "groups remain"} unsorted after pass {passNo}')

        if finalNumUnsorted == initNumUnsorted:
            log.error(
                f'Detected circular group dependency! The following groups ' \
                + f'could not be sorted:\n{remainingGroups}'
            )
            sys.exit(2)
        passNo += 1
    
    log.debug(f'Groups sorted after {passNo-1} {"pass" if passNo-1 == 1 else "passes"}.')
    return sortedGroups


def enforceLDAPInheritanceHierarchy(lConnection: ldap.ldapobject.LDAPObject, groups):
    ''' Determine which users need to be added to subgroups and then add them.
    '''
    log.info('Calculating necessary user insertion operations.')
    knownGroupUsers = {}
    userGroupAssociationsToAdd = {}
    for group in groups:
        knownGroupUsers[group[0]] = []
        if 'memberUid' in group[1].keys():
            for member_b in group[1]['memberUid']:
                member: str = member_b.decode('utf-8')
                knownGroupUsers[group[0]].append(member)
        
        if 'supergroup' in group[1].keys():
            for sg_b in group[1]['supergroup']:
                sg: str = sg_b.decode('utf-8')
                if sg not in knownGroupUsers.keys():
                    log.error(
                        f'Supergroup with DN {sg} has not been processed yet!' \
                        + f' This means that the LDAP tree was not sorted ' \
                        + f'properly! This is an internal issue with ' \
                        + f'{COMP_NAME}! This error occured when processing:\n'\
                        + f'{group}'
                    )
                    continue
                    
                shouldBePresent = knownGroupUsers[sg]
                ourUsers = knownGroupUsers[group[0]]
                for user in shouldBePresent:
                    if user not in ourUsers:
                        log.debug(f' > Need to insert {user} into {group[0]}')
                        if not group[0] in userGroupAssociationsToAdd.keys():
                            userGroupAssociationsToAdd[group[0]] = []
                        userGroupAssociationsToAdd[group[0]].append((
                            ldap.MOD_ADD,
                            'memberUid',
                            user.encode('utf-8')
                        ))
                        knownGroupUsers[group[0]].append(user)
    
    if not userGroupAssociationsToAdd:
        log.info('No user insertion operations necessary!')
        return
    
    numOps: int = len(userGroupAssociationsToAdd.keys())
    log.info(
        f'Performing {numOps} user insertion ' \
        + f'{"operation" if numOps == 1 else "operations"}'
    )

    for (group, operation) in userGroupAssociationsToAdd.items():
        lConnection.modify_s(group, operation)
    
    log.info('User insertions complete.')



if __name__ == '__main__':
    aP = argparse.ArgumentParser(
        description='The LDAP system does not provide an inherent way to ' \
            + 'enforce hieararchical group membership. This script uses a ' \
            + 'custom group attribute on the LDAP server to automatically ' \
            + 'update subgroups to contain all users of a supergroup. e.g., ' \
            + 'if group `databaseAdmins` is defined as a subgroup of ' \
            + '`administrators`, then this script will ensure that all ' \
            + 'members of `administrators` are also members of ' \
            + '`databaseAdmins, adding users to the latter group if necessary.'
    )

    aP.add_argument(
        'ldapServer',
        type=str,
        help='URI of the LDAP server to run enforcement actions over.'
    )

    aP.add_argument(
        'searchBase',
        type=str,
        help='Base DN to search for groups starting from.'
    )

    aP.add_argument(
        'bindUser',
        type=str,
        metavar='USER_DN',
        help='DN of the user to bind as. This user must have write access to ' \
            + 'whatever groups you want the script to run over.'
    )

    aP.add_argument(
        '--bindUserPassword', '-p',
        type=str,
        metavar='USER_PASSWORD',
        help='Password for `bindUser`. Specify either this option or `--pE`; ' \
            + 'otherwise, the password will be read from STDIN.'
    )

    aP.add_argument(
        '--userPwdEnv', '--pE',
        type=str,
        metavar='USER_PVAR',
        help='The name of an environment variable to read the password for ' \
            + '`bindUser` from. Specify either this option or `-p`; ' \
            + 'otherwise, the password will be read from STDIN.'
    )

    aP.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable more detailed debug logging.'
    )

    args = aP.parse_args()

    if args.verbose:
        coloredlogs.install(level=logging.DEBUG)
    else:
        coloredlogs.install(level=logging.INFO)

    log.info(f'MX-XDEN component {COMP_ID} ("{COMP_NAME}") mark {VERSION}')

    userPwd: str = ''
    if args.bindUserPassword:
        log.debug('User password was provided as a command-line argument.')
        userPwd = args.bindUserPassword
    elif args.userPwdEnv:
        log.debug('User password was provided from an environment variable.')
        if not args.userPwdEnv in os.environ.keys():
            log.error(
                  f'Password was requested to be read from environment ' \
                + f'variable {args.userPwdEnv}, but this environment ' \
                + f'variable does not exist!'
            )
            sys.exit(1)
        userPwd = os.environ[args.userPwdEnv]
    else:
        log.debug('No user password provided. Asking user manually.')
        userPwd = getpass.getpass('Please enter LDAP password: ')
    
    if not userPwd:
        log.error('Password is blank!')
    
    log.info(f'Connecting to {args.ldapServer}')

    log.debug('Opening connection to server.')
    ldapConnection: ldap.ldapobject.LDAPObject = ldap.initialize(
        args.ldapServer
    )

    log.debug('Enabling TLS.')
    ldapConnection.start_tls_s()

    log.debug('Binding user.')
    try:
        ldapConnection.simple_bind_s(args.bindUser, userPwd)
    except ldap.INVALID_CREDENTIALS:
        log.error(
            'Failed to bind user (invalid credentials)! Check the provided ' \
            + 'username and password.'
        )
        sys.exit(5)

    log.info(f'Searching for extended groups starting from {args.searchBase}.')
    searchResult = None
    try:
        searchResult = ldapConnection.search_s(
            args.searchBase,
            ldap.SCOPE_SUBTREE,
            '(ObjectClass=extendedGroup)'
        )
    except ldap.NO_SUCH_OBJECT:
        log.error(
            f'No such object {args.searchBase}! Check your searchBase.'
        )
        sys.exit(6)

    if not searchResult:
        log.warning(
            'Search returned no extendedGroups! Check your searchBase. ' \
            + 'This warning is expected if there aren\'t any extendedGroups ' \
            + 'in the LDAP server to begin with.'
        )
        sys.exit(0)

    log.info('Preprocessing groups.')
    sortedGroups = preprocessLDAPGroups(ldapConnection, searchResult)
    
    enforceLDAPInheritanceHierarchy(ldapConnection, sortedGroups)

    log.info('Done!')