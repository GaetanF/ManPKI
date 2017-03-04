#! /usr/bin/env python3

# This file is part of ManPKI.
# Copyright 2016 Gaetan FEREZ <gaetan@ferez.fr>
#
# ManPKI is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ManPKI is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ManPKI. If not, see <http://www.gnu.org/licenses/>.

"""ManPKI Manage User tools"""

import argparse

from tinydb_jsonorm import Database
from tinydb_jsonorm import TinyJsonModel
from tinydb_jsonorm import fields
from tinydb import where
from jsonmodels import models

from manpki.config import ManPKIObject

dbj = Database(ManPKIObject.dbdir + '/manpki.json')


class Roles(models.Base):
    role = fields.StringField(required=True)

    def __repr__(self):
        return self.role


class UserDB(TinyJsonModel):
    __tablename__ = "user"

    username = fields.StringField(required=True)
    roles = fields.ListField([Roles])

    def __init__(self, *args, **kwargs):
        super(UserDB, self).__init__(*args, **kwargs)

    def __repr__(self):
        return {'name': self.username, 'roles': self.roles}

    def contain_role(self, role):
        for urole in self.roles:
            if urole.role == role.role:
                return True
        return False

    class Meta:
        database = dbj


def main():
    parser = argparse.ArgumentParser(description='ManPKI Manage User.')
    parser.add_argument("-a", "--add", action="store_true",
                        help="add user")
    parser.add_argument("-d", "--delete", action="store_true",
                        help="delete user")
    parser.add_argument("-l", "--list", action="store_true", help="list users")
    parser.add_argument("-u", "--username", help="username")
    parser.add_argument("-g", "--grant-role", choices=["admin", "ca", "ra", "user"],
                        help="user role (admin,ca,ra,user)")
    parser.add_argument("-r", "--delete-role", choices=["admin", "ca", "ra", "user"],
                        help="user role (admin,ca,ra,user)")

    args = parser.parse_args()

    if args.username and args.add and not args.delete and not args.list:
        user = UserDB(username=args.username)
        try:
            user.validate()
            user.insert()
            print('User {} added.'.format(args.username))
        except BaseException:
            print('Unable to add user {}'.format(args.username))

    if args.username and args.delete and not args.add and not args.list:
        user = UserDB.get(where('username') == args.username)
        try:
            user.delete()
            print('User {} deleted.'.format(args.username))
        except BaseException:
            print('Unable to delete user {}'.format(args.username))

    if args.username and args.grant_role and not args.delete and not args.list:
        user = UserDB.get(where('username') == args.username)
        grant_role = Roles(role=args.grant_role)
        grant_role.validate()
        if user and not user.contain_role(grant_role):
            user.roles.append(grant_role)
        try:
            user.validate()
            user.save()
            print('Role {} added to user {}.'.format(args.grant_role, args.username))
        except BaseException:
            print('Unable to grant role {} to {}'.format(args.grant_role, args.username))

    if args.username and args.delete_role and not args.delete and not args.list:
        user = UserDB.get(where('username') == args.username)
        delete_role = Roles(role=args.delete_role)
        delete_role.validate()
        if user and user.contain_role(delete_role):
            tmp_list = []
            for role in user.roles:
                if role.role != delete_role.role:
                    tmp_list.append(role)
            user.roles = tmp_list
        try:
            user.validate()
            user.save()
            print('Role {} revoked from user {}.'.format(args.delete_role, args.username))
        except BaseException:
            print('Unable to delete role {} to {}'.format(args.delete_role, args.username))

    if args.list:
        print('Username\t\tRoles')
        for user in UserDB.all():

            print('{}\t\t{}'.format(user.username, user.roles))


if __name__ == "__main__":
    main()
