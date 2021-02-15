# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import copy

import pytest
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, authenticated_user, \
    superuser_access

from invenio_records_permissions.generators import Admin, \
    AllowedByAccessLevel, AnyUser, AnyUserIfPublic, AuthenticatedUser, \
    Disable, Generator, IfRestricted, RecordOwners, SuperUser


def test_generator():
    generator = Generator()

    assert generator.needs() == []
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_any_user():
    generator = AnyUser()

    assert generator.needs() == [any_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {'match_all': {}}


def test_superuser():
    generator = SuperUser()

    assert generator.needs() == [superuser_access]
    assert generator.excludes() == []
    # TODO: Test query_filter when new permissions metadata implemented


def test_disable():
    generator = Disable()

    assert generator.needs() == []
    assert generator.excludes() == [any_user]
    assert generator.query_filter().to_dict() in [
        # ES 6-
        {'bool': {'must_not': [{'match_all': {}}]}},
        # ES 7+
        {'match_none': {}}
    ]


def test_admin():
    generator = Admin()

    assert generator.needs() == [ActionNeed('admin-access')]
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_record_owner(create_record, mocker):
    generator = RecordOwners()
    record = create_record()

    assert generator.needs(record=record) == [
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    ]
    assert generator.excludes(record=record) == []

    # Anonymous identity.
    assert not generator.query_filter(identity=mocker.Mock(provides=[]))

    # Authenticated identity
    query_filter = generator.query_filter(
        identity=mocker.Mock(
            provides=[mocker.Mock(method='id', value=1)]
        )
    )

    assert query_filter.to_dict() == {'term': {'owners': 1}}


def test_any_user_if_public(create_record):
    generator = AnyUserIfPublic()
    record = create_record()
    private_record = create_record({
        "_access": {
            "metadata_restricted": True,
            "files_restricted": True
        },
        "access_right": "restricted"
    })

    assert generator.needs(record=record) == [any_user]
    assert generator.needs(record=private_record) == []

    assert generator.excludes(record=record) == []
    assert generator.excludes(record=private_record) == []

    assert generator.query_filter().to_dict() == {
        'term': {"_access.metadata_restricted": False}
    }


def test_authenticateduser():
    """Test Generator AuthenticatedUser."""
    generator = AuthenticatedUser()

    assert generator.needs() == [authenticated_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {'match_all': {}}


@pytest.mark.parametrize("action", ['read', 'update', 'delete'])
def test_allowedbyaccesslevels_metadata_curator(action, create_record):
    # Restricted record, only viewable by owner and a Metadata Curator
    record = create_record(
        {
            "owners": [4],
            "_access": {
                "metadata_restricted": True,
                "files_restricted": True
            },
            "internal": {
                "access_levels": {
                    "metadata_curator": [{"scheme": "person", "id": 1}]
                }
            }
        }
    )
    generator = AllowedByAccessLevel(action=action)

    if action in ['read', 'update']:
        assert generator.needs(record=record) == [UserNeed(1)]
    else:
        assert generator.needs(record=record) == []

    assert generator.excludes(record=record) == []


def test_allowedbyaccesslevels_query_filter(mocker):
    # TODO: Test query_filter on actual Elasticsearch instance per #23

    # User that has been allowed
    generator = AllowedByAccessLevel()
    query_filter = generator.query_filter(
        identity=mocker.Mock(
            provides=[mocker.Mock(method='id', value=1)]
        )
    )

    # TODO: Update to account for other 'read' access levels
    assert query_filter.to_dict() == {
        'term': {
            'internal.access_levels.metadata_curator': {
                'scheme': 'person', 'id': 1
            }
        }
    }

    # User that doesn't provide 'id'
    generator = AllowedByAccessLevel()
    query_filter = generator.query_filter(
        identity=mocker.Mock(
            provides=[mocker.Mock(method='foo', value=1)]
        )
    )

    assert query_filter == []


@pytest.mark.parametrize("field", ['files'])
def test_ifrestricted(field, create_record):
    # Restricted record, only viewable by owner and a grants level
    record = create_record(
        {
            "access": {
                "owned_by": [{"user": 4}],
                "record": False,  # currently a boolean public|restricted"
                "files": True,   # currently a boolean public|restricted"
                "grants": [
                    {"subject": "user", "id": 1, "level": "edit"},
                    # {"subject": "user", "id": 2, "level": "manage"},
                    # {"subject": "user", "id": 3, "level": "viewmeta"},
                    # {"subject": "user", "id": 3, "level": "viewfull"},
                    # {"subject": "role", "id": "curator", "level": "edit"},
                    # {"subject": "sysrole", "id": "authenticated_user",\
                    # "level": "view"}
                    ]
                }
        }
    )
    generator = IfRestricted('files', [AuthenticatedUser()], [AnyUser()])
    # if field in ['metadata']:
    #     print('filed in metadata')
    #     assert generator.needs(record=record) == [any_user]
    # if field in ['files']:
    #     print('filed in files', field)
    #     assert generator.needs(record=record) == [authenticated_user]

    assert generator.needs(record=record) == [authenticated_user]

    assert generator.excludes(record=record) == []
    assert generator.query_filter().to_dict() == {'match_all': {}}


# @pytest.mark.parametrize("level", ['edit', 'manage', 'viewmeta', 'viewfull'])
# def test_recordpermissionlevel(level, create_record):
#     # Restricted record, only viewable by owner and a grants level
#     record = create_record(
#         {
#             "access": {
#                 "owned_by": [{"user": 4}],
#                 "record": True,  # currently a boolean public|restricted"
#                 "files": True,   # currently a boolean public|restricted"
#                 "grants": [
#                     {"subject": "user", "id": 1, "level": "edit"},
#                     # {"subject": "user", "id": 2, "level": "manage"},
#                     # {"subject": "user", "id": 3, "level": "viewmeta"},
#                     # {"subject": "user", "id": 3, "level": "viewfull"},
#                     # {"subject": "role", "id": "curator", "level": "edit"},
#                     # {"subject": "sysrole", "id": "authenticated_user",\
#                     #  "level": "view"}
#                     ]
#                 }
#         }
#     )
#     generator = RecordPermissionLevel(level=level)
#     if level in ['edit']:
#         assert generator.needs(record=record) == [UserNeed(1)]
#     else:
#         assert generator.needs(record=record) == []

#     assert generator.excludes(record=record) == []
#     assert generator.query_filter().to_dict() == {'match_all': {}}
