# Copyright (C) DATADVANCE, 2010-2023
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Test the extensions specific to the `baseapp-django-channels-graphql-ws` fork."""

import graphene
import pytest


@pytest.mark.asyncio
async def test_connection_init_payload(gql):
    """Check `connect_and_init` delivers the payload to `on_connect`."""

    received_payloads = []

    async def on_connect(self, payload):
        del self
        received_payloads.append(payload)

    client = gql(query=Query, consumer_attrs={"on_connect": on_connect})
    await client.connect_and_init(payload={"Authorization": "token"})
    assert received_payloads == [{"Authorization": "token"}]
    await client.finalize()


@pytest.mark.asyncio
async def test_send(gql):
    """Check the backward compatible `GraphqlWsClient.send`."""

    client = gql(query=Query)
    await client.connect_and_init()
    msg_id = await client.send(
        msg_type="subscribe",
        payload={"query": "query op_name { value }", "operationName": "op_name"},
    )
    resp = await client.receive(assert_id=msg_id, assert_type="next")
    assert resp["data"]["value"] == Query.VALUE
    await client.receive_complete(msg_id)
    await client.finalize()


@pytest.mark.asyncio
async def test_context_build_absolute_uri(gql):
    """Check `info.context` exposes the scope keys and `build_absolute_uri`."""

    client = gql(
        query=Query,
        communicator_kwds={"headers": [(b"host", b"example.com")]},
    )
    await client.connect_and_init()
    msg_id = await client.start(query="query op_name { absolute_uri path }")
    resp = await client.receive_next(msg_id)
    # Pytest-django forces `DEBUG = False`, so the scheme is "https".
    assert resp["data"] == {
        "absolute_uri": "https://example.com/media/file.png",
        "path": "graphql/",
    }
    await client.receive_complete(msg_id)
    await client.finalize()


class Query(graphene.ObjectType):
    """Root GraphQL query."""

    VALUE = "Hello, world!"
    value = graphene.String()
    absolute_uri = graphene.String()
    path = graphene.String()

    def resolve_value(self, info):
        """Resolver to return predefined value."""
        del info
        return Query.VALUE

    def resolve_absolute_uri(self, info):
        """Build an absolute URI from the Channels scope."""
        return info.context.build_absolute_uri("/media/file.png")

    def resolve_path(self, info):
        """Read the path from the Channels scope through the context."""
        return info.context.path
