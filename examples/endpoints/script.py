#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example script to demonstrate the endpoints over web API."""
from __future__ import annotations

import os
import time
import typing as t

import click
import requests

from pprint import pprint

BASE_URL = "http://127.0.0.1:8000"

def echo_error(message: str) -> None:
    """Echo the message prefixed with ``Error`` in bold red.

    :param message: The error message to echo.
    """
    click.echo(click.style("Error: ", fg="red", bold=True), nl=False)
    click.echo(message)

def request(
    url,
    json: dict[str, t.Any] | None = None,
    data: dict[str, t.Any] | None = None,
    method="POST",
) -> dict[str, t.Any] | None:
    """Perform a request to the web API of ``aiida-restapi``.

    If the ``ACCESS_TOKEN`` environment variable is defined, it is passed in the ``Authorization`` header.

    :param url: The relative URL path without leading slash, e.g., `nodes`.
    :param json: A JSON serializable dictionary to send in the body of the request.
    :param data: Dictionary, list of tuples, bytes, or file-like object to send in the body of the request.
    :param method: The request method, POST by default.
    :returns: The response in JSON or ``None``.
    """
    access_token = os.getenv("ACCESS_TOKEN", None)

    if access_token:
        headers = {"Authorization": f"Bearer {access_token}"}
    else:
        headers = {}

    url = f"{BASE_URL}/{url}"
    #click.echo(f"Sending request:\n method:\n  {method}\n url:\n {url}\n"
    #        f"json:\n  {json}\n data:\n  {data}\n headers:\n  {headers}\n")
    response = requests.request(  # pylint: disable=missing-timeout
        method, url, json=json, data=data, headers=headers
    )

    try:
        response.raise_for_status()
    except requests.HTTPError:
        results = response.json()

        echo_error(f"{response.status_code} {response.reason}")

        if "detail" in results:
            echo_error(results["detail"])

        for error in results.get("errors", []):
            click.echo(error["message"])

        return None
    return response.json()

def authenticate(
    username: str = "johndoe@example.com", password: str = "secret"
) -> str | None:
    """Authenticate with the web API to obtain an access token.

    Note that if authentication is successful, the access token is stored in the ``ACCESS_TOKEN`` environment variable.

    :param username: The username.
    :param password: The password.
    :returns: The access token or ``None`` if authentication was unsuccessful.
    """
    results = request("token", data={"username": username, "password": password})

    if results:
        access_token = results["access_token"]
        os.environ["ACCESS_TOKEN"] = access_token
        return access_token

    return None

def query_node_selection_grid_full_type() -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/full_types
    """
    raise NotImplemented("full_types not supported yet")

def query_node_selection_grid() -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/page/1?perpage=25&full_type="data.%|"&orderby=-ctime
    """
    query = """
    {
      nodes(filters: "node_type LIKE 'data.%'") {
        rows(limit: 25, orderBy: "ctime", orderAsc: false) {
          ctime
          #full_type # TODO does not work yet
          id
          label
          mtime
          node_type
          process_type
          user_id
          uuid
        }
      }
    }
    """
    return request("graphql", {"query": query})

def query_node_details_attributes(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/1ca1fdc5-2bd5-44d6-ac93-66d61d593535?attributes=true
    """
    variables = {"node_uuid": node_uuid}
    query = """
        query function($node_uuid: String) {
            node(uuid: $node_uuid) {
                attributes
                ctime
                #full_type # TODO
                id
                label
                mtime
                node_type
                process_type
                user_id
                uuid
            }
        }
    """
    return request("graphql", {"query": query, "variables": variables})
    # NOTE
    # We could also implement this as a single query and not a reusable function
    #query = """
    #    {
    #        node(uuid: \""""+ f"{node_uuid}" +"""\") {
    #            attributes
    #            ctime
    #            #full_type # TODO
    #            id
    #            label
    #            mtime
    #            node_type
    #            process_type
    #            user_id
    #            uuid
    #        }
    #    }
    #"""
    #return request("graphql", {"query": query})

def query_node_details_incoming(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/1ca1fdc5-2bd5-44d6-ac93-66d61d593535/links/incoming

    """
    variables = {"node_uuid": node_uuid}
    query = """
        query function($node_uuid: String) {
            node(uuid: $node_uuid) {
                incoming {
                   rows {
                      link {
                        id
                        label
                        type
                      }
                      node {
                        ctime
                        #full_type # TODO
                        id
                        label
                        mtime
                        node_type
                        process_type
                        user_id
                        uuid
                      }
                   }
                }
            }
        }
    """
    return request("graphql", {"query": query, "variables": variables})

def query_node_details_outgoing(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/1ca1fdc5-2bd5-44d6-ac93-66d61d593535/links/tree?in_limit=10&out_limit=10
    """
    variables = {"node_uuid": node_uuid}
    query = """
        query function($node_uuid: String) {
            node(uuid: $node_uuid) {
                outgoing {
                   rows (limit: 10){
                      link {
                        id
                        label
                        type
                      }
                      node {
                        ctime
                        #full_type # TODO
                        id
                        label
                        mtime
                        node_type
                        process_type
                        user_id
                        uuid
                      }
                   }
                }
            }
        }
    """
    return request("graphql", {"query": query, "variables": variables})

def query_node_details_links(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/1ca1fdc5-2bd5-44d6-ac93-66d61d593535/links/tree?in_limit=10&out_limit=10
    """
    variables = {"node_uuid": node_uuid}
    query = """
        query function($node_uuid: String) {
            node(uuid: $node_uuid) {
                incoming {
                   rows(limit: 10) {
                      link {
                        id
                        label
                        type
                      }
                      node {
                        ctime
                        #full_type # TODO
                        id
                        label
                        mtime
                        node_type
                        process_type
                        user_id
                        uuid
                      }
                   }
                }
                outgoing {
                   rows(limit: 10) {
                      link {
                        id
                        label
                        type
                      }
                      node {
                        ctime
                        #full_type # TODO
                        id
                        label
                        mtime
                        node_type
                        process_type
                        user_id
                        uuid
                      }
                   }
                }
            }
        }
    """
    return request("graphql", {"query": query, "variables": variables})

def query_node_details_download_formats(node_uuid) -> dict[str, t.Any]:
    raise NotImplemented("download_format not supported yet.")

def query_node_details_download_upf(node_uuid) -> dict[str, t.Any]:
    raise NotImplemented("download_format upf not supported yet.")

def query_node_details_download_cif(node_uuid) -> dict[str, t.Any]:
    raise NotImplemented("download_format cif not supported yet.")

def query_node_details_download_file(node_uuid) -> dict[str, t.Any]:
    raise NotImplemented("download file not supported yet.")

def query_node_details_calcjob_input_files(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/calcjobs/1ca1fdc5-2bd5-44d6-ac93-66d61d593535/input_files
    """
    raise NotImplemented("Not supported yet.")

def query_node_details_calcjob_output_files(node_uuid) -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/calcjobs/1ca1fdc5-2bd5-44d6-ac93-66d61d593535/output_files
    """
    raise NotImplemented("Not supported yet.")

def query_statistics_users() -> dict[str, t.Any]:
    query = """
      {
        users {
          rows {
            first_name
            id
            institution
            last_name
          }
        }
      }
    """
    return request("graphql", {"query": query})

def query_statistics_server() -> dict[str, t.Any]:
    """
    Imitates the behavior of this query from old restapi
    https://aiida.materialscloud.org/mc3d/api/v4/users
    """
    raise NotImplemented("Not supported yet")
    query = """
      {
        server {
          rows {
            id
          }
        }
      }
    """
    return request("graphql", {"query": query})

def query_statistics_nodes_full_types_count(node_uuid) -> dict[str, t.Any]:
    """
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/full_types_count
    """
    raise NotImplemented("Not supported yet")

def query_statistics_nodes_statistics(node_uuid) -> dict[str, t.Any]:
    """
    https://aiida.materialscloud.org/mc3d/api/v4/nodes/statistics
    """

    raise NotImplemented("Not supported yet")

if __name__ == "__main__":
    token = authenticate()

    if token is None:
        echo_error("Could not authenticate with the API, aborting")

    # TODO does not work yet
    #results = query_node_selection_grid_full_type()
    #pprint(results)

    #results = query_node_selection_grid()
    #pprint(results)
        
    # This has to be adapted to an uuid that exists in the database
    uuid = "00800d1f-1d8c-433e-bc78-b0268eb8e79f"

    ## For these commands unlike the old restapi the properties of nodes and
    ## links are separated in the output results

    #results = query_node_details_attributes(uuid)
    #pprint(results)

    #results = query_node_details_incoming(uuid)
    #pprint(results)

    #results = query_node_details_outgoing(uuid)
    #pprint(results)

    #results = query_node_details_links(uuid)
    #pprint(results)

    # TODO missing download queries

    #results = query_statistics_users()
    #pprint(results)

    results = query_statistics_server()
    pprint(results)

