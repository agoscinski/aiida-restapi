#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example script to demonstrate process management over the web API."""
from __future__ import annotations

import os
import time
import typing as t

import click
import requests

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
    click.echo(f"Sending request:\n method:\n  {method}\n url:\n {url}\n"
            f"json:\n  {json}\n data:\n  {data}\n headers:\n  {headers}\n")
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

def get_code(uuid: str) -> dict[str, t.Any] | None:
    """Return a code that has the given default calculation job plugin.

    Returns the first code that is matched.

    :param default_calc_job_plugin: The default calculation job plugin the code should have.
    :raises ValueError: If no code could be found.
    """
    # PR COMMENT: IS seems to be not working so I used LIKE
    # replace at the end is bad coding style but is more convenient
    variables = {"uuid": uuid}
    query = """
        {
            nodes(filters: "uuid LIKE 'UUID_VARIABLE'") {
                rows {
                    uuid
                    label
                    attributes
                }
            }
        }
    """.replace("UUID_VARIABLE", uuid)
    results = request("graphql", {"query": query, "variables": variables})
    return results

@click.command()
def main():
    """Authenticate with the web API and submit an ``ArithmeticAddCalculation``."""
    token = authenticate()

    if token is None:
        echo_error("Could not authenticate with the API, aborting")
        return

    # PR COMMENT Please use uuid from a node that exist
    #uuid = "a2bb48e1-ece8-4658-a643-2381851f8be8"
    uuid = "cc72e31f-f7be-45e1-92df-b8af7af9b5a2"
    output = get_code(uuid)
    # PR COMMENT for debugging
    #click.echo(f"Output whole:\n{output}")
    if output is not None:
        click.echo(f"Found {len(output['data']['nodes']['rows'])} result(s)")
        if len(output['data']['nodes']['rows']) == 1:
            click.echo(f"Successfully found node with uuid {uuid!r}:")
            click.echo(f"{output['data']['nodes']['rows'][0]}")



if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
