# Process Management

## Description

This example shows how to manage processes over the web API, such as checking the status and retrieving outputs.
First, the example submits an `ArithmeticAddCalculation` (a calculation plugin that ships with `aiida-core`) to the daemon.
Then, the status of the calculation is queried for and when it is done, the final results are retrieved.

## Instructions

### Server

1. Install `aiida-restapi`:

    ```bash
    pip install aiida-restapi[auth]
    ```

1. Start the web API server:

    ```bash
    uvicorn --port 8000 aiida_restapi:app
    ```

TODO import mc3d aiida database 
TODO you can send GraphQL queries directly without the python request handling using the web interface `http://localhost:8000/graphql` `<PORT>`


### Client

1. Install Python prerequisites:

    ```bash
    pip install click requests
    ```

1. Execute the example script:

    ```bash
    python script.py
    ```
