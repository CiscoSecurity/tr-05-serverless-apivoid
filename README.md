[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# APIVoid Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using [APIVoid](https://www.apivoid.com/about/) as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

Open the code folder in your terminal.
```
cd code
```

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](requirements.txt) file:
```
pip install --upgrade --requirement requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

If you want to test the live Lambda you may use any HTTP client (e.g. Postman),
just make sure to send requests to your Lambda's `URL` with the `Authorization`
header set to `Bearer <JWT>`.

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-apivoid .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-apivoid tr-05-apivoid
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-apivoid
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

    curl http://localhost:9090

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Indicator`,
    - `Sighting`,
    - `Relationship`.
    
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `ip`
- `domain`

### CTIM Mapping Specifics

Each response from the APIVoid API for the supported observables generates the following CTIM entities:
- `Sighting` from each entry in `.data.report.blacklists.engines` where `.data.report.blacklists.engines[].detected` is `true`:
  - Value from `.data.report.blacklists.engines[].engine` will map to `source`
  - Value from `.data.report.blacklists.engines[].reference` will map to `source_uri`
  - The query time will map to `.observed_time.start_time`

- `Indicator` from each entry in `.data.report.blacklists.engines` where `.data.report.blacklists.engines[].detected` is `true`:
  - `Indicator` TLP will be `white`
  - Value from `.data.report.blacklists.engines[].engine` will map to `short_description`
  
- `Relationship` type between `Sighting` and `Indicator` is `member-of` because `Sightings` and `Indicators` are based on feeds.
