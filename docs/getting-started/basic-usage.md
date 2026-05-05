# Basic Usage

## Binaries

Running as a binary allows you to skip dealing with any container related networking issues and leverage the same network interface that the host machine is using.

```bash
methodtenable vm vulnerability export --severity critical --state OPEN
```

## Docker

Running methodtenable within a Docker container should typically work similarly to running directly on a host, however, occasionally there are a few things to keep in mind.

If you're running on a Docker container on a MacOS machine and you are trying to connect to a locally running service, you can leverage the `host.docker.internal` address as mentioned in the Docker documentation [here](https://docs.docker.com/desktop/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host).

```bash
docker run methodsecurity/methodtenable \
  vm \
  vulnerability \
  export \
  --severity critical \
  --state OPEN
```
